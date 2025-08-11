"""Streaming ingest: read CloudTrail records from files, directories or a stream, parse them,
drop duplicates, and restore approximate time order with a bounded reorder buffer.

CloudTrail delivers events in ~5-minute files per region, so a consumer sees them out of order
by up to several minutes. Stateful rules (impossible travel, login-then-change windows) need
time order, so events pass through :class:`ReorderBuffer`, which holds each event until the
watermark ``max_event_time - max_lateness`` passes it. Memory is bounded by ``max_items``: when
full the oldest event is released early (counted as ``forced``).
"""

from __future__ import annotations

import gzip
import heapq
import io
import json
import logging
import re
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from trailwatch.model import Event
from trailwatch.parse import ParseError, parse_record
from trailwatch.window import BoundedLRU

log = logging.getLogger(__name__)

JSON_SUFFIXES = (".json", ".jsonl", ".ndjson")
_STAMP = re.compile(r"_CloudTrail_[a-z0-9-]+_(\d{8}T\d{4}Z)_")


@dataclass(slots=True)
class IngestStats:
    records: int = 0
    events: int = 0
    malformed: int = 0
    duplicates: int = 0
    late: int = 0
    forced: int = 0
    files: int = 0
    bad_files: int = 0


def _records_from_value(value: Any) -> Iterator[Any]:
    if isinstance(value, dict) and isinstance(value.get("Records"), list):
        yield from value["Records"]
    elif isinstance(value, list):
        yield from value
    else:
        yield value


def iter_stream(handle: IO[str], stats: IngestStats, origin: str = "<stream>") -> Iterator[Any]:
    """Yield raw records from a line-oriented stream.

    Each non-blank line may be one CloudTrail record or a whole CloudTrail log file object
    (``{"Records": [...]}``). Undecodable lines are counted and skipped, never fatal.
    """
    for lineno, line in enumerate(handle, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            stats.malformed += 1
            log.warning("%s:%d: skipping undecodable line: %s", origin, lineno, exc.msg)
            continue
        yield from _records_from_value(value)


def _open_text(path: Path) -> IO[str]:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8")
    return path.open(encoding="utf-8")


def _logical_suffix(path: Path) -> str:
    return Path(path.stem).suffix if path.suffix == ".gz" else path.suffix


#: File-level failures that make the rest of one input unreadable: missing/unreadable files and
#: corrupt gzip (``OSError``, which includes ``gzip.BadGzipFile``), truncated gzip (``EOFError``),
#: corrupt deflate data (``zlib.error``) and non-UTF-8 bytes (``UnicodeDecodeError``).
UNREADABLE_INPUT_ERRORS: tuple[type[Exception], ...] = (
    OSError,
    EOFError,
    zlib.error,
    UnicodeDecodeError,
)


def _iter_file_unguarded(path: Path, stats: IngestStats) -> Iterator[Any]:
    with _open_text(path) as handle:
        if _logical_suffix(path) == ".json":
            try:
                value = json.load(handle)
            except json.JSONDecodeError as exc:
                # Not a single JSON document; fall back to treating it as JSON lines.
                log.debug("%s is not one JSON document (%s); reading as JSON lines", path, exc)
                handle.seek(0)
                yield from iter_stream(handle, stats, str(path))
                return
            yield from _records_from_value(value)
        else:
            yield from iter_stream(handle, stats, str(path))


def iter_file(path: Path, stats: IngestStats) -> Iterator[Any]:
    """Yield raw records from one file: CloudTrail ``.json`` (optionally gzipped) or JSONL.

    A file that cannot be read to the end (corrupt or truncated gzip, non-UTF-8 bytes, I/O
    error) is counted in ``stats.bad_files``, logged and abandoned, so one bad file in a synced
    CloudTrail tree never stops the run. Records already yielded from it before the failure are
    kept; the unread remainder of that file is lost.
    """
    stats.files += 1
    try:
        yield from _iter_file_unguarded(path, stats)
    except UNREADABLE_INPUT_ERRORS as exc:
        stats.bad_files += 1
        log.error("%s: skipping unreadable file: %s: %s", path, type(exc).__name__, exc)


def delivery_sort_key(path: Path) -> tuple[str, str]:
    """Sort key putting CloudTrail log files in delivery-time order across regions.

    CloudTrail names files ``<acct>_CloudTrail_<region>_<YYYYMMDDTHHMMZ>_<id>.json.gz`` under
    per-region prefixes, so a plain path sort would replay one region's whole history before
    the next region's; ordering by the embedded timestamp interleaves regions correctly.
    Other files sort by name.
    """
    match = _STAMP.search(path.name)
    return (match.group(1) if match else "", str(path))


def discover(paths: Iterable[Path]) -> list[Path]:
    """Expand directories (recursively) into JSON/JSONL(.gz) files in delivery order."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            found.extend(
                sorted(
                    (
                        p
                        for p in path.rglob("*")
                        if p.is_file() and _logical_suffix(p) in JSON_SUFFIXES
                    ),
                    key=delivery_sort_key,
                )
            )
        elif path.exists():
            found.append(path)
        else:
            raise FileNotFoundError(f"input not found: {path}")
    return found


def parse_records(
    records: Iterable[Any], stats: IngestStats, dedup_capacity: int = 200_000
) -> Iterator[Event]:
    """Parse raw records into events, skipping malformed ones and duplicate ``eventID`` s."""
    seen: BoundedLRU[str, bool] = BoundedLRU(dedup_capacity)
    for raw in records:
        stats.records += 1
        try:
            event = parse_record(raw)
        except ParseError as exc:
            stats.malformed += 1
            log.warning("skipping malformed record #%d: %s", stats.records, exc)
            continue
        if event.event_id in seen:
            stats.duplicates += 1
            continue
        seen.put(event.event_id, True)
        stats.events += 1
        yield event


class ReorderBuffer:
    """Bounded min-heap that releases events once the watermark has passed them."""

    def __init__(self, max_lateness: float, max_items: int, stats: IngestStats | None = None):
        if max_lateness < 0 or max_items < 1:
            raise ValueError("max_lateness must be >= 0 and max_items >= 1")
        self.max_lateness = max_lateness
        self.max_items = max_items
        self.stats = stats if stats is not None else IngestStats()
        self._heap: list[tuple[float, int, Event]] = []
        self._seq = 0
        self._max_time = float("-inf")
        self._released_time = float("-inf")

    def __len__(self) -> int:
        return len(self._heap)

    def _release(self) -> Event:
        _, _, event = heapq.heappop(self._heap)
        self._released_time = max(self._released_time, event.time)
        return event

    def push(self, event: Event) -> list[Event]:
        """Add one event; return the events (in time order) that are now safe to process."""
        if event.time < self._released_time:
            self.stats.late += 1
        heapq.heappush(self._heap, (event.time, self._seq, event))
        self._seq += 1
        self._max_time = max(self._max_time, event.time)
        watermark = self._max_time - self.max_lateness
        out: list[Event] = []
        while self._heap and self._heap[0][0] <= watermark:
            out.append(self._release())
        while len(self._heap) > self.max_items:
            self.stats.forced += 1
            out.append(self._release())
        return out

    def flush(self) -> list[Event]:
        out = []
        while self._heap:
            out.append(self._release())
        return out


def ordered(events: Iterable[Event], buffer: ReorderBuffer) -> Iterator[Event]:
    """Pass ``events`` through ``buffer``, yielding them in (approximate) time order."""
    for event in events:
        yield from buffer.push(event)
    yield from buffer.flush()
