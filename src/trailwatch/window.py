"""Bounded state primitives.

Every piece of per-principal state in trailwatch lives in one of these containers, and every one
of them has a hard size cap, so memory is bounded by configuration rather than by the length or
cardinality of the input stream:

* :class:`BoundedLRU` -- key/value map evicting the least-recently-used key.
* :class:`TimeWindow` -- sliding time window with an item cap and incremental distinct counts.
* :class:`DecayedCounter` -- exponentially decayed counts with top-K-by-weight retention.
"""

from __future__ import annotations

import math
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Hashable, Iterator
from typing import Any


def decay_factor(elapsed: float, half_life: float) -> float:
    """Multiplicative decay after ``elapsed`` seconds for a given half-life (seconds)."""
    if elapsed <= 0:
        return 1.0
    return math.pow(0.5, elapsed / half_life)


class BoundedLRU[K: Hashable, V]:
    """An insertion-ordered map that evicts the least-recently-used entry beyond ``capacity``."""

    __slots__ = ("_data", "capacity", "evictions")

    def __init__(self, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._data: OrderedDict[K, V] = OrderedDict()
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def get(self, key: K) -> V | None:
        value = self._data.get(key)
        if value is not None:
            self._data.move_to_end(key)
        return value

    def peek(self, key: K) -> V | None:
        """Look up without refreshing recency."""
        return self._data.get(key)

    def put(self, key: K, value: V) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self.capacity:
            self._data.popitem(last=False)
            self.evictions += 1

    def get_or_create(self, key: K, factory: Callable[[], V]) -> V:
        value = self.get(key)
        if value is None:
            value = factory()
            self.put(key, value)
        return value

    def pop(self, key: K) -> V | None:
        return self._data.pop(key, None)

    def items(self) -> Iterator[tuple[K, V]]:
        return iter(list(self._data.items()))

    def keys(self) -> list[K]:
        return list(self._data.keys())


class TimeWindow[T: Hashable]:
    """Events within the last ``span`` seconds, capped at ``max_items``.

    Maintains a multiset of item keys so ``distinct()`` is O(1). ``add`` and ``expire`` are
    amortised O(1). When the cap is hit the oldest entries are dropped first, so a flood can
    never grow the window without bound (the window then under-counts, which is acceptable:
    the flood itself is already over any burst threshold).
    """

    __slots__ = ("_counts", "_entries", "dropped", "max_items", "span")

    def __init__(self, span: float, max_items: int) -> None:
        if span <= 0:
            raise ValueError("span must be > 0")
        if max_items < 1:
            raise ValueError("max_items must be >= 1")
        self.span = span
        self.max_items = max_items
        self._entries: deque[tuple[float, T]] = deque()
        self._counts: Counter[T] = Counter()
        self.dropped = 0

    def __len__(self) -> int:
        return len(self._entries)

    def _pop_left(self) -> None:
        _, item = self._entries.popleft()
        self._counts[item] -= 1
        if self._counts[item] <= 0:
            del self._counts[item]

    def expire(self, now: float) -> None:
        cutoff = now - self.span
        while self._entries and self._entries[0][0] < cutoff:
            self._pop_left()

    def add(self, when: float, item: T) -> None:
        self.expire(when)
        self._entries.append((when, item))
        self._counts[item] += 1
        while len(self._entries) > self.max_items:
            self._pop_left()
            self.dropped += 1

    def distinct(self) -> int:
        return len(self._counts)

    def count(self, item: T) -> int:
        return self._counts.get(item, 0)

    def keys(self) -> set[T]:
        return set(self._counts)

    def oldest(self) -> float | None:
        return self._entries[0][0] if self._entries else None

    def clear(self) -> None:
        self._entries.clear()
        self._counts.clear()


class DecayedCounter:
    """Exponentially decayed per-key counts, keeping at most ``capacity`` keys.

    Each key stores ``(weight, last_update)``; decay is applied lazily on access so updates are
    O(1). On overflow the lowest-weight keys are pruned down to 90% of capacity, which amortises
    the O(k log k) sort over at least ``capacity/10`` inserts.
    """

    __slots__ = ("_items", "_total", "_total_t", "capacity", "half_life", "pruned")

    def __init__(self, half_life: float, capacity: int) -> None:
        if half_life <= 0:
            raise ValueError("half_life must be > 0")
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.half_life = half_life
        self.capacity = capacity
        self._items: dict[str, list[float]] = {}
        self._total = 0.0
        self._total_t = 0.0
        self.pruned = 0

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key: object) -> bool:
        return key in self._items

    def weight(self, key: str, now: float) -> float:
        entry = self._items.get(key)
        if entry is None:
            return 0.0
        return entry[0] * decay_factor(now - entry[1], self.half_life)

    def total(self, now: float) -> float:
        return self._total * decay_factor(now - self._total_t, self.half_life)

    def add(self, key: str, now: float, amount: float = 1.0) -> float:
        """Add ``amount`` to ``key`` at time ``now``; returns the new decayed weight."""
        entry = self._items.get(key)
        if entry is None:
            entry = [0.0, now]
            self._items[key] = entry
        new_weight = entry[0] * decay_factor(now - entry[1], self.half_life) + amount
        entry[0] = new_weight
        entry[1] = max(entry[1], now)
        self._total = self.total(now) + amount
        self._total_t = max(self._total_t, now)
        if len(self._items) > self.capacity:
            self._prune(now)
        return new_weight

    def _prune(self, now: float) -> None:
        keep = max(1, int(self.capacity * 0.9))
        ranked = sorted(self._items, key=lambda k: self.weight(k, now), reverse=True)
        for key in ranked[keep:]:
            del self._items[key]
            self.pruned += 1

    def keys(self) -> list[str]:
        return list(self._items)

    def to_dict(self) -> dict[str, Any]:
        return {
            "half_life": self.half_life,
            "capacity": self.capacity,
            "total": [self._total, self._total_t],
            "items": {k: list(v) for k, v in self._items.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecayedCounter:
        counter = cls(float(data["half_life"]), int(data["capacity"]))
        total, total_t = data.get("total", [0.0, 0.0])
        counter._total, counter._total_t = float(total), float(total_t)
        for key, (weight, ts) in data.get("items", {}).items():
            counter._items[str(key)] = [float(weight), float(ts)]
        return counter
