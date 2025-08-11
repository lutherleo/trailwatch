"""IP address -> network (ASN, organisation, kind, location) lookup.

The bundled map (``trailwatch/data/netmap.csv``) is synthetic: reserved address space, private
ASNs, invented organisations. A real deployment would load a CSV in the same schema exported from
a commercial or open IP-intelligence database. Lookups are a binary search over sorted,
non-overlapping integer ranges (O(log n)) fronted by a bounded LRU cache.
"""

from __future__ import annotations

import bisect
import csv
import ipaddress
import itertools
import math
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from trailwatch.window import BoundedLRU

EARTH_RADIUS_KM = 6371.0088


@dataclass(frozen=True, slots=True)
class NetInfo:
    """What the map knows about one network."""

    cidr: str
    asn: int
    org: str
    kind: str  # corporate | vpn | isp | mobile | hosting
    country: str
    city: str
    lat: float
    lon: float

    @property
    def asn_label(self) -> str:
        return f"AS{self.asn}"


class NetMapError(ValueError):
    """The network map file is malformed."""


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points in kilometres."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


class NetMap:
    """Sorted range table supporting IPv4 and IPv6 lookups."""

    def __init__(self, networks: list[NetInfo], cache_size: int = 65536) -> None:
        self._tables: dict[int, tuple[list[int], list[int], list[NetInfo]]] = {}
        by_version: dict[int, list[tuple[int, int, NetInfo]]] = {4: [], 6: []}
        for info in networks:
            try:
                net = ipaddress.ip_network(info.cidr, strict=True)
            except ValueError as exc:
                raise NetMapError(f"invalid CIDR {info.cidr!r}: {exc}") from exc
            by_version[net.version].append(
                (int(net.network_address), int(net.broadcast_address), info)
            )
        for version, rows in by_version.items():
            rows.sort(key=lambda r: r[0])
            for prev, cur in itertools.pairwise(rows):
                if cur[0] <= prev[1]:
                    raise NetMapError(f"overlapping networks {prev[2].cidr} and {cur[2].cidr}")
            self._tables[version] = (
                [r[0] for r in rows],
                [r[1] for r in rows],
                [r[2] for r in rows],
            )
        self._cache: BoundedLRU[str, tuple[NetInfo | None]] = BoundedLRU(cache_size)
        self.networks = tuple(networks)

    def __len__(self) -> int:
        return len(self.networks)

    def lookup(self, ip: str) -> NetInfo | None:
        """Return the network containing ``ip`` or ``None`` (unknown, unparsable, or a service
        hostname such as ``ec2.amazonaws.com``, which CloudTrail uses for service-made calls)."""
        cached = self._cache.get(ip)
        if cached is not None:
            return cached[0]
        result = self._lookup_uncached(ip)
        self._cache.put(ip, (result,))
        return result

    def _lookup_uncached(self, ip: str) -> NetInfo | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        starts, ends, infos = self._tables[addr.version]
        value = int(addr)
        idx = bisect.bisect_right(starts, value) - 1
        if idx >= 0 and value <= ends[idx]:
            return infos[idx]
        return None

    def by_asn(self, asn: int) -> list[NetInfo]:
        return [n for n in self.networks if n.asn == asn]

    @classmethod
    def from_csv(cls, path: str | Path) -> NetMap:
        with Path(path).open(encoding="utf-8") as handle:
            return cls(_read_rows(handle.read().splitlines(), str(path)))

    @classmethod
    def bundled(cls) -> NetMap:
        text = resources.files("trailwatch").joinpath("data/netmap.csv").read_text("utf-8")
        return cls(_read_rows(text.splitlines(), "bundled netmap.csv"))


def _read_rows(lines: list[str], origin: str) -> list[NetInfo]:
    body = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
    reader = csv.DictReader(body)
    required = {"cidr", "asn", "org", "kind", "country", "city", "lat", "lon"}
    if reader.fieldnames is None or not required.issubset(reader.fieldnames):
        raise NetMapError(f"{origin}: header must contain {sorted(required)}")
    networks = []
    for lineno, row in enumerate(reader, start=2):
        try:
            networks.append(
                NetInfo(
                    cidr=row["cidr"].strip(),
                    asn=int(row["asn"]),
                    org=row["org"].strip(),
                    kind=row["kind"].strip(),
                    country=row["country"].strip(),
                    city=row["city"].strip(),
                    lat=float(row["lat"]),
                    lon=float(row["lon"]),
                )
            )
        except (TypeError, ValueError) as exc:
            raise NetMapError(f"{origin}: bad row {lineno}: {exc}") from exc
    return networks
