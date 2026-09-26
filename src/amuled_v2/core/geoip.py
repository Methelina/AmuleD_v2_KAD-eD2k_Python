"""IP geolocation (stage X).

Primary format: **MaxMind MMDB** (`.mmdb`, the same libmaxminddb
database eMuleAI 1.6.0 loads — `dbip-city-lite.mmdb`), read through the
official `maxminddb` package.

Backward compatibility: the legacy MaxMind `GeoIP.dat` country tree is
still supported best-effort (see GeoIpDat) for installs that only carry
the old file.

src/amuled_v2/core/geoip.py
Version:     0.2.0
Author:      Soror L.'.L.'.
Updated:     2026-09-26

Patch Notes v0.2.0 (Soror L.'.L'.):
  [+] MMDB support via the official `maxminddb` package — the format
      eMuleAI itself uses (parity).
  [+] Legacy GeoIP.dat tree reader kept as a fallback.
  [+] load_geoip(path) accepts either format; lookup() -> ISO alpha-2.
"""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

from amuled_v2.logging_setup import LogTags, get_tagged_logger

log = get_tagged_logger(LogTags.IPFILTER, "core.geoip")

__all__ = ["GeoIpDatabase", "GeoIpMmdb", "GeoIpDat", "load_geoip"]

COUNTRY_BEGIN = 16776960

# Standard MaxMind legacy country-index table (index -> ISO alpha-2),
# identical to geo_ip.cpp / pygeoip COUNTRY_CODES.  US sits at 225.
COUNTRY_CODES = (
    "--", "AP", "EU", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AN", "AO",
    "AR", "AS", "AT", "AU", "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG",
    "BH", "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BW", "BY", "BZ",
    "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO",
    "CR", "CU", "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ",
    "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO",
    "FR", "FX", "GA", "GB", "GD", "GE", "GF", "GH", "GI", "GL", "GM", "GN",
    "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR",
    "HT", "HU", "ID", "IE", "IL", "IN", "IO", "IQ", "IR", "IS", "IT", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY",
    "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
    "MA", "MC", "MD", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ",
    "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE",
    "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE",
    "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY",
    "QA", "RE", "RO", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SI",
    "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "ST", "SV", "SY", "SZ", "TC",
    "TD", "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TP", "TR", "TT",
    "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE",
    "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "RS", "ZA", "ZM", "ME",
    "ZW", "A1", "A2", "O1", "AX", "GG", "IM", "JE", "BL", "MF",
)


class GeoIpMmdb:
    """Country lookup over an MMDB file via the official maxminddb package."""

    def __init__(self, reader: Any, path: str) -> None:
        self._reader = reader
        self.path = path

    def lookup(self, ip: str) -> str | None:
        try:
            record = self._reader.get(ip)
        except (ValueError, OSError):
            return None
        if not isinstance(record, dict):
            return None
        country = record.get("country") or record.get("registered_country")
        if not isinstance(country, dict):
            return None
        code = country.get("iso_code")
        return code if isinstance(code, str) and len(code) == 2 else None


class GeoIpDat:
    """Legacy MaxMind GeoIP.dat country tree (best-effort fallback)."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def lookup(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version != 4:
            return None
        # The legacy dbip tree: 3-byte little-endian records, child values
        # are NODE indexes (byte position = node * 6), a value >=
        # COUNTRY_BEGIN terminates and yields the country index.
        ipnum = int(addr)
        node = 0
        data = self._data
        for depth in range(31, -1, -1):
            bit = (ipnum >> depth) & 1
            base = node * 6 + 3 * bit
            value = int.from_bytes(data[base:base + 3], "little")
            if value >= COUNTRY_BEGIN:
                index = value - COUNTRY_BEGIN
                if 0 <= index < len(COUNTRY_CODES):
                    code = COUNTRY_CODES[index]
                    return None if code == "--" else code
                return None
            node = value
        return None


class GeoIpDatabase:
    """Compatibility alias for the legacy reader."""

    def __init__(self, data: bytes, record_length: int = 3) -> None:
        self._dat = GeoIpDat(data)
        self.record_length = record_length

    def lookup(self, ip: str) -> str | None:
        return self._dat.lookup(ip)


def load_geoip(path: str | Path) -> GeoIpDatabase | GeoIpMmdb | None:
    """Load an MMDB (primary) or legacy GeoIP.dat (fallback) database.

    Returns None when the file is missing or cannot be validated.
    """
    path = Path(path)
    if not path.exists():
        log.warning("GeoIP file missing: path=%s", path)
        return None

    if path.suffix.lower() == ".mmdb":
        try:
            import maxminddb

            reader = maxminddb.open_database(str(path), maxminddb.MODE_FILE)
            db = GeoIpMmdb(reader, str(path))
            probe = db.lookup("8.8.8.8")
            log.info(
                "GeoIP MMDB loaded: path=%s, probe(8.8.8.8)=%s", path, probe
            )
            return db
        except Exception as exc:
            log.warning("GeoIP MMDB load failed: path=%s, error=%s", path, exc)
            return None

    # Legacy .dat: structural validation against well-known public IPs.
    data = path.read_bytes()
    db = GeoIpDat(data)
    probes = (("8.8.8.8", "US"), ("200.100.50.25", "BR"))
    results = [db.lookup(ip) for ip, _ in probes]
    if any(results):  # at least one public IP resolved to a country
        log.info("GeoIP legacy dat loaded: path=%s, bytes=%d", path, len(data))
        return db
    log.warning("GeoIP legacy dat failed validation: path=%s", path)
    return None
