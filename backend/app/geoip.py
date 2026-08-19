from __future__ import annotations

import logging
from typing import Optional

import maxminddb

from app.config import settings
from app.schemas import GeoIPInfo

logger = logging.getLogger(__name__)


class GeoIPEnricher:
    def __init__(self) -> None:
        self._reader = None
        try:
            self._reader = maxminddb.open_database(settings.geoip_mmdb_path)
            logger.info("geoip_enabled", extra={"path": settings.geoip_mmdb_path})
        except Exception:
            logger.warning("geoip_disabled")

    def lookup(self, ip: str) -> Optional[GeoIPInfo]:
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip.startswith("172.") or ip == "0.0.0.0":
                return GeoIPInfo(
                    country_iso="LAN",
                    country_name="Local Network (LAN)",
                    city_name="Internal Network",
                    latitude=0.0,
                    longitude=0.0,
                )
        except Exception:
            pass

        if not self._reader:
            return None
        try:
            data = self._reader.get(ip) or {}
            country = data.get("country", {})
            city = data.get("city", {})
            location = data.get("location", {})
            return GeoIPInfo(
                country_iso=country.get("iso_code") or "UNK",
                country_name=(country.get("names", {}) or {}).get("en") or "Unknown Region",
                city_name=(city.get("names", {}) or {}).get("en") or "Unknown City",
                latitude=location.get("latitude"),
                longitude=location.get("longitude"),
            )
        except Exception:
            return None
