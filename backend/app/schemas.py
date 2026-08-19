from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class FlowRecord(BaseModel):
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_seen: datetime
    last_seen: datetime
    features: Dict[str, float]


class GeoIPInfo(BaseModel):
    country_iso: Optional[str] = None
    country_name: Optional[str] = None
    city_name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class AlertRecord(BaseModel):
    alert_id: str
    created_at: datetime
    flow_id: str

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    severity: str = Field(pattern="^(critical|high|medium|low)$")
    label: str
    confidence: float

    signals: Dict[str, Any]
    geoip: Optional[GeoIPInfo] = None
