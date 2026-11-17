from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

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


class IdpBlockRecord(BaseModel):
    block_id: str
    ip: str
    reason: str
    severity: str
    confidence: float
    enforcement_layer: str = "iptables"  # iptables | nftables | waf | k8s_network_policy | rate_limit
    status: str = "active"  # active | expired | unblocked | failed | simulated
    incident_id: Optional[str] = None
    alert_id: Optional[str] = None
    created_at: datetime
    expires_at: datetime
    unblocked_at: Optional[datetime] = None
    unblocked_by: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IdpAllowlistEntry(BaseModel):
    entry_id: str
    ip_or_cidr: str
    label: str
    is_management: bool = False
    created_at: datetime
    created_by: str = "system"


class SecurityIncident(BaseModel):
    incident_id: str
    title: str
    classification: str
    severity: str
    confidence: float
    src_ip: str
    dst_ip: str
    target_app: Optional[str] = None
    target_namespace: Optional[str] = None
    status: str = "open"  # open | contained | mitigated | resolved
    first_seen: datetime
    last_seen: datetime
    event_count: int = 1
    detection_sources: List[str] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    prevention_action: str = "Monitoring"
    response_status: str = "Active Monitoring"


class DiscoveredApplication(BaseModel):
    app_id: str
    name: str
    namespace: str
    service_name: str
    ingress_domain: str
    exposed_ports: List[int] = Field(default_factory=list)
    pod_count: int = 1
    monitoring_status: str = "active"  # active | degraded | unmonitored
    security_status: str = "protected"  # protected | under_attack | warning | isolated
    threat_count: int = 0
    waf_enabled: bool = True
    last_seen: datetime
    recent_threats: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LayerSecurityEvent(BaseModel):
    event_id: str
    created_at: datetime
    layer: str  # host | kubernetes | network | application | waf | idp
    category: str
    severity: str
    src_ip: str
    dst_ip: str
    target: str
    namespace: Optional[str] = None
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ManualBlockRequest(BaseModel):
    ip: str
    reason: str = "Manual administrator block"
    severity: str = "high"
    duration_seconds: Optional[int] = None
    enforcement_layer: str = "iptables"


class AllowlistAddRequest(BaseModel):
    ip_or_cidr: str
    label: str = "Trusted IP/CIDR"
    is_management: bool = False


class HttpInspectRequest(BaseModel):
    src_ip: str
    dst_ip: str = "10.96.0.10"
    host: str = "localhost"
    method: str = "GET"
    uri: str = "/"
    user_agent: str = "Mozilla/5.0"
    status_code: int = 200
    headers: Dict[str, str] = Field(default_factory=dict)
    body_snippet: Optional[str] = None
    target_app: Optional[str] = None
    namespace: Optional[str] = "default"


class K8sAuditEventRequest(BaseModel):
    verb: str
    user: str
    namespace: str = "default"
    resource: str = "pods"
    resource_name: str = ""
    source_ip: str = "127.0.0.1"
    status_code: int = 200
    privileged: bool = False
    run_as_root: bool = False
    host_path: Optional[str] = None
    image: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
