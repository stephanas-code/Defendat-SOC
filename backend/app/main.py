from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaAdminClient
from pydantic import BaseModel
import redis

from app.config import settings
from app.correlation import ThreatCorrelationEngine
from app.db import (
    clear_alerts,
    get_alert_stats,
    get_flow_stats,
    get_recent_alerts,
    get_security_events,
    init_db,
    insert_alert,
    insert_flow,
    ping_db,
    record_app_threat,
)
from app.dedup import AlertDeduplicator
from app.detection.detector import Detector, get_model_metrics
from app.detection.models import load_models
from app.geoip import GeoIPEnricher
from app.idp_engine import IdpEngine
from app.kafka_consumer import FlowConsumer
from app.kafka_producer import AlertProducer
from app.logging_setup import setup_logging
from app.monitors.host_monitor import HostMonitor
from app.monitors.k8s_monitor import KubernetesMonitor
from app.monitors.waf_monitor import WafMonitor
from app.schemas import (
    AlertRecord,
    AllowlistAddRequest,
    FlowRecord,
    HttpInspectRequest,
    K8sAuditEventRequest,
    ManualBlockRequest,
)
from app.ws import ThreadsafeBroadcaster, WebSocketManager

setup_logging(settings.backend_log_level)
logger = logging.getLogger(__name__)


ws_manager = WebSocketManager()
broadcaster = ThreadsafeBroadcaster(ws_manager)
dedup = AlertDeduplicator()
geoip = GeoIPEnricher()
models = load_models()
detector = Detector(models)
alert_producer = AlertProducer()

correlation_engine = ThreatCorrelationEngine()
idp_engine = IdpEngine(on_event=lambda ev: broadcaster.broadcast(ev))


def verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """Optional API authentication guard for administrative endpoints."""
    if not settings.api_auth_enabled:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")


def process_and_dispatch_alert(
    alert: AlertRecord,
    detection_source: str = "AI Network Detection",
    bypass_dedup: bool = False,
) -> Dict[str, Any]:
    """Central pipeline for GeoIP enrichment, deduplication, persistence, correlation, IDP prevention, and live streaming."""
    if alert.geoip is None:
        try:
            alert.geoip = geoip.lookup(alert.src_ip)
        except Exception:
            pass

    if not bypass_dedup:
        dedup_key = f"dedup:{alert.src_ip}:{alert.label}:{alert.severity}"
        if not dedup.should_emit(dedup_key):
            return {"emitted": False, "reason": "deduplicated"}

    # 1. Correlate across layers into a unified SecurityIncident
    incident = None
    if settings.threat_intelligence_enabled:
        try:
            incident = correlation_engine.correlate_alert(alert, detection_source=detection_source)
            alert.signals["incident_id"] = incident.incident_id
            alert.signals["detection_source"] = detection_source
        except Exception:
            logger.exception("correlation_failed")

    # 2. Evaluate IDP active threat prevention
    block_record = None
    if settings.idp_enabled or idp_engine.enabled:
        try:
            block_record = idp_engine.evaluate_alert(
                alert,
                incident_id=incident.incident_id if incident else None,
            )
            if block_record:
                alert.signals["idp_action"] = block_record.status
                alert.signals["idp_layer"] = block_record.enforcement_layer
                alert.signals["idp_block_id"] = block_record.block_id
                if incident and block_record.status in ("active", "simulated"):
                    correlation_engine.record_prevention_action(
                        incident.incident_id,
                        action=f"{block_record.status.upper()} ({block_record.enforcement_layer}) for {idp_engine.block_seconds}s",
                        response_status="Blocked & Contained" if block_record.status == "active" else "Simulated (Monitor Mode)",
                    )
        except Exception:
            logger.exception("idp_evaluation_failed")

    # 3. Attribute port/target threat to discovered application inventory
    try:
        if alert.dst_port:
            record_app_threat(
                alert.dst_port,
                {
                    "alert_id": alert.alert_id,
                    "timestamp": alert.created_at.isoformat(),
                    "category": alert.label,
                    "severity": alert.severity,
                    "src_ip": alert.src_ip,
                    "confidence": alert.confidence,
                },
            )
    except Exception:
        pass

    # 4. Store in TimescaleDB
    try:
        insert_alert(alert)
    except Exception:
        logger.exception("alert_insert_failed")

    # 5. Publish to Kafka alerts topic & broadcast to WebSocket clients
    payload: Dict[str, Any] = alert.model_dump(mode="json")
    alert_producer.send_alert(payload)
    broadcaster.broadcast(payload)

    return {
        "emitted": True,
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "label": alert.label,
        "confidence": alert.confidence,
        "incident_id": incident.incident_id if incident else None,
        "idp_block": block_record.model_dump(mode="json") if block_record else None,
    }


def handle_flow(flow: FlowRecord) -> Optional[Dict[str, Any]]:
    # Store flow for forensics (best-effort)
    try:
        insert_flow(
            flow_id=flow.flow_id,
            first_seen=flow.first_seen,
            last_seen=flow.last_seen,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            features_json=flow.features,
        )
    except Exception:
        logger.exception("flow_insert_failed")

    alert = detector.detect(flow)
    if not alert:
        return None

    return process_and_dispatch_alert(alert, detection_source="AI Network Detection")


flow_consumer = FlowConsumer(on_flow=handle_flow)
host_monitor = HostMonitor(on_alert=lambda a, src: process_and_dispatch_alert(a, detection_source=src, bypass_dedup=True))
k8s_monitor = KubernetesMonitor(
    on_alert=lambda a, src: process_and_dispatch_alert(a, detection_source=src, bypass_dedup=True),
    on_node_ips=idp_engine.register_k8s_node_ips,
)
waf_monitor = WafMonitor(on_alert=lambda a, src: process_and_dispatch_alert(a, detection_source=src, bypass_dedup=True))


def _ping_redis() -> bool:
    try:
        client = redis.Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)
        return bool(client.ping())
    except Exception:
        return False


def _ping_kafka() -> bool:
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=settings.kafka_brokers.split(","),
            request_timeout_ms=1000,
            api_version_auto_timeout_ms=1000,
            metadata_max_age_ms=5000,
        )
        admin.list_topics()
        admin.close()
        return True
    except Exception:
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    idp_engine.initialize()
    correlation_engine.initialize()

    import asyncio

    broadcaster.set_loop(asyncio.get_running_loop())
    flow_consumer.start()
    host_monitor.start()
    k8s_monitor.start()
    waf_monitor.start()
    yield
    flow_consumer.stop()
    host_monitor.stop()
    k8s_monitor.stop()
    waf_monitor.stop()
    idp_engine.stop()


app = FastAPI(title=settings.project_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root() -> Dict[str, Any]:
    """Root endpoint with API information and available endpoints."""
    return {
        "service": settings.project_name,
        "version": "2.0.0-production",
        "status": "operational",
        "capabilities": [
            "AI Network Flow IDS (44-Feature IsolationForest + XGBoost + LSTM)",
            "Active Intrusion Prevention System (IDP with 12 Safety Guardrails)",
            "Linux Host & System Log Monitoring",
            "Kubernetes Cluster Auto-Discovery & Workload Security Audit",
            "OWASP CRS Web Application Firewall (WAF) & API Protection",
            "Centralized Multi-Layer Threat Intelligence & Incident Correlation",
        ],
        "endpoints": {
            "health": "/health",
            "status": "/status",
            "models": "/models",
            "alerts": "/alerts?limit=N",
            "ingest_flow": "/ingest/flow - POST 44-feature flow for live ML inference & IDP",
            "ingest_alert": "/ingest/alert - POST alert record",
            "idp_status": "/idp/status",
            "idp_block": "/idp/block",
            "idp_unblock": "/idp/unblock/{ip}",
            "idp_kill_switch": "/idp/kill-switch",
            "idp_allowlist": "/idp/allowlist",
            "incidents": "/incidents",
            "kubernetes_status": "/kubernetes/status",
            "applications": "/kubernetes/applications",
            "host_status": "/host/status",
            "waf_status": "/waf/status",
            "waf_inspect": "/waf/inspect",
            "events": "/events",
            "websocket": "/ws/alerts",
        },
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    """Basic health check with model and IDP status."""
    return {
        "status": "ok",
        "ids_enabled": settings.ids_enabled,
        "idp_enabled": idp_engine.enabled,
        "idp_enforcement_mode": idp_engine.enforcement_mode,
        "models": {
            "scaler": bool(models.scaler),
            "isoforest": bool(models.isoforest),
            "xgboost": bool(models.xgb_model),
            "lstm_onnx": bool(models.lstm_onnx_path),
        },
        "message": "AI IDS/IDP operational",
    }


@app.get("/models")
def models_info() -> Dict[str, Any]:
    """Detailed information about ML models and their live runtime status."""
    import os

    def _fsize(rel: str) -> int:
        p = os.path.join(settings.artifacts_dir, rel)
        return os.path.getsize(p) if os.path.exists(p) else 0

    metrics = get_model_metrics()
    iso_estimators = getattr(models.isoforest, "n_estimators", None) if models.isoforest else None
    xgb_classes = len(models.xgb_labels) if models.xgb_labels else 0

    model_status = {
        "scaler": {
            "loaded": bool(models.scaler),
            "purpose": "Feature normalization (44 CICFlowMeter features)",
            "required_for": ["Isolation Forest", "LSTM Autoencoder"],
            "file": "artifacts/scaler.joblib",
            "file_size_bytes": _fsize("scaler.joblib"),
        },
        "isoforest": {
            "loaded": bool(models.isoforest),
            "purpose": "Unsupervised zero-day anomaly detection",
            "detects": ["Unknown attacks", "Zero-day threats", "Traffic anomalies"],
            "n_estimators": iso_estimators,
            "threshold": settings.isoforest_threshold,
            "file": "artifacts/isoforest.joblib",
            "file_size_bytes": _fsize("isoforest.joblib"),
            "metrics": metrics.get("isoforest"),
        },
        "xgboost": {
            "loaded": bool(models.xgb_model),
            "purpose": f"Supervised multi-class attack classification ({xgb_classes} classes)",
            "classes": models.xgb_labels or [],
            "confidence_threshold": settings.xgboost_confidence_threshold,
            "file": "artifacts/xgboost.json",
            "file_size_bytes": _fsize("xgboost.json"),
            "metrics": metrics.get("xgboost"),
        },
        "lstm_onnx": {
            "loaded": bool(models.lstm_onnx_path),
            "purpose": f"Temporal sequence anomaly detection (seq_len={settings.lstm_seq_len})",
            "recon_error_threshold": settings.lstm_recon_error_threshold,
            "file": "artifacts/lstm_autoencoder.onnx",
            "file_size_bytes": _fsize("lstm_autoencoder.onnx"),
            "metrics": metrics.get("lstm_onnx"),
        },
    }
    return {
        "models": model_status,
        "overall_status": "operational" if any([models.isoforest, models.xgb_model]) else "no_models_loaded",
    }


@app.get("/alerts")
def alerts(limit: int = 200) -> Dict[str, Any]:
    return {"items": list(get_recent_alerts(limit=limit))}


@app.delete("/alerts")
def delete_alerts(_: None = Depends(verify_api_key)) -> Dict[str, Any]:
    """Clear all stored alerts from database and reset deduplication cache."""
    try:
        clear_alerts()
        dedup.clear()
        correlation_engine.clear_all()
        idp_engine.clear_history()
        k8s_monitor.discover_once()
        broadcaster.broadcast({"action": "clear", "type": "clear"})
        return {"status": "ok", "message": "All alerts cleared successfully"}
    except Exception as e:
        logger.exception("clear_alerts_failed")
        return {"status": "error", "message": str(e)}


@app.get("/status")
def status() -> Dict[str, Any]:
    db_ok = ping_db()
    redis_ok = _ping_redis()
    kafka_ok = _ping_kafka()

    alerts_stats = None
    flows_stats = None
    if db_ok:
        try:
            alerts_stats = get_alert_stats()
            flows_stats = get_flow_stats()
        except Exception:
            logger.exception("stats_fetch_failed")

    idp_st = idp_engine.get_status()
    k8s_st = k8s_monitor.get_status()
    host_st = host_monitor.get_status()
    waf_st = waf_monitor.get_status()
    incidents_list = correlation_engine.list_incidents(limit=25)

    return {
        "ok": bool(db_ok and redis_ok and kafka_ok),
        "components": {
            "database": {"ok": db_ok},
            "redis": {"ok": redis_ok},
            "kafka": {"ok": kafka_ok},
            "ids": {"ok": settings.ids_enabled, "enabled": settings.ids_enabled},
            "idp": {
                "ok": idp_st["enabled"] and not idp_st["kill_switch_engaged"],
                "enabled": idp_st["enabled"],
                "mode": idp_st["enforcement_mode"],
                "active_blocks": idp_st["active_blocks_count"],
            },
            "waf": {"ok": waf_st["enabled"], "enabled": waf_st["enabled"], "mode": waf_st["mode"]},
            "kubernetes": {"ok": k8s_st["connected"], "status": k8s_st["cluster_status"]},
            "host": {"ok": host_st["status"] != "critical", "status": host_st["status"]},
        },
        "models": {
            "scaler": bool(models.scaler),
            "isoforest": bool(models.isoforest),
            "xgboost": bool(models.xgb_model),
            "lstm_onnx": bool(models.lstm_onnx_path),
        },
        "model_metrics": get_model_metrics(),
        "alerts": alerts_stats,
        "flows": flows_stats,
        "idp": {
            "enabled": idp_st["enabled"],
            "enforcement_mode": idp_st["enforcement_mode"],
            "kill_switch_engaged": idp_st["kill_switch_engaged"],
            "active_blocks_count": idp_st["active_blocks_count"],
            "failed_attempts_count": idp_st["failed_attempts_count"],
            "allowlist_count": len(idp_st["allowlist"]),
        },
        "infrastructure": {
            "server_status": host_st["status"],
            "cluster_status": k8s_st["cluster_status"],
            "monitored_nodes": k8s_st["nodes_count"],
            "monitored_namespaces": k8s_st["namespaces_count"],
            "monitored_pods": k8s_st["pods_count"],
            "monitored_applications": k8s_st["applications_count"],
            "active_connections": host_st["active_connections"],
            "established_connections": host_st["established_connections"],
            "cpu_load_pct": host_st["cpu_load_pct"],
            "memory_used_pct": host_st["memory_used_pct"],
            "incidents_open": len(incidents_list),
        },
        "waf": {
            "enabled": waf_st["enabled"],
            "total_inspected": waf_st["total_inspected"],
            "http_attacks_detected": waf_st["http_attacks_detected"],
            "blocked_requests_count": waf_st["blocked_requests_count"],
            "rate_limited_count": waf_st["rate_limited_count"],
        },
    }


# --- Flow & Alert Ingestion Endpoints ---

@app.post("/ingest/flow")
async def ingest_flow(flow: FlowRecord) -> Dict[str, Any]:
    """Ingest a 44-feature network flow directly into the ML inference, correlation, and IDP pipeline."""
    res = handle_flow(flow)
    if res is None:
        return {"status": "ok", "detected": False, "label": "Benign"}
    return {"status": "ok", "detected": True, **res}


@app.post("/ingest/alert")
async def ingest_alert(alert: AlertRecord) -> Dict[str, Any]:
    """Ingest an alert record and process it through GeoIP, correlation, IDP, and persistence."""
    res = process_and_dispatch_alert(alert, detection_source=str(alert.signals.get("layer", "External Sensor")), bypass_dedup=True)
    return {"status": "ok", **res}


# --- IDP Prevention & Control Endpoints ---

@app.get("/idp/status")
def get_idp_status() -> Dict[str, Any]:
    return idp_engine.get_status()


@app.post("/idp/block")
def manual_idp_block(req: ManualBlockRequest, _: None = Depends(verify_api_key)) -> Dict[str, Any]:
    rec = idp_engine.block_ip(
        ip=req.ip,
        reason=req.reason,
        severity=req.severity,
        confidence=0.99,
        duration_seconds=req.duration_seconds,
        enforcement_layer=req.enforcement_layer,
    )
    return {"status": "ok", "block": rec.model_dump(mode="json")}


@app.post("/idp/unblock/{ip:path}")
def manual_idp_unblock(ip: str, _: None = Depends(verify_api_key)) -> Dict[str, Any]:
    idp_engine.unblock_ip(ip, unblocked_by="manual_admin")
    return {"status": "ok", "ip": ip, "idp": idp_engine.get_status()}


class KillSwitchRequest(BaseModel):
    engage: bool = True


@app.post("/idp/kill-switch")
def trigger_idp_kill_switch(req: KillSwitchRequest, _: None = Depends(verify_api_key)) -> Dict[str, Any]:
    st = idp_engine.emergency_kill_switch(engage=req.engage)
    broadcaster.broadcast({"type": "idp_kill_switch", "engaged": req.engage})
    return {"status": "ok", "idp": st}


class IdpPolicyUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    enforcement_mode: Optional[str] = None
    block_seconds: Optional[int] = None
    confidence_threshold: Optional[float] = None
    auto_block_critical: Optional[bool] = None
    auto_block_high: Optional[bool] = None


@app.post("/idp/policy")
def update_idp_policy(req: IdpPolicyUpdateRequest, _: None = Depends(verify_api_key)) -> Dict[str, Any]:
    st = idp_engine.update_policy(
        enabled=req.enabled,
        enforcement_mode=req.enforcement_mode,
        block_seconds=req.block_seconds,
        confidence_threshold=req.confidence_threshold,
        auto_block_critical=req.auto_block_critical,
        auto_block_high=req.auto_block_high,
    )
    return {"status": "ok", "idp": st}


@app.get("/idp/allowlist")
def list_allowlist() -> Dict[str, Any]:
    st = idp_engine.get_status()
    return {"items": st["allowlist"], "system_protected_ips": st["system_protected_ips"]}


@app.post("/idp/allowlist")
def add_to_allowlist(req: AllowlistAddRequest, _: None = Depends(verify_api_key)) -> Dict[str, Any]:
    try:
        entry = idp_engine.add_allowlist(req.ip_or_cidr, req.label, req.is_management)
        return {"status": "ok", "entry": entry.model_dump(mode="json")}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IP or CIDR: {e}")


@app.delete("/idp/allowlist")
def remove_from_allowlist(ip_or_cidr: str = Query(...), _: None = Depends(verify_api_key)) -> Dict[str, Any]:
    idp_engine.remove_allowlist(ip_or_cidr)
    return {"status": "ok", "removed": ip_or_cidr}


# --- Centralized Threat Intelligence & Incidents ---

@app.get("/incidents")
def list_correlated_incidents(limit: int = 100) -> Dict[str, Any]:
    return {"items": correlation_engine.list_incidents(limit=limit)}


# --- Kubernetes Monitoring & Application Discovery ---

@app.get("/kubernetes/status")
def kubernetes_status() -> Dict[str, Any]:
    return k8s_monitor.get_status()


@app.get("/kubernetes/applications")
def kubernetes_applications() -> Dict[str, Any]:
    return {"items": k8s_monitor.list_applications()}


@app.post("/kubernetes/audit")
def ingest_k8s_audit(req: K8sAuditEventRequest) -> Dict[str, Any]:
    ev = k8s_monitor.ingest_audit_event(req)
    return {"status": "ok", "event": ev}


class WorkloadIsolateRequest(BaseModel):
    namespace: str = "default"
    workload: str
    reason: str = "Manual or automated compromise containment"


@app.post("/kubernetes/isolate")
def isolate_k8s_workload(req: WorkloadIsolateRequest, _: None = Depends(verify_api_key)) -> Dict[str, Any]:
    res = k8s_monitor.isolate_workload(req.namespace, req.workload, req.reason)
    return {"status": "ok", "isolation": res}


# --- Linux Host Monitoring ---

@app.get("/host/status")
def get_host_status() -> Dict[str, Any]:
    return host_monitor.get_status()


class HostLogLineRequest(BaseModel):
    line: str
    source: str = "auth.log"


@app.post("/host/log")
def ingest_host_log(req: HostLogLineRequest) -> Dict[str, Any]:
    ev = host_monitor.ingest_log_line(req.line, source=req.source)
    return {"status": "ok", "matched": ev is not None, "event": ev}


# --- Website, API & WAF Protection ---

@app.get("/waf/status")
def get_waf_status() -> Dict[str, Any]:
    return waf_monitor.get_status()


@app.post("/waf/inspect")
def inspect_http_request(req: HttpInspectRequest) -> Dict[str, Any]:
    res = waf_monitor.inspect_http_request(req)
    return {"status": "ok", **res}


@app.get("/waf/auth-verify")
def nginx_ingress_auth_verify(request: Request) -> Dict[str, Any]:
    """Endpoint for Kubernetes NGINX Ingress external auth (`nginx.ingress.kubernetes.io/auth-url`)."""
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or (request.client.host if request.client else "127.0.0.1")
    )
    orig_uri = request.headers.get("X-Original-URI", request.url.path)
    orig_method = request.headers.get("X-Original-Method", request.method)
    orig_host = request.headers.get("X-Original-Host", request.headers.get("Host", "localhost"))
    ua = request.headers.get("User-Agent", "")

    # Check if IP is currently blocked in IDP
    idp_st = idp_engine.get_status()
    if any(b["ip"] == client_ip and b["status"] == "active" for b in idp_st["active_blocks"]):
        raise HTTPException(status_code=403, detail="Blocked by AI IDP")

    res = waf_monitor.inspect_http_request(
        HttpInspectRequest(
            src_ip=client_ip,
            host=orig_host,
            method=orig_method,
            uri=orig_uri,
            user_agent=ua,
        )
    )
    if not res.get("allowed", True):
        raise HTTPException(status_code=403, detail=f"Blocked by WAF rule {res.get('rule_id')}")
    return {"allowed": True}


# --- Unified Security Events ---

@app.get("/events")
def list_security_events(layer: Optional[str] = None, limit: int = 150) -> Dict[str, Any]:
    return {"items": get_security_events(layer=layer, limit=limit)}


# --- Runtime Settings Synchronization ---

class RuntimeSettingsUpdate(BaseModel):
    sensitivity: Optional[int] = None
    modules: Optional[List[Dict[str, Any]]] = None
    notifications: Optional[Dict[str, Any]] = None
    display: Optional[Dict[str, Any]] = None
    idp_enabled: Optional[bool] = None
    idp_enforcement_mode: Optional[str] = None


_runtime_settings: Dict[str, Any] = {
    "sensitivity": 85,
    "modules": [
        {"id": "dpi", "label": "OWASP CRS WAF & HTTP Inspection", "enabled": settings.waf_enabled},
        {"id": "flow", "label": "44-Feature AI Flow Anomaly Engine", "enabled": settings.ids_enabled},
        {"id": "k8s", "label": "Kubernetes Auto-Discovery & Audit", "enabled": settings.kubernetes_monitoring_enabled},
        {"id": "host", "label": "Linux Host & Log Monitor", "enabled": settings.host_monitoring_enabled},
        {"id": "idp", "label": "Automated Intrusion Prevention (IDP)", "enabled": settings.idp_enabled},
        {"id": "geoip", "label": "Geo-IP & Threat Correlation Engine", "enabled": settings.threat_intelligence_enabled},
    ],
    "isoforest_threshold": settings.isoforest_threshold,
    "xgboost_confidence_threshold": settings.xgboost_confidence_threshold,
    "idp_enabled": settings.idp_enabled,
    "idp_enforcement_mode": settings.idp_enforcement_mode,
}


@app.get("/settings")
def get_runtime_settings() -> Dict[str, Any]:
    _runtime_settings["isoforest_threshold"] = settings.isoforest_threshold
    _runtime_settings["xgboost_confidence_threshold"] = settings.xgboost_confidence_threshold
    _runtime_settings["idp_enabled"] = idp_engine.enabled
    _runtime_settings["idp_enforcement_mode"] = idp_engine.enforcement_mode
    return _runtime_settings


@app.post("/settings")
def update_runtime_settings(payload: RuntimeSettingsUpdate) -> Dict[str, Any]:
    if payload.sensitivity is not None:
        sens = max(1, min(100, payload.sensitivity))
        _runtime_settings["sensitivity"] = sens
        settings.isoforest_threshold = round(0.95 - (sens / 100.0) * 0.35, 3)
        settings.xgboost_confidence_threshold = round(max(0.40, 0.95 - (sens / 100.0) * 0.35), 3)

    if payload.modules is not None:
        _runtime_settings["modules"] = payload.modules
        for m in payload.modules:
            mid = m.get("id")
            en = bool(m.get("enabled", True))
            if mid == "flow":
                settings.ids_enabled = en
            elif mid == "idp":
                idp_engine.update_policy(enabled=en)
            elif mid == "dpi":
                settings.waf_enabled = en

    if payload.idp_enabled is not None:
        idp_engine.update_policy(enabled=payload.idp_enabled)
    if payload.idp_enforcement_mode is not None:
        idp_engine.update_policy(enforcement_mode=payload.idp_enforcement_mode)

    if payload.notifications is not None:
        _runtime_settings["notifications"] = payload.notifications
    if payload.display is not None:
        _runtime_settings["display"] = payload.display

    _runtime_settings["isoforest_threshold"] = settings.isoforest_threshold
    _runtime_settings["xgboost_confidence_threshold"] = settings.xgboost_confidence_threshold
    _runtime_settings["idp_enabled"] = idp_engine.enabled
    _runtime_settings["idp_enforcement_mode"] = idp_engine.enforcement_mode
    logger.info("runtime_settings_updated", extra={"settings": _runtime_settings})
    return {"status": "ok", "settings": _runtime_settings}


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)
