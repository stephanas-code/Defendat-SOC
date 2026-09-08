from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaAdminClient
from pydantic import BaseModel
import redis

from app.config import settings
from app.db import clear_alerts, get_alert_stats, get_flow_stats, get_recent_alerts, init_db, insert_alert, insert_flow, ping_db
from app.dedup import AlertDeduplicator
from app.detection.detector import Detector, get_model_metrics
from app.detection.models import load_models
from app.geoip import GeoIPEnricher
from app.kafka_consumer import FlowConsumer
from app.kafka_producer import AlertProducer
from app.logging_setup import setup_logging
from app.schemas import AlertRecord, FlowRecord
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


def handle_flow(flow: FlowRecord) -> None:
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
        return

    # GeoIP enrich (best-effort)
    try:
        alert.geoip = geoip.lookup(alert.src_ip)
    except Exception:
        pass

    dedup_key = f"dedup:{alert.src_ip}:{alert.label}:{alert.severity}"
    if not dedup.should_emit(dedup_key):
        return

    try:
        insert_alert(alert)
    except Exception:
        logger.exception("alert_insert_failed")

    payload: Dict[str, Any] = alert.model_dump()
    # send to alert topic (for responder/IDP or SIEM integration)
    alert_producer.send_alert(payload)

    # push to websocket (thread-safe)
    broadcaster.broadcast(payload)


flow_consumer = FlowConsumer(on_flow=handle_flow)


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
    import asyncio

    broadcaster.set_loop(asyncio.get_running_loop())
    flow_consumer.start()
    yield
    flow_consumer.stop()


app = FastAPI(title=settings.project_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.get("/")
def root() -> Dict[str, Any]:
    """Root endpoint with API information and available endpoints."""
    return {
        "service": settings.project_name,
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health - Basic health check and model status",
            "status": "/status - Detailed system status and metrics",
            "models": "/models - Detailed model information and capabilities",
            "alerts": "/alerts?limit=N - Get recent alerts",
            "ingest": "/ingest/alert - POST endpoint for alert ingestion (demo)",
            "websocket": "/ws/alerts - WebSocket endpoint for real-time alerts"
        },
        "documentation": "See DATASET_ANALYSIS.md and ARTIFACTS_DATASETS_SUMMARY.md for training information"
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    """Basic health check with model loading status."""
    return {
        "status": "ok",
        "models": {
            "scaler": bool(models.scaler),
            "isoforest": bool(models.isoforest),
            "xgboost": bool(models.xgb_model),
            "lstm_onnx": bool(models.lstm_onnx_path),
        },
        "message": "For detailed model information, visit /models"
    }


@app.get("/models")
def models_info() -> Dict[str, Any]:
    """Detailed information about ML models and their status."""
    model_status = {
        "scaler": {
            "loaded": bool(models.scaler),
            "purpose": "Feature normalization for Isolation Forest",
            "required_for": ["Isolation Forest"],
            "file": "artifacts/scaler.joblib"
        },
        "isoforest": {
            "loaded": bool(models.isoforest),
            "purpose": "Unsupervised anomaly detection",
            "detects": ["Unknown attacks", "Zero-day threats", "Traffic anomalies"],
            "training_data": "CIC-IDS2017 benign traffic (artifacts/CSVs/)",
            "file": "artifacts/isoforest.joblib",
            "performance": {"inference_time_ms": "<10ms", "accuracy": "85-95%"}
        },
        "xgboost": {
            "loaded": bool(models.xgb_model),
            "purpose": "Multi-class attack classification",
            "detects": ["DDoS", "DoS", "Botnet", "Web Attacks", "Port Scanning", "Brute Force"],
            "training_data": "CIC-IDS2017 mixed traffic (artifacts/CSVs/)",
            "file": "artifacts/xgboost.json",
            "performance": {"inference_time_ms": "<5ms", "accuracy": "90-98%"}
        },
        "lstm_onnx": {
            "loaded": bool(models.lstm_onnx_path),
            "purpose": "Temporal anomaly detection (sequence-based)",
            "detects": ["Temporal patterns", "Sequential anomalies"],
            "training_data": "Requires custom LSTM training",
            "file": "artifacts/lstm_autoencoder.onnx",
            "status": "Optional - not required for basic detection"
        }
    }
    
    # Add training instructions if models are not loaded
    if not any([models.scaler, models.isoforest, models.xgb_model]):
        model_status["training_instructions"] = {
            "quick_start": "Run: python scripts/train_all_models.py --artifacts-dir artifacts/CSVs --output-dir artifacts",
            "manual_training": [
                "1. Prepare data: python scripts/prepare_training_data.py --artifacts-dir artifacts/CSVs --output-dir artifacts/processed",
                "2. Train Isolation Forest: python scripts/train_isoforest.py --input artifacts/processed/benign_features.npy --output artifacts",
                "3. Train XGBoost: python scripts/train_xgboost.py --features artifacts/processed/xgboost_features.npy --labels artifacts/processed/xgboost_labels.npy --label-names artifacts/processed/xgboost_label_names.txt --output artifacts"
            ],
            "documentation": "See DATASET_ANALYSIS.md and ARTIFACTS_DATASETS_SUMMARY.md"
        }
    
    return {
        "models": model_status,
        "overall_status": "operational" if any([models.isoforest, models.xgb_model]) else "no_models_loaded",
        "recommendation": "Train models using: python scripts/train_all_models.py" if not any([models.isoforest, models.xgb_model]) else "Models loaded and ready for detection"
    }


@app.get("/alerts")
def alerts(limit: int = 200) -> Dict[str, Any]:
    return {"items": list(get_recent_alerts(limit=limit))}


class RuntimeSettingsUpdate(BaseModel):
    sensitivity: Optional[int] = None
    modules: Optional[List[Dict[str, Any]]] = None
    notifications: Optional[Dict[str, Any]] = None
    display: Optional[Dict[str, Any]] = None


_runtime_settings: Dict[str, Any] = {
    "sensitivity": 85,
    "modules": [
        {"id": "dpi", "label": "Deep Packet Inspection (DPI)", "enabled": True},
        {"id": "flow", "label": "Flow-based Anomaly Engine", "enabled": True},
        {"id": "bayes", "label": "Bayesian Behavioral Analysis", "enabled": False},
        {"id": "geoip", "label": "Geo-IP Threat Intel Sync", "enabled": True},
    ],
    "isoforest_threshold": settings.isoforest_threshold,
    "xgboost_confidence_threshold": settings.xgboost_confidence_threshold,
}


@app.get("/settings")
def get_runtime_settings() -> Dict[str, Any]:
    _runtime_settings["isoforest_threshold"] = settings.isoforest_threshold
    _runtime_settings["xgboost_confidence_threshold"] = settings.xgboost_confidence_threshold
    return _runtime_settings


@app.post("/settings")
def update_runtime_settings(payload: RuntimeSettingsUpdate) -> Dict[str, Any]:
    if payload.sensitivity is not None:
        sens = max(1, min(100, payload.sensitivity))
        _runtime_settings["sensitivity"] = sens
        # Dynamically scale detection thresholds based on sensitivity:
        # Higher sensitivity -> lower threshold for triggering anomaly
        # Default sens=85: isoforest_threshold = 0.65
        settings.isoforest_threshold = round(0.95 - (sens / 100.0) * 0.35, 3)
        settings.xgboost_confidence_threshold = round(max(0.40, 0.95 - (sens / 100.0) * 0.35), 3)

    if payload.modules is not None:
        _runtime_settings["modules"] = payload.modules
    if payload.notifications is not None:
        _runtime_settings["notifications"] = payload.notifications
    if payload.display is not None:
        _runtime_settings["display"] = payload.display

    _runtime_settings["isoforest_threshold"] = settings.isoforest_threshold
    _runtime_settings["xgboost_confidence_threshold"] = settings.xgboost_confidence_threshold
    logger.info("runtime_settings_updated", extra={"settings": _runtime_settings})
    return {"status": "ok", "settings": _runtime_settings}


@app.delete("/alerts")
def delete_alerts() -> Dict[str, Any]:
    """Clear all stored alerts from database and reset deduplication cache."""
    try:
        clear_alerts()
        dedup.clear()
        # Broadcast clear event to all active WebSocket clients so UI immediately clears
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

    return {
        "ok": bool(db_ok and redis_ok and kafka_ok),
        "components": {
            "database": {"ok": db_ok},
            "redis": {"ok": redis_ok},
            "kafka": {"ok": kafka_ok},
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
    }


@app.post("/ingest/alert")
async def ingest_alert(alert: AlertRecord) -> Dict[str, Any]:
    """Demo ingestion endpoint.

    This is intentionally simple to support replaying datasets that are *not* flow-based.
    In production, keep this endpoint private or remove it.
    """
    if alert.geoip is None:
        try:
            alert.geoip = geoip.lookup(alert.src_ip)
        except Exception:
            pass

    try:
        insert_alert(alert)
    except Exception:
        logger.exception("alert_insert_failed")

    payload: Dict[str, Any] = alert.model_dump()
    alert_producer.send_alert(payload)
    broadcaster.broadcast(payload)
    return {"status": "ok"}


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            # keep-alive; client doesn't need to send
            await ws.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(ws)

