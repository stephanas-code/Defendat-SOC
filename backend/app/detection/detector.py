from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

import numpy as np

from app.config import settings
from app.detection.models import LoadedModels, vectorize_44
from app.detection.lstm_onnx import TemporalLstmOnnxScorer
from app.schemas import AlertRecord, FlowRecord
import time
from datetime import datetime, timezone

# Simple in-memory model metrics (running averages)
_MODEL_METRICS: dict = {
    "isoforest": {"invocations": 0, "avg_latency_ms": 0.0, "last_run": None},
    "xgboost": {"invocations": 0, "avg_latency_ms": 0.0, "last_run": None},
    "lstm_onnx": {"invocations": 0, "avg_latency_ms": 0.0, "last_run": None},
}

def get_model_metrics():
    # Return a shallow copy suitable for JSON encoding
    out = {}
    for k, v in _MODEL_METRICS.items():
        out[k] = {
            "invocations": int(v.get("invocations", 0)),
            "avg_latency_ms": float(v.get("avg_latency_ms", 0.0)),
            "last_run": (v.get("last_run").isoformat() if v.get("last_run") else None),
        }
    return out

logger = logging.getLogger(__name__)


@dataclass
class DetectionSignals:
    isoforest_score: Optional[float] = None
    xgb_label: Optional[str] = None
    xgb_confidence: Optional[float] = None
    lstm_score: Optional[float] = None


class Detector:
    def __init__(self, models: LoadedModels) -> None:
        self._models = models
        self._lstm = None
        if settings.lstm_enabled and models.lstm_onnx_path:
            try:
                self._lstm = TemporalLstmOnnxScorer(models.lstm_onnx_path)
            except Exception:
                logger.exception("lstm_onnx_init_failed")

    def _scale(self, x: np.ndarray) -> np.ndarray:
        if self._models.scaler is None:
            return x
        return self._models.scaler.transform(x.reshape(1, -1)).astype(np.float32)

    def _isoforest(self, x_scaled: np.ndarray) -> Optional[float]:
        if self._models.isoforest is None:
            return None

        start = time.time()
        # sklearn IsolationForest: score_samples higher = less anomalous.
        # Convert to [0,1] anomaly score: 1 - normalized score.
        raw = float(self._models.isoforest.score_samples(x_scaled)[0])
        # heuristic normalization using a clipped logistic to avoid overflow
        raw_c = float(np.clip(raw, -20.0, 20.0))
        score = 1.0 / (1.0 + float(np.exp(raw_c)))
        dur_ms = (time.time() - start) * 1000.0
        m = _MODEL_METRICS.get("isoforest")
        if m is not None:
            m["invocations"] += 1
            # running average
            m["avg_latency_ms"] = ((m["avg_latency_ms"] * (m["invocations"] - 1)) + dur_ms) / m["invocations"]
            m["last_run"] = datetime.now(timezone.utc)
        return float(score)

    def _xgboost(self, x_scaled: np.ndarray) -> tuple[Optional[str], Optional[float]]:
        if self._models.xgb_model is None:
            return None, None

        start = time.time()
        dmat = None
        try:
            import xgboost as xgb

            dmat = xgb.DMatrix(x_scaled)
            proba = self._models.xgb_model.predict(dmat)
            if proba.ndim == 1:
                # binary
                conf = float(proba[0])
                label_idx = int(conf >= 0.5)
                label = str(label_idx)
                return label, conf

            idx = int(np.argmax(proba[0]))
            conf = float(proba[0][idx])
            if self._models.xgb_labels and idx < len(self._models.xgb_labels):
                label = self._models.xgb_labels[idx]
            else:
                label = str(idx)
            return label, conf
        except Exception:
            logger.exception("xgboost_predict_failed")
            return None, None
        finally:
            dur_ms = (time.time() - start) * 1000.0
            m = _MODEL_METRICS.get("xgboost")
            if m is not None:
                m["invocations"] += 1
                m["avg_latency_ms"] = ((m["avg_latency_ms"] * (m["invocations"] - 1)) + dur_ms) / m["invocations"]
                m["last_run"] = datetime.now(timezone.utc)

    def _lstm_score(self, src_ip: str, x_scaled: np.ndarray) -> Optional[float]:
        if not self._lstm:
            return None
        start = time.time()
        res = self._lstm.score(src_ip=src_ip, x_scaled_44=x_scaled.reshape(-1))
        dur_ms = (time.time() - start) * 1000.0
        m = _MODEL_METRICS.get("lstm_onnx")
        if m is not None:
            m["invocations"] += 1
            m["avg_latency_ms"] = ((m["avg_latency_ms"] * (m["invocations"] - 1)) + dur_ms) / m["invocations"]
            m["last_run"] = datetime.now(timezone.utc)
        if not res:
            return None
        return float(res.recon_error)

    def detect(self, flow: FlowRecord) -> Optional[AlertRecord]:
        x = vectorize_44(flow.features)
        x_scaled = self._scale(x)

        sig = DetectionSignals()
        sig.isoforest_score = self._isoforest(x_scaled)
        sig.xgb_label, sig.xgb_confidence = self._xgboost(x)  # Pass raw features to XGBoost
        sig.lstm_score = self._lstm_score(flow.src_ip, x_scaled)

        is_anomaly = False
        label = "benign"
        confidence = 0.5

        # 1. Supervised XGBoost Attack Classification
        if sig.xgb_label is not None and sig.xgb_confidence is not None:
            if sig.xgb_label.lower() not in {"benign", "normal", "0"} and sig.xgb_confidence >= settings.xgboost_confidence_threshold:
                is_anomaly = True
                label = sig.xgb_label
                confidence = sig.xgb_confidence

        # 2. Unsupervised Isolation Forest (Zero-Day Anomaly Detection)
        if sig.isoforest_score is not None and sig.isoforest_score >= settings.isoforest_threshold:
            # Only trigger if XGBoost didn't classify as benign or if score is high zero-day threshold (>= 0.75)
            if not is_anomaly and sig.isoforest_score >= 0.75:
                is_anomaly = True
                label = "Anomaly (Zero-Day)"
                confidence = float(sig.isoforest_score)

        # 3. Temporal LSTM Autoencoder
        if settings.lstm_enabled and sig.lstm_score is not None:
            if sig.lstm_score >= settings.lstm_recon_error_threshold:
                if not is_anomaly:
                    is_anomaly = True
                    label = "Anomaly (Temporal)"
                    confidence = min(0.99, float(sig.lstm_score))

        if not is_anomaly or label.lower() in {"benign", "normal", "0"}:
            return None

        severity = _severity_for_label(label)

        return AlertRecord(
            alert_id=str(uuid4()),
            created_at=datetime.now(timezone.utc),
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            severity=severity,
            label=label,
            confidence=float(confidence),
            signals={
                "isoforest_score": sig.isoforest_score,
                "xgb_label": sig.xgb_label,
                "xgb_confidence": sig.xgb_confidence,
                "lstm_score": sig.lstm_score,
            },
            geoip=None,
        )


def _severity_for_label(label: str) -> str:
    l = (label or "").lower()
    if any(k in l for k in ["ddos", "dos", "botnet", "synflood", "flood"]):
        return "critical"
    if any(k in l for k in ["portscan", "scan", "bruteforce", "ssh"]):
        return "high"
    if any(k in l for k in ["sql", "xss", "ssrf", "injection", "waf", "web"]):
        return "medium"
    return "low"
