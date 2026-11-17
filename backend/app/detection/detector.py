from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

import numpy as np

from app.config import settings
from app.detection.lstm_onnx import TemporalLstmOnnxScorer
from app.detection.models import LoadedModels, vectorize_44
from app.schemas import AlertRecord, FlowRecord

# Simple in-memory model metrics (running averages)
_MODEL_METRICS: dict = {
    "isoforest": {"invocations": 0, "avg_latency_ms": 0.0, "last_run": None},
    "xgboost": {"invocations": 0, "avg_latency_ms": 0.0, "last_run": None},
    "lstm_onnx": {"invocations": 0, "avg_latency_ms": 0.0, "last_run": None},
}


def get_model_metrics() -> Dict[str, Any]:
    out = {}
    for k, v in _MODEL_METRICS.items():
        out[k] = {
            "invocations": int(v.get("invocations", 0)),
            "avg_latency_ms": round(float(v.get("avg_latency_ms", 0.0)), 3),
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
            return x.reshape(1, -1).astype(np.float32)
        return self._models.scaler.transform(x.reshape(1, -1)).astype(np.float32)

    def _isoforest(self, x_scaled: np.ndarray) -> Optional[float]:
        if self._models.isoforest is None:
            return None

        start = time.time()
        raw = float(self._models.isoforest.score_samples(x_scaled)[0])
        raw_c = float(np.clip(raw, -20.0, 20.0))
        score = 1.0 / (1.0 + float(np.exp(raw_c)))
        dur_ms = (time.time() - start) * 1000.0
        m = _MODEL_METRICS.get("isoforest")
        if m is not None:
            m["invocations"] += 1
            m["avg_latency_ms"] = ((m["avg_latency_ms"] * (m["invocations"] - 1)) + dur_ms) / m["invocations"]
            m["last_run"] = datetime.now(timezone.utc)
        return float(score)

    def _xgboost(self, x_raw: np.ndarray) -> tuple[Optional[str], Optional[float]]:
        if self._models.xgb_model is None:
            return None, None

        start = time.time()
        try:
            import xgboost as xgb

            dmat = xgb.DMatrix(x_raw.reshape(1, -1))
            proba = self._models.xgb_model.predict(dmat)
            if proba.ndim == 1:
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
        if not settings.ids_enabled:
            return None

        x = vectorize_44(flow.features)
        x_scaled = self._scale(x)

        sig = DetectionSignals()
        sig.isoforest_score = self._isoforest(x_scaled)
        sig.xgb_label, sig.xgb_confidence = self._xgboost(x)
        sig.lstm_score = self._lstm_score(flow.src_ip, x_scaled)

        is_anomaly = False
        label = "benign"
        confidence = 0.5

        # 1. Supervised XGBoost Attack Classification
        if sig.xgb_label is not None and sig.xgb_confidence is not None:
            if sig.xgb_label.lower() not in {"benign", "normal", "0"} and sig.xgb_confidence >= settings.xgboost_confidence_threshold:
                is_anomaly = True
                label = sig.xgb_label
                confidence = float(sig.xgb_confidence)
                # Multi-model consensus boost if IsolationForest also detects anomaly
                if sig.isoforest_score is not None and sig.isoforest_score >= settings.isoforest_threshold:
                    confidence = min(0.99, confidence + 0.04)

        xgb_is_explicitly_benign = (
            sig.xgb_label is not None
            and sig.xgb_label.lower() in {"benign", "normal", "0"}
            and (sig.xgb_confidence or 0.0) >= 0.70
        )

        # 2. Unsupervised Isolation Forest (Zero-Day Anomaly Detection)
        if sig.isoforest_score is not None and sig.isoforest_score >= settings.isoforest_threshold:
            min_score = 0.88 if xgb_is_explicitly_benign else max(0.72, settings.isoforest_threshold)
            if not is_anomaly and sig.isoforest_score >= min_score:
                is_anomaly = True
                label = "Anomaly (Zero-Day)"
                confidence = float(sig.isoforest_score)

        # 3. Temporal LSTM Autoencoder
        if settings.lstm_enabled and sig.lstm_score is not None:
            if sig.lstm_score >= settings.lstm_recon_error_threshold:
                if not is_anomaly:
                    is_anomaly = True
                    label = "Anomaly (Temporal)"
                    confidence = min(0.99, max(0.75, float(sig.lstm_score)))

        # 4. Flow-level Heuristic Safety Net (SYN flood / high packet rate / port scan signatures)
        if not is_anomaly:
            syn_cnt = float(flow.features.get("syn_flag_cnt", 0.0))
            pkts_s = float(flow.features.get("flow_pkts_s", 0.0))
            bwd_pkts = float(flow.features.get("tot_bwd_pkts", 0.0))
            if syn_cnt >= 50 and pkts_s >= 500:
                is_anomaly = True
                label = "DDoS_SYN_Flood"
                confidence = 0.92
            elif syn_cnt >= 15 and bwd_pkts == 0 and pkts_s >= 100:
                is_anomaly = True
                label = "Port_Scan"
                confidence = 0.86

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
            confidence=round(float(confidence), 4),
            signals={
                "layer": "network",
                "isoforest_score": round(float(sig.isoforest_score), 4) if sig.isoforest_score is not None else None,
                "xgb_label": sig.xgb_label,
                "xgb_confidence": round(float(sig.xgb_confidence), 4) if sig.xgb_confidence is not None else None,
                "lstm_score": round(float(sig.lstm_score), 4) if sig.lstm_score is not None else None,
            },
            geoip=None,
        )


def _severity_for_label(label: str) -> str:
    l = (label or "").lower()
    if any(k in l for k in ["ddos", "dos", "botnet", "synflood", "flood", "heartbleed", "hulk", "loit", "goldeneye", "ares", "command_injection", "sql"]):
        return "critical"
    if any(k in l for k in ["portscan", "port_scan", "scan", "bruteforce", "brute", "patator", "ssh", "ftp", "xss", "traversal", "zero-day"]):
        return "high"
    if any(k in l for k in ["ssrf", "injection", "waf", "web", "temporal", "anomaly"]):
        return "medium"
    return "low"
