from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.db import get_incidents, upsert_incident
from app.schemas import AlertRecord, LayerSecurityEvent, SecurityIncident

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
RANK_TO_SEVERITY = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def _infer_kill_chain_stage(label_or_cat: str, layer: str) -> str:
    l = (label_or_cat or "").lower()
    if any(k in l for k in ["scan", "recon", "probe", "discovery"]):
        return "Reconnaissance"
    if any(k in l for k in ["brute", "patator", "ssh", "ftp", "auth", "credential", "login"]):
        return "Credential Access / Brute Force"
    if any(k in l for k in ["sql", "xss", "traversal", "lfi", "rce", "command_injection", "waf", "web", "exploit", "heartbleed"]):
        return "Application Exploitation"
    if any(k in l for k in ["priv", "sudo", "root", "hostpath", "rbac", "secret", "container", "cron", "file_integrity"]):
        return "Privilege Escalation / Execution"
    if any(k in l for k in ["ddos", "dos", "flood", "hulk", "loit", "slowloris", "goldeneye"]):
        return "Impact / Denial of Service"
    if any(k in l for k in ["botnet", "c2", "ares", "dns", "outbound", "exfil"]):
        return "Command & Control"
    if layer == "kubernetes":
        return "Container / Cluster Activity"
    if layer == "waf":
        return "Application Exploitation"
    if layer == "host":
        return "Host Intrusion Activity"
    return "Network Anomaly"


class ThreatCorrelationEngine:
    """Centralized Threat Intelligence & Multi-Layer Incident Correlation Engine."""

    def __init__(self, correlation_window_minutes: int = 60) -> None:
        self._lock = threading.RLock()
        self._window = timedelta(minutes=correlation_window_minutes)
        self._incidents_by_ip: Dict[str, SecurityIncident] = {}
        self._incidents_by_id: Dict[str, SecurityIncident] = {}

    def initialize(self) -> None:
        try:
            rows = get_incidents(limit=100)
            with self._lock:
                for r in rows:
                    inc = SecurityIncident(
                        incident_id=r["incident_id"],
                        title=r["title"],
                        classification=r["classification"],
                        severity=r["severity"],
                        confidence=r["confidence"],
                        src_ip=r["src_ip"],
                        dst_ip=r["dst_ip"],
                        target_app=r.get("target_app"),
                        target_namespace=r.get("target_namespace"),
                        status=r.get("status", "open"),
                        first_seen=datetime.fromisoformat(r["first_seen"]),
                        last_seen=datetime.fromisoformat(r["last_seen"]),
                        event_count=r.get("event_count", 1),
                        detection_sources=r.get("detection_sources") or [],
                        evidence=r.get("evidence") or [],
                        prevention_action=r.get("prevention_action", "Monitoring"),
                        response_status=r.get("response_status", "Active Monitoring"),
                    )
                    self._incidents_by_id[inc.incident_id] = inc
                    self._incidents_by_ip[inc.src_ip] = inc
        except Exception:
            pass

    def correlate_alert(
        self,
        alert: AlertRecord,
        detection_source: str = "AI Network Detection",
        target_app: Optional[str] = None,
        target_namespace: Optional[str] = None,
    ) -> SecurityIncident:
        now = alert.created_at or datetime.now(timezone.utc)
        stage = _infer_kill_chain_stage(alert.label, detection_source.lower())
        ev_item = {
            "timestamp": now.isoformat(),
            "alert_id": alert.alert_id,
            "source": detection_source,
            "stage": stage,
            "label": alert.label,
            "severity": alert.severity,
            "confidence": round(float(alert.confidence), 3),
            "target": f"{alert.dst_ip}:{alert.dst_port}/{alert.protocol}",
            "signals": alert.signals,
        }
        return self._merge_or_create(
            src_ip=alert.src_ip,
            dst_ip=f"{alert.dst_ip}:{alert.dst_port}",
            label=alert.label,
            severity=alert.severity,
            confidence=float(alert.confidence),
            detection_source=detection_source,
            stage=stage,
            evidence_item=ev_item,
            target_app=target_app or alert.signals.get("target_app"),
            target_namespace=target_namespace or alert.signals.get("namespace"),
            timestamp=now,
        )

    def correlate_layer_event(self, ev: LayerSecurityEvent) -> SecurityIncident:
        now = ev.created_at or datetime.now(timezone.utc)
        source_map = {
            "host": "Linux Host Monitor",
            "kubernetes": "Kubernetes Security Audit",
            "waf": "WAF / Ingress Protection",
            "application": "Application Security Monitor",
            "network": "Network Telemetry",
            "idp": "IDP Responder",
        }
        det_source = source_map.get(ev.layer, ev.layer.capitalize())
        stage = _infer_kill_chain_stage(ev.category, ev.layer)
        ev_item = {
            "timestamp": now.isoformat(),
            "event_id": ev.event_id,
            "source": det_source,
            "stage": stage,
            "label": ev.category,
            "severity": ev.severity,
            "confidence": float(ev.details.get("confidence", 0.85)),
            "target": ev.target,
            "summary": ev.summary,
        }
        return self._merge_or_create(
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
            label=ev.category,
            severity=ev.severity,
            confidence=float(ev.details.get("confidence", 0.85)),
            detection_source=det_source,
            stage=stage,
            evidence_item=ev_item,
            target_app=ev.details.get("target_app") or ev.target,
            target_namespace=ev.namespace,
            timestamp=now,
        )

    def _merge_or_create(
        self,
        src_ip: str,
        dst_ip: str,
        label: str,
        severity: str,
        confidence: float,
        detection_source: str,
        stage: str,
        evidence_item: Dict[str, Any],
        target_app: Optional[str],
        target_namespace: Optional[str],
        timestamp: datetime,
    ) -> SecurityIncident:
        sev_clean = (severity or "medium").lower()
        if sev_clean not in SEVERITY_RANK:
            sev_clean = "medium"

        with self._lock:
            existing = self._incidents_by_ip.get(src_ip)
            if existing and (timestamp - existing.last_seen) <= self._window:
                existing.last_seen = max(existing.last_seen, timestamp)
                existing.event_count += 1
                if detection_source not in existing.detection_sources:
                    existing.detection_sources.append(detection_source)

                existing.evidence.insert(0, evidence_item)
                existing.evidence = existing.evidence[:30]

                if target_app and not existing.target_app:
                    existing.target_app = str(target_app)
                if target_namespace and not existing.target_namespace:
                    existing.target_namespace = str(target_namespace)

                # Multi-layer correlation escalation!
                stages = list({e.get("stage", stage) for e in existing.evidence})
                cur_rank = max(SEVERITY_RANK.get(existing.severity, 2), SEVERITY_RANK.get(sev_clean, 2))
                if len(existing.detection_sources) >= 2 or len(stages) >= 2:
                    # Escalate severity and confidence when attack spans multiple layers/stages
                    cur_rank = min(4, cur_rank + 1)
                    existing.confidence = min(0.99, max(existing.confidence, confidence) + 0.06)
                    existing.classification = f"Multi-Stage Attack ({' -> '.join(stages[:3])})"
                    existing.title = f"Correlated Multi-Layer Intrusion from {src_ip} ({len(existing.detection_sources)} layers)"
                else:
                    existing.confidence = round(max(existing.confidence, confidence), 3)
                    existing.classification = label
                    existing.title = f"{label} activity from {src_ip} ({existing.event_count} events)"

                existing.severity = RANK_TO_SEVERITY[cur_rank]
                inc = existing
            else:
                inc_id = f"INC-{str(uuid4())[:8].upper()}"
                inc = SecurityIncident(
                    incident_id=inc_id,
                    title=f"{label} detected from {src_ip}",
                    classification=label,
                    severity=sev_clean,
                    confidence=round(confidence, 3),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    target_app=str(target_app) if target_app else None,
                    target_namespace=str(target_namespace) if target_namespace else "default",
                    status="open",
                    first_seen=timestamp,
                    last_seen=timestamp,
                    event_count=1,
                    detection_sources=[detection_source],
                    evidence=[evidence_item],
                    prevention_action="Evaluated by IDP",
                    response_status="Active Monitoring",
                )
                self._incidents_by_ip[src_ip] = inc
                self._incidents_by_id[inc.incident_id] = inc

        try:
            upsert_incident(inc)
        except Exception:
            pass
        return inc

    def record_prevention_action(self, incident_id: str, action: str, response_status: str = "Blocked & Contained") -> None:
        with self._lock:
            inc = self._incidents_by_id.get(incident_id)
            if not inc:
                return
            inc.prevention_action = action
            inc.response_status = response_status
            if "blocked" in response_status.lower() or "contained" in response_status.lower():
                inc.status = "contained"
        try:
            upsert_incident(inc)
        except Exception:
            pass

    def clear_all(self) -> None:
        with self._lock:
            self._incidents_by_ip.clear()
            self._incidents_by_id.clear()

    def list_incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        try:
            db_items = get_incidents(limit=limit)
            if db_items:
                return db_items
        except Exception:
            pass
        with self._lock:
            items = sorted(self._incidents_by_id.values(), key=lambda x: x.last_seen, reverse=True)[:limit]
            return [i.model_dump(mode="json") for i in items]
