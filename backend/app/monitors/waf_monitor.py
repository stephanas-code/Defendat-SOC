from __future__ import annotations

import logging
import os
import re
import threading
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import uuid4

from app.config import settings
from app.db import insert_security_event, record_app_threat
from app.schemas import AlertRecord, HttpInspectRequest, LayerSecurityEvent

logger = logging.getLogger(__name__)

# OWASP Core Rule Set (CRS) Equivalent Application-Layer Signatures (Post-TLS Termination)
WAF_RULES: List[Tuple[str, str, str, float, re.Pattern]] = [
    (
        "CRS-942100",
        "Web_SQL_Injection",
        "critical",
        0.96,
        re.compile(
            r"(?:union\s+(?:all\s+)?select|select\s+.*\s+from\s+information_schema|"
            r"(?:'|\"|%27)\s*(?:or|and)\s*(?:'|\"|\d)+.*(?:=|like)|"
            r";\s*(?:drop|alter|truncate)\s+table|(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+|"
            r"waitfor\s+delay\s+'|extractvalue\s*\(|updatexml\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "CRS-941100",
        "Web_XSS",
        "high",
        0.94,
        re.compile(
            r"(?:<\s*script\b|javascript\s*:|on(?:error|load|mouseover|focus|click)\s*=|"
            r"document\.(?:cookie|domain|write)|<\s*(?:img|svg|iframe|body|embed|object)\b[^>]*\bon\w+\s*=|"
            r"alert\s*\(\s*(?:1|document|window|'))",
            re.IGNORECASE,
        ),
    ),
    (
        "CRS-932100",
        "Web_Command_Injection",
        "critical",
        0.97,
        re.compile(
            r"(?:(?:;|\|\||&&|\||`|\$\()\s*(?:cat|whoami|id|uname|ls|pwd|nc|netcat|bash|sh|curl|wget|python|perl|chmod)\b|"
            r"/bin/(?:bash|sh|zsh)|cmd\.exe\s*/c)",
            re.IGNORECASE,
        ),
    ),
    (
        "CRS-930100",
        "Web_Path_Traversal",
        "high",
        0.95,
        re.compile(
            r"(?:(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f){2,}|"
            r"/etc/(?:passwd|shadow|group|hosts|sudoers)|/proc/self/(?:environ|cmdline)|"
            r"c:\\windows\\(?:win\.ini|system32))",
            re.IGNORECASE,
        ),
    ),
    (
        "CRS-944100",
        "Web_Exploit_Attempt",
        "critical",
        0.96,
        re.compile(
            r"(?:\$\{jndi:(?:ldap|rmi|dns|ldaps|iiop)://|<!ENTITY\s+\w+\s+SYSTEM|"
            r"php://(?:filter|input|expect)|/\.(?:env|git/config|aws/credentials)|"
            r"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin\.php)",
            re.IGNORECASE,
        ),
    ),
]

SCANNER_UA_RE = re.compile(
    r"\b(?:sqlmap|nikto|nuclei|nmap|masscan|gobuster|dirbuster|dirb|ffuf|wfuzz|wpscan|acunetix|nessus|openvas|zgrab|hydra|medusa|burpsuite)\b",
    re.IGNORECASE,
)

AUTH_ENDPOINTS_RE = re.compile(
    r"(?:/login|/signin|/auth|/oauth|/api/v\d+/auth|/api/login|/token|/wp-login\.php|/admin/login)",
    re.IGNORECASE,
)

NGINX_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+[^"]+"\s+(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)


class WafMonitor:
    """Application & Website Protection Engine (WAF + Ingress Log & Webhook Inspector)."""

    def __init__(self, on_alert: Callable[[AlertRecord, str], None]) -> None:
        self._on_alert = on_alert
        self._stop = threading.Event()
        self._lock = threading.RLock()

        self._log_offsets: Dict[str, int] = {}
        self._auth_attempts: Dict[str, List[float]] = defaultdict(list)
        self._req_rates: Dict[str, List[float]] = defaultdict(list)

        self._stats: Dict[str, Any] = {
            "enabled": settings.waf_enabled,
            "mode": "OWASP_CRS_ACTIVE_PROTECTION",
            "total_inspected": 0,
            "http_attacks_detected": 0,
            "sqli_count": 0,
            "xss_count": 0,
            "path_traversal_count": 0,
            "command_injection_count": 0,
            "brute_force_count": 0,
            "bot_scanner_count": 0,
            "rate_limited_count": 0,
            "blocked_requests_count": 0,
            "recent_detections": [],
        }

    def start(self) -> None:
        if not settings.waf_enabled and not settings.application_monitoring_enabled:
            logger.info("waf_monitoring_disabled")
            return
        threading.Thread(target=self._run_loop, daemon=True, name="waf-monitor").start()

    def stop(self) -> None:
        self._stop.set()

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tail_waf_logs()
            except Exception:
                logger.exception("waf_log_tail_error")
            time.sleep(5)

    def _tail_waf_logs(self) -> None:
        paths = [p.strip() for p in settings.waf_log_paths.split(",") if p.strip()]
        for p in paths:
            if not os.path.exists(p) or not os.path.isfile(p):
                continue
            try:
                size = os.path.getsize(p)
                offset = self._log_offsets.get(p, max(0, size - 32768))
                if size < offset:
                    offset = 0
                if size == offset:
                    continue
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(offset)
                    lines = f.readlines()
                    self._log_offsets[p] = f.tell()
                for line in lines[-200:]:
                    m = NGINX_COMBINED_RE.match(line.strip())
                    if m:
                        req = HttpInspectRequest(
                            src_ip=m.group("ip"),
                            host="ingress-gateway",
                            method=m.group("method"),
                            uri=m.group("uri"),
                            user_agent=m.group("ua"),
                            status_code=int(m.group("status")),
                        )
                        self.inspect_http_request(req)
            except Exception:
                pass

    def inspect_http_request(self, req: HttpInspectRequest) -> Dict[str, Any]:
        """Inspect an HTTP/API request (post-TLS termination at Ingress/WAF) and enforce WAF rules."""
        now = datetime.now(timezone.utc)
        now_ts = time.time()

        with self._lock:
            self._stats["total_inspected"] += 1

        decoded_uri = urllib.parse.unquote_plus(req.uri or "/")
        decoded_body = urllib.parse.unquote_plus(req.body_snippet or "")
        headers_str = " ".join(f"{k}: {v}" for k, v in (req.headers or {}).items())
        inspection_blob = f"{decoded_uri} {decoded_body} {headers_str}"

        matched_rule_id: Optional[str] = None
        matched_category: Optional[str] = None
        matched_severity: str = "medium"
        matched_conf: float = 0.85

        # 1. Check OWASP CRS Payload Signatures (SQLi, XSS, LFI/Path Traversal, Command Injection, Exploits)
        for rule_id, category, sev, conf, regex in WAF_RULES:
            if regex.search(inspection_blob):
                matched_rule_id = rule_id
                matched_category = category
                matched_severity = sev
                matched_conf = conf
                break

        # 2. Check Malicious Bot / Vulnerability Scanner User-Agent
        if not matched_category and SCANNER_UA_RE.search(req.user_agent or ""):
            matched_rule_id = "CRS-913100"
            matched_category = "Malicious_Bot_Scanner"
            matched_severity = "high"
            matched_conf = 0.92

        # 3. Check HTTP Protocol Anomalies (Null byte, dangerous methods)
        if not matched_category:
            if "%00" in (req.uri or "") or "\x00" in decoded_uri or req.method.upper() in ("TRACE", "TRACK", "CONNECT"):
                matched_rule_id = "CRS-920100"
                matched_category = "HTTP_Protocol_Anomaly"
                matched_severity = "medium"
                matched_conf = 0.88

        # 4. Check Authentication Brute Force / Credential Stuffing on auth endpoints
        if not matched_category and AUTH_ENDPOINTS_RE.search(decoded_uri):
            if req.status_code in (401, 403) or req.method.upper() == "POST":
                with self._lock:
                    attempts = [t for t in self._auth_attempts[req.src_ip] if now_ts - t <= 120.0]
                    attempts.append(now_ts)
                    self._auth_attempts[req.src_ip] = attempts
                    auth_cnt = len(attempts)
                if auth_cnt >= 4:
                    matched_rule_id = "WAF-AUTH-BRUTE"
                    matched_category = "Web_Brute_Force"
                    matched_severity = "high"
                    matched_conf = min(0.97, 0.80 + auth_cnt * 0.03)

        # 5. Check Abnormal HTTP Request Rate / API Flooding
        with self._lock:
            reqs = [t for t in self._req_rates[req.src_ip] if now_ts - t <= 10.0]
            reqs.append(now_ts)
            self._req_rates[req.src_ip] = reqs
            rps = len(reqs) / 10.0

        if not matched_category and rps * 10 >= settings.idp_rate_limit_rps:
            matched_rule_id = "WAF-RATE-LIMIT"
            matched_category = "HTTP_Request_Flood"
            matched_severity = "high"
            matched_conf = 0.91

        if not matched_category:
            return {"allowed": True, "action": "pass", "rule_id": None}

        # Update WAF counters
        action = "blocked" if settings.waf_enabled and matched_severity in ("critical", "high") else "rate_limited"
        target_app = req.target_app or req.host or "ingress-nginx-gateway"

        with self._lock:
            self._stats["http_attacks_detected"] += 1
            if "SQL" in matched_category:
                self._stats["sqli_count"] += 1
            elif "XSS" in matched_category:
                self._stats["xss_count"] += 1
            elif "Traversal" in matched_category:
                self._stats["path_traversal_count"] += 1
            elif "Command" in matched_category:
                self._stats["command_injection_count"] += 1
            elif "Brute" in matched_category:
                self._stats["brute_force_count"] += 1
            elif "Scanner" in matched_category:
                self._stats["bot_scanner_count"] += 1

            if action == "blocked":
                self._stats["blocked_requests_count"] += 1
            else:
                self._stats["rate_limited_count"] += 1

            det_record = {
                "detection_id": f"WAF-{str(uuid4())[:8].upper()}",
                "timestamp": now.isoformat(),
                "rule_id": matched_rule_id,
                "category": matched_category,
                "severity": matched_severity,
                "confidence": matched_conf,
                "src_ip": req.src_ip,
                "host": req.host,
                "target_app": target_app,
                "namespace": req.namespace or "default",
                "method": req.method,
                "uri": req.uri[:200],
                "user_agent": (req.user_agent or "")[:120],
                "action": action,
            }
            self._stats["recent_detections"].insert(0, det_record)
            self._stats["recent_detections"] = self._stats["recent_detections"][:100]

        # Attribute threat to discovered application
        try:
            record_app_threat(target_app, det_record)
            record_app_threat(80, det_record)
        except Exception:
            pass

        summary = f"WAF [{matched_rule_id}] {action.upper()} {matched_category} from {req.src_ip} on {req.method} {req.host}{req.uri[:80]}"
        ev = LayerSecurityEvent(
            event_id=str(uuid4()),
            created_at=now,
            layer="waf",
            category=matched_category,
            severity=matched_severity,
            src_ip=req.src_ip,
            dst_ip=req.dst_ip,
            target=target_app,
            namespace=req.namespace or "default",
            summary=summary,
            details=det_record,
        )
        try:
            insert_security_event(ev)
        except Exception:
            pass

        if self._on_alert:
            alert = AlertRecord(
                alert_id=str(uuid4()),
                created_at=now,
                flow_id=f"waf-{det_record['detection_id']}",
                src_ip=req.src_ip,
                dst_ip=req.dst_ip,
                src_port=0,
                dst_port=443 if "443" in req.host else 80,
                protocol="HTTP",
                severity=matched_severity,
                label=matched_category,
                confidence=matched_conf,
                signals={
                    "layer": "waf",
                    "rule_id": matched_rule_id,
                    "method": req.method,
                    "uri": req.uri[:200],
                    "user_agent": (req.user_agent or "")[:120],
                    "target_app": target_app,
                    "namespace": req.namespace or "default",
                    "waf_action": action,
                },
                geoip=None,
            )
            try:
                self._on_alert(alert, "WAF / Ingress Protection")
            except Exception:
                logger.exception("waf_alert_callback_failed")

        return {
            "allowed": action != "blocked",
            "action": action,
            "rule_id": matched_rule_id,
            "category": matched_category,
            "severity": matched_severity,
            "confidence": matched_conf,
            "detection": det_record,
        }

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)
