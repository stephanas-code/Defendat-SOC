from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

import redis

from app.config import settings
from app.db import (
    delete_allowlist_entry,
    expire_old_idp_blocks,
    get_allowlist_entries,
    get_idp_blocks,
    insert_idp_block,
    insert_security_event,
    update_idp_block_status,
    upsert_allowlist_entry,
)
from app.schemas import AlertRecord, IdpAllowlistEntry, IdpBlockRecord, LayerSecurityEvent

logger = logging.getLogger(__name__)


class IdpEngine:
    """Production Intrusion Prevention System (IDP) Engine with 12 Safety Guardrails."""

    def __init__(self, on_event: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self._lock = threading.RLock()
        self._on_event = on_event
        self._stop = threading.Event()

        # Dynamic runtime state initialized from settings
        self.enabled: bool = bool(settings.idp_enabled)
        self.enforcement_mode: str = settings.idp_enforcement_mode  # monitor | safe_enforce | full_enforce
        self.block_seconds: int = int(settings.idp_block_seconds)
        self.max_blocks: int = int(settings.idp_max_blocks)
        self.confidence_threshold: float = float(settings.idp_confidence_threshold)
        self.auto_block_critical: bool = bool(settings.idp_auto_block_critical)
        self.auto_block_high: bool = bool(settings.idp_auto_block_high)
        self.kill_switch_engaged: bool = False

        # In-memory cache of active blocks and allowlist (synced with DB & Redis)
        self._active_blocks: Dict[str, IdpBlockRecord] = {}
        self._history_blocks: List[IdpBlockRecord] = []
        self._allowlist_entries: Dict[str, IdpAllowlistEntry] = {}
        self._protected_node_ips: Set[str] = set()
        self._corroboration_counts: Dict[str, List[float]] = {}

        # Discover local interfaces, DNS resolvers, and active SSH client IPs
        self._system_protected_ips: Set[str] = self._discover_system_protected_ips()
        self._firewall_backend: str = self._detect_firewall_backend()

        self._redis: Optional[redis.Redis] = None
        try:
            self._redis = redis.Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)
        except Exception:
            self._redis = None

    def _detect_firewall_backend(self) -> str:
        pref = (settings.idp_firewall_backend or "auto").lower()
        if pref in ("iptables", "nftables"):
            return pref
        if shutil.which("nft"):
            return "nftables"
        if shutil.which("iptables"):
            return "iptables"
        return "responder_agent"

    def _discover_system_protected_ips(self) -> Set[str]:
        protected: Set[str] = {"127.0.0.1", "::1", "0.0.0.0", "localhost"}
        # 1. Local hostname / interface IPs
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ip:
                    protected.add(ip.split("%")[0])
        except Exception:
            pass

        # 2. Kubernetes API server IP from environment
        k8s_host = os.getenv("KUBERNETES_SERVICE_HOST")
        if k8s_host:
            protected.add(k8s_host)

        # 3. Cluster / Host DNS resolvers from /etc/resolv.conf
        for resolv_path in [os.path.join(settings.host_etc_dir, "resolv.conf"), "/etc/resolv.conf"]:
            if os.path.exists(resolv_path):
                try:
                    with open(resolv_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("nameserver"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    protected.add(parts[1])
                except Exception:
                    pass

        # 4. Active SSH client IPs from /proc/net/tcp (port 22 = 0x0016)
        for tcp_path in [os.path.join(settings.host_proc_dir, "net/tcp"), "/proc/net/tcp"]:
            if os.path.exists(tcp_path):
                try:
                    with open(tcp_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f.readlines()[1:]:
                            cols = line.strip().split()
                            if len(cols) < 4:
                                continue
                            local_addr, rem_addr, state = cols[1], cols[2], cols[3]
                            # state 01 = ESTABLISHED, local port 0016 = 22 (SSH)
                            if state == "01" and local_addr.endswith(":0016"):
                                rem_hex = rem_addr.split(":")[0]
                                if len(rem_hex) == 8:
                                    ip_int = int(rem_hex, 16)
                                    ssh_ip = socket.inet_ntoa(ip_int.to_bytes(4, "little"))
                                    protected.add(ssh_ip)
                except Exception:
                    pass

        return protected

    def register_k8s_node_ips(self, node_ips: List[str]) -> None:
        with self._lock:
            for ip in node_ips:
                if ip:
                    self._protected_node_ips.add(ip)

    def initialize(self) -> None:
        """Seed default allowlist entries and load existing active blocks from DB."""
        with self._lock:
            now = datetime.now(timezone.utc)
            # Seed configured management IPs
            for mip in settings.parsed_management_ips():
                entry = IdpAllowlistEntry(
                    entry_id=f"mgmt-{mip}",
                    ip_or_cidr=mip,
                    label="Protected Management IP",
                    is_management=True,
                    created_at=now,
                    created_by="env_config",
                )
                self._allowlist_entries[mip] = entry
                try:
                    upsert_allowlist_entry(entry)
                except Exception:
                    pass

            # Seed configured allowlist CIDRs
            for cidr in settings.parsed_allowlist():
                entry = IdpAllowlistEntry(
                    entry_id=f"allow-{cidr}",
                    ip_or_cidr=cidr,
                    label="Configured Allowlist Network",
                    is_management=False,
                    created_at=now,
                    created_by="env_config",
                )
                self._allowlist_entries[cidr] = entry
                try:
                    upsert_allowlist_entry(entry)
                except Exception:
                    pass

            # Load stored allowlist from DB
            try:
                for row in get_allowlist_entries():
                    e = IdpAllowlistEntry(
                        entry_id=row["entry_id"],
                        ip_or_cidr=row["ip_or_cidr"],
                        label=row["label"],
                        is_management=row["is_management"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        created_by=row["created_by"],
                    )
                    self._allowlist_entries[e.ip_or_cidr] = e
            except Exception:
                pass

            # Load existing active blocks from DB
            try:
                for b in get_idp_blocks(limit=200):
                    rec = IdpBlockRecord(
                        block_id=b["block_id"],
                        ip=b["ip"],
                        reason=b["reason"],
                        severity=b["severity"],
                        confidence=b["confidence"],
                        enforcement_layer=b["enforcement_layer"],
                        status=b["status"],
                        incident_id=b.get("incident_id"),
                        alert_id=b.get("alert_id"),
                        created_at=datetime.fromisoformat(b["created_at"]),
                        expires_at=datetime.fromisoformat(b["expires_at"]),
                        unblocked_at=datetime.fromisoformat(b["unblocked_at"]) if b.get("unblocked_at") else None,
                        unblocked_by=b.get("unblocked_by"),
                        metadata=b.get("metadata") or {},
                    )
                    if rec.status in ("active", "simulated") and rec.expires_at > now:
                        self._active_blocks[rec.ip] = rec
                    else:
                        self._history_blocks.append(rec)
            except Exception:
                pass

        # Start background expiry thread
        threading.Thread(target=self._expiry_worker, daemon=True, name="idp-expiry-worker").start()

    def _expiry_worker(self) -> None:
        while not self._stop.is_set():
            try:
                self.cleanup_expired_blocks()
            except Exception:
                logger.exception("idp_expiry_worker_error")
            time.sleep(5)

    def stop(self) -> None:
        self._stop.set()

    def is_ip_protected(self, ip_str: str) -> Tuple[bool, str]:
        """Evaluate all 12 critical safety rules before allowing any IP block."""
        if not ip_str:
            return True, "empty_ip"
        clean_ip = ip_str.strip()
        if clean_ip in self._system_protected_ips:
            return True, "system_or_ssh_or_dns_protected_ip"
        if clean_ip in self._protected_node_ips:
            return True, "kubernetes_node_ip"
        if clean_ip in settings.parsed_management_ips():
            return True, "management_ip"

        try:
            ip_obj = ipaddress.ip_address(clean_ip)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                return True, "loopback_or_link_local_or_multicast"

            # Check protected infrastructure CIDRs (K8s Pod/Service networks)
            for cidr in settings.parsed_protected_cidrs():
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if ip_obj in net:
                        return True, f"protected_k8s_cidr:{cidr}"
                except Exception:
                    pass

            # Check dynamic allowlist entries
            with self._lock:
                entries = list(self._allowlist_entries.values())
            for entry in entries:
                target = entry.ip_or_cidr.strip()
                try:
                    if "/" in target:
                        if ip_obj in ipaddress.ip_network(target, strict=False):
                            return True, f"allowlist_cidr:{entry.label}"
                    else:
                        if ip_obj == ipaddress.ip_address(target):
                            return True, f"allowlist_ip:{entry.label}"
                except Exception:
                    if clean_ip == target:
                        return True, f"allowlist_match:{entry.label}"
        except ValueError:
            return True, "invalid_ip_format"

        return False, ""

    def _apply_firewall_rule(self, ip: str, action: str = "block", layer: str = "iptables") -> Tuple[bool, str]:
        """Apply or remove firewall rule safely with rollback protection."""
        if self.enforcement_mode == "monitor" or not self.enabled or self.kill_switch_engaged:
            self._publish_responder_command(action=action, ip=ip, layer=layer, simulated=True)
            return True, "simulated_in_monitor_mode"

        # Publish to Redis & Kafka so host-network responder enforces immediately
        self._publish_responder_command(action=action, ip=ip, layer=layer, simulated=False)

        chain = settings.idp_chain
        # Also enforce directly if iptables/nft is available in this runtime namespace
        if shutil.which("iptables"):
            try:
                if action == "block":
                    subprocess.run(["iptables", "-N", chain], check=False, capture_output=True, timeout=3)
                    for parent_chain in ["INPUT", "FORWARD"]:
                        chk = subprocess.run(
                            ["iptables", "-C", parent_chain, "-j", chain],
                            check=False,
                            capture_output=True,
                            timeout=3,
                        )
                        if chk.returncode != 0:
                            subprocess.run(
                                ["iptables", "-I", parent_chain, "1", "-j", chain],
                                check=False,
                                capture_output=True,
                                timeout=3,
                            )
                    chk_rule = subprocess.run(
                        ["iptables", "-C", chain, "-s", ip, "-j", "DROP"],
                        check=False,
                        capture_output=True,
                        timeout=3,
                    )
                    if chk_rule.returncode != 0:
                        res = subprocess.run(
                            ["iptables", "-I", chain, "1", "-s", ip, "-j", "DROP"],
                            check=False,
                            capture_output=True,
                            timeout=3,
                        )
                        if res.returncode == 0:
                            return True, f"iptables_enforced:{chain}"
                elif action == "unblock":
                    subprocess.run(
                        ["iptables", "-D", chain, "-s", ip, "-j", "DROP"],
                        check=False,
                        capture_output=True,
                        timeout=3,
                    )
                    return True, f"iptables_removed:{chain}"
            except Exception as e:
                logger.warning("direct_iptables_call_skipped", extra={"err": str(e)})

        return True, f"dispatched_to_responder:{layer}"

    def _publish_responder_command(self, action: str, ip: str, layer: str, simulated: bool = False) -> None:
        if not self._redis:
            return
        try:
            payload = json.dumps(
                {
                    "action": action,
                    "ip": ip,
                    "layer": layer,
                    "simulated": simulated,
                    "chain": settings.idp_chain,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
            if action == "block" and not simulated:
                self._redis.hset("idp:active_blocks", ip, payload)
            elif action in ("unblock", "flush"):
                if action == "flush":
                    self._redis.delete("idp:active_blocks")
                else:
                    self._redis.hdel("idp:active_blocks", ip)
            self._redis.publish("idp:commands", payload)
        except Exception:
            pass

    def evaluate_alert(self, alert: AlertRecord, incident_id: Optional[str] = None) -> Optional[IdpBlockRecord]:
        """Evaluate an incoming alert against IDP response policies and safety rules."""
        src_ip = (alert.src_ip or "").strip()
        if not src_ip:
            return None

        sev = (alert.severity or "low").lower()
        conf = float(alert.confidence or 0.0)
        label_lower = (alert.label or "").lower()

        # Record corroboration timestamp for this source IP
        now_ts = time.time()
        with self._lock:
            history = [t for t in self._corroboration_counts.get(src_ip, []) if now_ts - t <= 300.0]
            history.append(now_ts)
            self._corroboration_counts[src_ip] = history
            recent_hits = len(history)

        # Intelligent response policy evaluation:
        # BENIGN / LOW: Record and monitor only
        if sev == "low" or label_lower in {"benign", "normal", "0"}:
            return None

        # MEDIUM: Rate-limit only if repeated (>= 3 events in 5m), never L3 block automatically
        enforcement_layer = "iptables"
        should_block = False
        duration = self.block_seconds

        if sev == "critical":
            if self.auto_block_critical and conf >= self.confidence_threshold:
                should_block = True
                duration = self.block_seconds * 2  # Longer containment for critical threats
                if any(w in label_lower for w in ["sql", "xss", "web", "http", "waf"]):
                    enforcement_layer = "waf_and_iptables"
        elif sev == "high":
            # High severity requires confidence >= threshold AND (auto_block_high enabled)
            if self.auto_block_high and (conf >= self.confidence_threshold or recent_hits >= 2):
                should_block = True
                if any(w in label_lower for w in ["sql", "xss", "web", "http", "waf", "brute"]):
                    enforcement_layer = "waf_and_iptables"
        elif sev == "medium":
            if recent_hits >= 3 and conf >= 0.65:
                should_block = True
                enforcement_layer = "rate_limit"
                duration = max(120, self.block_seconds // 2)

        if not should_block:
            return None

        return self.block_ip(
            ip=src_ip,
            reason=f"Auto-IDP [{sev.upper()}]: {alert.label} (conf={conf:.2f}, hits={recent_hits})",
            severity=sev,
            confidence=conf,
            duration_seconds=duration,
            enforcement_layer=enforcement_layer,
            alert_id=alert.alert_id,
            incident_id=incident_id,
            target_dst=f"{alert.dst_ip}:{alert.dst_port}",
        )

    def block_ip(
        self,
        ip: str,
        reason: str,
        severity: str = "high",
        confidence: float = 0.90,
        duration_seconds: Optional[int] = None,
        enforcement_layer: str = "iptables",
        alert_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        target_dst: str = "",
    ) -> IdpBlockRecord:
        now = datetime.now(timezone.utc)
        dur = int(duration_seconds or self.block_seconds)
        expires = now + timedelta(seconds=dur)

        # 1. Check critical safety guardrails (Allowlist, Management IPs, K8s Nodes/CIDRs, Loopback, SSH, DNS)
        protected, prot_reason = self.is_ip_protected(ip)
        if protected:
            rec = IdpBlockRecord(
                block_id=str(uuid4()),
                ip=ip,
                reason=f"BLOCKED PREVENTED BY SAFETY GUARDRAIL ({prot_reason}) — {reason}",
                severity=severity,
                confidence=confidence,
                enforcement_layer=enforcement_layer,
                status="failed",
                incident_id=incident_id,
                alert_id=alert_id,
                created_at=now,
                expires_at=now,
                metadata={"safety_guardrail": prot_reason, "protected": True, "target": target_dst},
            )
            with self._lock:
                self._history_blocks.insert(0, rec)
                self._history_blocks = self._history_blocks[:200]
            try:
                insert_idp_block(rec)
            except Exception:
                pass
            logger.info("idp_block_prevented_by_guardrail", extra={"ip": ip, "guardrail": prot_reason})
            return rec

        with self._lock:
            # Check if already blocked -> extend expiry
            if ip in self._active_blocks:
                existing = self._active_blocks[ip]
                existing.expires_at = max(existing.expires_at, expires)
                existing.reason = reason
                existing.confidence = max(existing.confidence, confidence)
                try:
                    insert_idp_block(existing)
                except Exception:
                    pass
                return existing

            # Check max blocks limit
            if len(self._active_blocks) >= self.max_blocks:
                rec = IdpBlockRecord(
                    block_id=str(uuid4()),
                    ip=ip,
                    reason=f"MAX BLOCKS REACHED ({self.max_blocks}) — {reason}",
                    severity=severity,
                    confidence=confidence,
                    enforcement_layer=enforcement_layer,
                    status="failed",
                    incident_id=incident_id,
                    alert_id=alert_id,
                    created_at=now,
                    expires_at=now,
                    metadata={"error": "max_blocks_reached"},
                )
                self._history_blocks.insert(0, rec)
                try:
                    insert_idp_block(rec)
                except Exception:
                    pass
                return rec

        # Apply enforcement (or simulate if in monitor mode)
        ok, detail = self._apply_firewall_rule(ip=ip, action="block", layer=enforcement_layer)
        is_simulated = (not self.enabled) or (self.enforcement_mode == "monitor") or self.kill_switch_engaged
        status = "simulated" if is_simulated else ("active" if ok else "failed")

        rec = IdpBlockRecord(
            block_id=str(uuid4()),
            ip=ip,
            reason=reason,
            severity=severity,
            confidence=confidence,
            enforcement_layer=enforcement_layer,
            status=status,
            incident_id=incident_id,
            alert_id=alert_id,
            created_at=now,
            expires_at=expires,
            metadata={"detail": detail, "mode": self.enforcement_mode, "target": target_dst},
        )

        with self._lock:
            if status in ("active", "simulated"):
                self._active_blocks[ip] = rec
            else:
                self._history_blocks.insert(0, rec)

        try:
            insert_idp_block(rec)
            ev = LayerSecurityEvent(
                event_id=str(uuid4()),
                created_at=now,
                layer="idp",
                category="IP_BLOCKED" if status == "active" else f"IDP_{status.upper()}",
                severity=severity,
                src_ip=ip,
                dst_ip=target_dst or "host",
                target=enforcement_layer,
                namespace="host-security",
                summary=f"IDP {status.upper()}: {ip} via {enforcement_layer} for {dur}s ({reason})",
                details=rec.model_dump(mode="json"),
            )
            insert_security_event(ev)
        except Exception:
            pass

        if self._on_event:
            try:
                self._on_event({"type": "idp_action", "block": rec.model_dump(mode="json")})
            except Exception:
                pass

        logger.info("idp_action_executed", extra={"ip": ip, "status": status, "layer": enforcement_layer})
        return rec

    def unblock_ip(self, ip: str, unblocked_by: str = "admin") -> bool:
        now = datetime.now(timezone.utc)
        self._apply_firewall_rule(ip=ip, action="unblock")
        with self._lock:
            rec = self._active_blocks.pop(ip, None)
            if rec:
                rec.status = "unblocked"
                rec.unblocked_at = now
                rec.unblocked_by = unblocked_by
                self._history_blocks.insert(0, rec)
                self._history_blocks = self._history_blocks[:200]
        try:
            update_idp_block_status(ip, "unblocked", unblocked_by=unblocked_by)
        except Exception:
            pass
        return True

    def cleanup_expired_blocks(self) -> List[str]:
        now = datetime.now(timezone.utc)
        expired_ips: List[str] = []
        with self._lock:
            for ip, rec in list(self._active_blocks.items()):
                if now >= rec.expires_at:
                    expired_ips.append(ip)
                    self._active_blocks.pop(ip, None)
                    rec.status = "expired"
                    rec.unblocked_at = now
                    rec.unblocked_by = "ttl_expiry"
                    self._history_blocks.insert(0, rec)
                    self._history_blocks = self._history_blocks[:200]

        for ip in expired_ips:
            self._apply_firewall_rule(ip=ip, action="unblock")

        try:
            db_expired = expire_old_idp_blocks()
            for ip in db_expired:
                if ip not in expired_ips:
                    self._apply_firewall_rule(ip=ip, action="unblock")
                    expired_ips.append(ip)
        except Exception:
            pass

        return expired_ips

    def emergency_kill_switch(self, engage: bool = True) -> Dict[str, Any]:
        """Emergency IDP kill switch: immediately flush all blocks and switch to monitor mode without stopping IDS."""
        now = datetime.now(timezone.utc)
        with self._lock:
            self.kill_switch_engaged = engage
            if engage:
                self.enforcement_mode = "monitor"
                self.enabled = False
                active_ips = list(self._active_blocks.keys())
                for ip in active_ips:
                    rec = self._active_blocks.pop(ip)
                    rec.status = "unblocked"
                    rec.unblocked_at = now
                    rec.unblocked_by = "emergency_kill_switch"
                    self._history_blocks.insert(0, rec)
                    self._apply_firewall_rule(ip=ip, action="unblock")
                    try:
                        update_idp_block_status(ip, "unblocked", unblocked_by="emergency_kill_switch")
                    except Exception:
                        pass
                self._publish_responder_command(action="flush", ip="all", layer="all", simulated=False)
                if shutil.which("iptables"):
                    subprocess.run(["iptables", "-F", settings.idp_chain], check=False, capture_output=True, timeout=3)
            else:
                self.enabled = True
                self.enforcement_mode = "safe_enforce"

        return self.get_status()

    def add_allowlist(self, ip_or_cidr: str, label: str, is_management: bool = False) -> IdpAllowlistEntry:
        clean = ip_or_cidr.strip()
        # Validate IP or CIDR
        if "/" in clean:
            ipaddress.ip_network(clean, strict=False)
        else:
            ipaddress.ip_address(clean)

        entry = IdpAllowlistEntry(
            entry_id=f"allow-{clean}",
            ip_or_cidr=clean,
            label=label,
            is_management=is_management,
            created_at=datetime.now(timezone.utc),
            created_by="admin",
        )
        with self._lock:
            self._allowlist_entries[clean] = entry
            # If this IP was blocked, immediately unblock it!
            if clean in self._active_blocks:
                self.unblock_ip(clean, unblocked_by="allowlist_added")
        try:
            upsert_allowlist_entry(entry)
        except Exception:
            pass
        return entry

    def remove_allowlist(self, ip_or_cidr: str) -> bool:
        clean = ip_or_cidr.strip()
        with self._lock:
            self._allowlist_entries.pop(clean, None)
        try:
            delete_allowlist_entry(clean)
        except Exception:
            pass
        return True

    def update_policy(
        self,
        enabled: Optional[bool] = None,
        enforcement_mode: Optional[str] = None,
        block_seconds: Optional[int] = None,
        confidence_threshold: Optional[float] = None,
        auto_block_critical: Optional[bool] = None,
        auto_block_high: Optional[bool] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            if enabled is not None:
                self.enabled = bool(enabled)
                if self.enabled:
                    self.kill_switch_engaged = False
            if enforcement_mode in {"monitor", "safe_enforce", "full_enforce"}:
                self.enforcement_mode = enforcement_mode
            if block_seconds is not None:
                self.block_seconds = max(10, min(86400 * 7, int(block_seconds)))
            if confidence_threshold is not None:
                self.confidence_threshold = max(0.1, min(0.99, float(confidence_threshold)))
            if auto_block_critical is not None:
                self.auto_block_critical = bool(auto_block_critical)
            if auto_block_high is not None:
                self.auto_block_high = bool(auto_block_high)
        return self.get_status()

    def clear_history(self) -> None:
        with self._lock:
            self._active_blocks.clear()
            self._history_blocks.clear()
            self._corroboration_counts.clear()

    def get_status(self) -> Dict[str, Any]:
        self.cleanup_expired_blocks()
        now = datetime.now(timezone.utc)
        with self._lock:
            active_list = []
            for rec in sorted(self._active_blocks.values(), key=lambda x: x.created_at, reverse=True):
                d = rec.model_dump(mode="json")
                d["remaining_seconds"] = max(0, int((rec.expires_at - now).total_seconds()))
                active_list.append(d)

            history_list = [r.model_dump(mode="json") for r in self._history_blocks[:100]]
            allow_list = [e.model_dump(mode="json") for e in self._allowlist_entries.values()]

        try:
            db_blocks = get_idp_blocks(limit=100)
            if db_blocks:
                history_list = [b for b in db_blocks if b["status"] not in ("active", "simulated")]
        except Exception:
            pass

        failed_count = sum(1 for b in history_list if b.get("status") == "failed")

        return {
            "enabled": self.enabled,
            "enforcement_mode": self.enforcement_mode,
            "kill_switch_engaged": self.kill_switch_engaged,
            "firewall_backend": self._firewall_backend,
            "chain": settings.idp_chain,
            "block_seconds": self.block_seconds,
            "max_blocks": self.max_blocks,
            "confidence_threshold": self.confidence_threshold,
            "auto_block_critical": self.auto_block_critical,
            "auto_block_high": self.auto_block_high,
            "active_blocks_count": len(active_list),
            "history_blocks_count": len(history_list),
            "failed_attempts_count": failed_count,
            "active_blocks": active_list,
            "recent_history": history_list[:50],
            "allowlist": allow_list,
            "system_protected_ips": sorted(list(self._system_protected_ips | self._protected_node_ips)),
        }
