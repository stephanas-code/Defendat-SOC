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
from typing import Dict, List, Set, Tuple

from kafka import KafkaConsumer
from pythonjsonlogger import jsonlogger
import redis


def setup_logging() -> None:
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.setLevel("INFO")

    handler = logging.StreamHandler()
    handler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)


setup_logging()
logger = logging.getLogger("responder")


KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")
KAFKA_TOPIC_ALERTS = os.getenv("KAFKA_TOPIC_ALERTS", "alerts")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "responder")

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

IDP_ENABLED = os.getenv("IDP_ENABLED", "true").lower() == "true"
IDP_ENFORCEMENT_MODE = os.getenv("IDP_ENFORCEMENT_MODE", "safe_enforce").lower()
IDP_BLOCK_SECONDS = int(os.getenv("IDP_BLOCK_SECONDS", "600"))
IDP_MAX_BLOCKS = int(os.getenv("IDP_MAX_BLOCKS", "100"))
IDP_CONFIDENCE_THRESHOLD = float(os.getenv("IDP_CONFIDENCE_THRESHOLD", "0.75"))
IDP_AUTO_BLOCK_CRITICAL = os.getenv("IDP_AUTO_BLOCK_CRITICAL", "true").lower() == "true"
IDP_AUTO_BLOCK_HIGH = os.getenv("IDP_AUTO_BLOCK_HIGH", "true").lower() == "true"
IDP_CHAIN = os.getenv("IDP_CHAIN", "AI_IDS_BLOCK")
IDP_ALLOWLIST = [x.strip() for x in os.getenv("IDP_ALLOWLIST", "127.0.0.1/32,::1/128,10.96.0.0/12,10.244.0.0/16").split(",") if x.strip()]
IDP_MANAGEMENT_IPS = [x.strip() for x in os.getenv("IDP_MANAGEMENT_IPS", "127.0.0.1,192.168.1.1,10.0.0.1").split(",") if x.strip()]
IDP_PROTECTED_CIDRS = [x.strip() for x in os.getenv("IDP_PROTECTED_CIDRS", "127.0.0.0/8,10.96.0.0/12,10.244.0.0/16,169.254.0.0/16").split(",") if x.strip()]


class FirewallEnforcer:
    """Host-level iptables / nftables enforcement with safety guardrails and automatic rollback."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blocked: Dict[str, float] = {}  # ip -> unblock_epoch
        self._backend = "iptables" if shutil.which("iptables") else ("nftables" if shutil.which("nft") else "none")
        self._protected_ips: Set[str] = self._discover_protected_ips()

    def _discover_protected_ips(self) -> Set[str]:
        prot: Set[str] = {"127.0.0.1", "::1", "0.0.0.0", "localhost"} | set(IDP_MANAGEMENT_IPS)
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                if info[4][0]:
                    prot.add(info[4][0].split("%")[0])
        except Exception:
            pass
        k8s_host = os.getenv("KUBERNETES_SERVICE_HOST")
        if k8s_host:
            prot.add(k8s_host)
        return prot

    def is_safe_to_block(self, ip: str) -> Tuple[bool, str]:
        if not ip:
            return False, "empty_ip"
        clean = ip.strip()
        if clean in self._protected_ips:
            return False, "protected_system_or_management_ip"
        try:
            ip_obj = ipaddress.ip_address(clean)
            if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
                return False, "loopback_or_link_local"
            for cidr in IDP_ALLOWLIST + IDP_PROTECTED_CIDRS:
                try:
                    if "/" in cidr:
                        if ip_obj in ipaddress.ip_network(cidr, strict=False):
                            return False, f"allowlist_or_protected_cidr:{cidr}"
                    elif ip_obj == ipaddress.ip_address(cidr):
                        return False, f"allowlist_ip:{cidr}"
                except Exception:
                    pass
        except ValueError:
            return False, "invalid_ip"
        return True, "ok"

    def ensure_chain(self) -> None:
        if self._backend != "iptables" or IDP_ENFORCEMENT_MODE == "monitor":
            return
        subprocess.run(["iptables", "-N", IDP_CHAIN], check=False, capture_output=True)
        # Hook into INPUT and FORWARD (plus DOCKER-USER if present) so both host and K8s pods are protected
        for parent in ["INPUT", "FORWARD", "DOCKER-USER"]:
            chk_parent = subprocess.run(["iptables", "-L", parent, "-n"], check=False, capture_output=True)
            if chk_parent.returncode != 0:
                continue
            chk_jump = subprocess.run(["iptables", "-C", parent, "-j", IDP_CHAIN], check=False, capture_output=True)
            if chk_jump.returncode != 0:
                subprocess.run(["iptables", "-I", parent, "1", "-j", IDP_CHAIN], check=False, capture_output=True)

    def block_ip(self, ip: str, duration_s: int = IDP_BLOCK_SECONDS, simulated: bool = False) -> bool:
        safe, reason = self.is_safe_to_block(ip)
        if not safe:
            logger.warning("responder_guardrail_prevented_block", extra={"ip": ip, "reason": reason})
            return False

        with self._lock:
            if len(self._blocked) >= IDP_MAX_BLOCKS and ip not in self._blocked:
                logger.warning("idp_max_blocks_reached", extra={"ip": ip, "max": IDP_MAX_BLOCKS})
                return False
            self._blocked[ip] = time.time() + duration_s

        if simulated or IDP_ENFORCEMENT_MODE == "monitor" or not IDP_ENABLED:
            logger.info("ip_block_simulated", extra={"src_ip": ip, "duration_s": duration_s})
            return True

        if self._backend == "iptables":
            self.ensure_chain()
            chk = subprocess.run(["iptables", "-C", IDP_CHAIN, "-s", ip, "-j", "DROP"], check=False, capture_output=True)
            if chk.returncode != 0:
                res = subprocess.run(["iptables", "-I", IDP_CHAIN, "1", "-s", ip, "-j", "DROP"], check=False, capture_output=True)
                if res.returncode != 0:
                    logger.error("iptables_block_failed_rolling_back", extra={"ip": ip})
                    with self._lock:
                        self._blocked.pop(ip, None)
                    return False
        logger.info("ip_blocked", extra={"src_ip": ip, "duration_s": duration_s, "backend": self._backend})
        return True

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked.pop(ip, None)
        if self._backend == "iptables":
            while subprocess.run(["iptables", "-C", IDP_CHAIN, "-s", ip, "-j", "DROP"], check=False, capture_output=True).returncode == 0:
                subprocess.run(["iptables", "-D", IDP_CHAIN, "-s", ip, "-j", "DROP"], check=False, capture_output=True)
        logger.info("ip_unblocked", extra={"src_ip": ip})

    def flush_all(self) -> None:
        with self._lock:
            ips = list(self._blocked.keys())
            self._blocked.clear()
        if self._backend == "iptables":
            subprocess.run(["iptables", "-F", IDP_CHAIN], check=False, capture_output=True)
        logger.warning("idp_kill_switch_flushed_all_blocks", extra={"flushed_count": len(ips)})

    def cleanup_expired(self) -> None:
        now = time.time()
        expired: List[str] = []
        with self._lock:
            for ip, until in list(self._blocked.items()):
                if now >= until:
                    expired.append(ip)
        for ip in expired:
            self.unblock_ip(ip)


enforcer = FirewallEnforcer()


def expiry_loop() -> None:
    while True:
        try:
            enforcer.cleanup_expired()
        except Exception:
            logger.exception("expiry_loop_error")
        time.sleep(5)


def redis_command_listener() -> None:
    """Listen for real-time block/unblock/kill-switch commands from backend API."""
    while True:
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            pubsub = r.pubsub()
            pubsub.subscribe("idp:commands")
            logger.info("responder_redis_listener_connected")
            for item in pubsub.listen():
                if item.get("type") != "message":
                    continue
                data = json.loads(item["data"])
                action = data.get("action")
                ip = data.get("ip", "")
                simulated = bool(data.get("simulated", False))
                if action == "block" and ip:
                    enforcer.block_ip(ip, simulated=simulated)
                elif action == "unblock" and ip:
                    enforcer.unblock_ip(ip)
                elif action == "flush":
                    enforcer.flush_all()
        except Exception:
            time.sleep(3)


def main() -> None:
    if IDP_ENABLED and IDP_ENFORCEMENT_MODE != "monitor":
        enforcer.ensure_chain()
        logger.info("idp_enabled", extra={"mode": IDP_ENFORCEMENT_MODE, "chain": IDP_CHAIN})
    else:
        logger.info("idp_monitor_mode", extra={"enabled": IDP_ENABLED, "mode": IDP_ENFORCEMENT_MODE})

    consumer = KafkaConsumer(
        KAFKA_TOPIC_ALERTS,
        bootstrap_servers=KAFKA_BROKERS.split(","),
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset="latest",
        enable_auto_commit=True,
        consumer_timeout_ms=2000,
    )

    while True:
        enforcer.cleanup_expired()
        for msg in consumer:
            enforcer.cleanup_expired()
            try:
                alert = json.loads(msg.value.decode("utf-8"))
            except Exception:
                continue

            src_ip = alert.get("src_ip")
            severity = (alert.get("severity") or "").lower()
            confidence = float(alert.get("confidence") or 0.0)

            if not src_ip or not IDP_ENABLED:
                continue

            if severity == "critical" and IDP_AUTO_BLOCK_CRITICAL and confidence >= IDP_CONFIDENCE_THRESHOLD:
                enforcer.block_ip(src_ip, duration_s=IDP_BLOCK_SECONDS * 2)
            elif severity == "high" and IDP_AUTO_BLOCK_HIGH and confidence >= IDP_CONFIDENCE_THRESHOLD:
                enforcer.block_ip(src_ip, duration_s=IDP_BLOCK_SECONDS)


if __name__ == "__main__":
    threading.Thread(target=expiry_loop, daemon=True).start()
    threading.Thread(target=redis_command_listener, daemon=True).start()
    while True:
        try:
            main()
        except Exception:
            logger.exception("responder_kafka_loop_restarting")
            time.sleep(2)
