from __future__ import annotations

import hashlib
import logging
import os
import re
import socket
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from app.config import settings
from app.db import insert_security_event
from app.schemas import AlertRecord, LayerSecurityEvent

logger = logging.getLogger(__name__)

EXPECTED_LISTEN_PORTS: Set[int] = {
    22, 53, 80, 443, 2181, 2379, 2380, 3000, 5173, 5432, 6379, 6443,
    8000, 8080, 8443, 9090, 9092, 9094, 10250, 10256, 10257, 10259,
}

SUSPICIOUS_PROC_PATTERNS = [
    r"\bxmrig\b",
    r"\bminerd\b",
    r"\bncat\b",
    r"\bsocat\b",
    r"\bchisel\b",
    r"/dev/tcp/",
    r"bash\s+-i",
    r"sh\s+-i",
    r"python.*pty\.spawn",
    r"curl\s+.*\|\s*(ba)?sh",
    r"wget\s+.*\|\s*(ba)?sh",
]

CRITICAL_FILES = [
    "passwd",
    "shadow",
    "group",
    "sudoers",
    "ssh/sshd_config",
    "crontab",
    "hosts",
    "resolv.conf",
]

SSH_FAIL_RE = re.compile(
    r"(?:Failed password|Invalid user|authentication failure|Connection closed by authenticating user).*?(?:from|rhost=)\s*(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE,
)
PRIV_ESC_RE = re.compile(
    r"(?:sudo:.*(?:authentication failure|NOT in sudoers|COMMAND=.*/bin/su|COMMAND=.*/bin/bash|COMMAND=.*/etc/shadow)|su\[.*\]:\s*FAILED)",
    re.IGNORECASE,
)
FW_DROP_RE = re.compile(
    r"(?:UFW BLOCK|IPTABLES_DROP|NFT_DROP|AI_IDS_BLOCK).*?SRC=(\d{1,3}(?:\.\d{1,3}){3}).*?DST=(\d{1,3}(?:\.\d{1,3}){3}).*?(?:DPT=(\d+))?",
    re.IGNORECASE,
)


def _decode_proc_ip_port(hex_addr: str) -> Tuple[str, int]:
    try:
        ip_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        if len(ip_hex) == 8:
            ip_int = int(ip_hex, 16)
            ip = socket.inet_ntoa(ip_int.to_bytes(4, "little"))
            return ip, port
        elif len(ip_hex) == 32:
            return "::1" if ip_hex.endswith("0001") else "ipv6", port
    except Exception:
        pass
    return "0.0.0.0", 0


class HostMonitor:
    """Linux Host Security & System Log Monitor."""

    def __init__(self, on_alert: Callable[[AlertRecord, str], None]) -> None:
        self._on_alert = on_alert
        self._stop = threading.Event()
        self._lock = threading.RLock()

        self._file_hashes: Dict[str, str] = {}
        self._log_offsets: Dict[str, int] = {}
        self._ssh_failures_by_ip: Dict[str, List[float]] = defaultdict(list)
        self._known_unexpected_ports: Set[int] = set()
        self._last_state: Dict[str, Any] = {
            "status": "initializing",
            "cpu_load_pct": 0.0,
            "memory_used_pct": 0.0,
            "memory_total_mb": 0,
            "memory_used_mb": 0,
            "active_connections": 0,
            "established_connections": 0,
            "listening_ports": [],
            "unexpected_ports": [],
            "running_processes": 0,
            "suspicious_processes": [],
            "file_integrity_status": "verified",
            "monitored_files_count": 0,
            "modified_files": [],
            "cron_jobs_count": 0,
            "ssh_failed_attempts": 0,
            "network_rx_mb": 0.0,
            "network_tx_mb": 0.0,
            "last_scan_at": None,
        }

    def start(self) -> None:
        if not settings.host_monitoring_enabled:
            logger.info("host_monitoring_disabled")
            return
        self._baseline_critical_files()
        # Perform immediate initial scan so dashboard has real telemetry on startup
        try:
            self.scan_once()
        except Exception:
            logger.exception("initial_host_scan_failed")
        threading.Thread(target=self._run_loop, daemon=True, name="host-monitor").start()

    def stop(self) -> None:
        self._stop.set()

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception:
                logger.exception("host_monitor_scan_error")
            time.sleep(max(5, settings.monitor_interval_seconds))

    def _resolve_etc_path(self, rel: str) -> Optional[str]:
        for base in [settings.host_etc_dir, "/etc"]:
            p = os.path.join(base, rel)
            if os.path.exists(p) and os.path.isfile(p):
                return p
        return None

    def _baseline_critical_files(self) -> None:
        for rel in CRITICAL_FILES:
            p = self._resolve_etc_path(rel)
            if not p:
                continue
            try:
                with open(p, "rb") as f:
                    self._file_hashes[p] = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                pass

    def scan_once(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        proc_dir = settings.host_proc_dir if os.path.exists(settings.host_proc_dir) else "/proc"

        # 1. CPU & Memory telemetry
        cpu_pct = 0.0
        loadavg_path = os.path.join(proc_dir, "loadavg")
        if os.path.exists(loadavg_path):
            try:
                with open(loadavg_path, "r", encoding="utf-8") as f:
                    load1 = float(f.read().strip().split()[0])
                cores = os.cpu_count() or 2
                cpu_pct = round(min(100.0, (load1 / cores) * 100.0), 1)
            except Exception:
                pass

        mem_total_mb = 0
        mem_used_mb = 0
        mem_pct = 0.0
        meminfo_path = os.path.join(proc_dir, "meminfo")
        if os.path.exists(meminfo_path):
            try:
                mem_kv: Dict[str, int] = {}
                with open(meminfo_path, "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            val_parts = parts[1].strip().split()
                            if val_parts and val_parts[0].isdigit():
                                mem_kv[parts[0].strip()] = int(val_parts[0])
                total_kb = mem_kv.get("MemTotal", 0)
                avail_kb = mem_kv.get("MemAvailable", mem_kv.get("MemFree", 0))
                if total_kb > 0:
                    used_kb = max(0, total_kb - avail_kb)
                    mem_total_mb = total_kb // 1024
                    mem_used_mb = used_kb // 1024
                    mem_pct = round((used_kb / total_kb) * 100.0, 1)
            except Exception:
                pass

        # 2. Network RX/TX counters from /proc/net/dev
        rx_bytes = 0
        tx_bytes = 0
        netdev_path = os.path.join(proc_dir, "net/dev")
        if os.path.exists(netdev_path):
            try:
                with open(netdev_path, "r", encoding="utf-8") as f:
                    for line in f.readlines()[2:]:
                        if ":" not in line:
                            continue
                        iface, stats_str = line.split(":", 1)
                        if iface.strip() == "lo":
                            continue
                        cols = stats_str.split()
                        if len(cols) >= 9:
                            rx_bytes += int(cols[0])
                            tx_bytes += int(cols[8])
            except Exception:
                pass

        # 3. Active TCP/UDP connections, listening ports, and SYN_RECV / scan detection
        active_conns = 0
        established_conns = 0
        listening_ports: Set[int] = set()
        syn_recv_by_src: Counter[str] = Counter()
        conn_ports_by_src: Dict[str, Set[int]] = defaultdict(set)

        for proto_file in ["net/tcp", "net/tcp6", "net/udp"]:
            p = os.path.join(proc_dir, proto_file)
            if not os.path.exists(p):
                continue
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f.readlines()[1:]:
                        cols = line.strip().split()
                        if len(cols) < 4:
                            continue
                        local_ip, local_port = _decode_proc_ip_port(cols[1])
                        rem_ip, rem_port = _decode_proc_ip_port(cols[2])
                        state = cols[3]
                        active_conns += 1
                        if state == "0A":  # TCP_LISTEN
                            if local_port > 0:
                                listening_ports.add(local_port)
                        elif state == "01":  # TCP_ESTABLISHED
                            established_conns += 1
                            if rem_ip not in ("0.0.0.0", "127.0.0.1", "ipv6", "::1"):
                                conn_ports_by_src[rem_ip].add(local_port)
                        elif state == "03":  # TCP_SYN_RECV
                            if rem_ip not in ("0.0.0.0", "127.0.0.1"):
                                syn_recv_by_src[rem_ip] += 1
                                conn_ports_by_src[rem_ip].add(local_port)
            except Exception:
                pass

        # Detect unexpected listening ports (exclude ephemeral >= 32768)
        unexpected_ports = sorted(
            [pt for pt in listening_ports if pt < 32768 and pt not in EXPECTED_LISTEN_PORTS]
        )
        for up in unexpected_ports:
            if up not in self._known_unexpected_ports:
                self._known_unexpected_ports.add(up)
                self._emit_host_event(
                    category="UNEXPECTED_LISTENING_PORT",
                    severity="medium",
                    src_ip="127.0.0.1",
                    dst_ip=f"0.0.0.0:{up}",
                    summary=f"Unexpected listening TCP port {up} detected on host",
                    details={"port": up, "confidence": 0.80},
                )

        # Detect port scanning / SYN flood on host socket table
        for rem_ip, ports_set in conn_ports_by_src.items():
            if len(ports_set) >= 12:
                self._emit_host_event(
                    category="Host_Port_Scan",
                    severity="high",
                    src_ip=rem_ip,
                    dst_ip="host",
                    summary=f"Host socket table detected port scan from {rem_ip} across {len(ports_set)} ports",
                    details={"ports_count": len(ports_set), "confidence": 0.91},
                    trigger_alert=True,
                )

        # 4. Process inspection (/proc/[pid]/cmdline)
        proc_count = 0
        suspicious_procs: List[Dict[str, Any]] = []
        if os.path.exists(proc_dir):
            try:
                for entry in os.listdir(proc_dir):
                    if not entry.isdigit():
                        continue
                    proc_count += 1
                    cmdline_path = os.path.join(proc_dir, entry, "cmdline")
                    try:
                        with open(cmdline_path, "rb") as f:
                            raw = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                        if not raw:
                            continue
                        for pat in SUSPICIOUS_PROC_PATTERNS:
                            if re.search(pat, raw, re.IGNORECASE):
                                item = {"pid": int(entry), "cmdline": raw[:200], "pattern": pat}
                                suspicious_procs.append(item)
                                self._emit_host_event(
                                    category="Suspicious_Host_Process",
                                    severity="critical",
                                    src_ip="127.0.0.1",
                                    dst_ip="host",
                                    summary=f"Suspicious process PID {entry} executing: {raw[:120]}",
                                    details={"pid": int(entry), "cmdline": raw[:200], "confidence": 0.94},
                                    trigger_alert=True,
                                )
                                break
                    except Exception:
                        pass
            except Exception:
                pass

        # 5. Critical file integrity check
        modified_files: List[str] = []
        for path, old_hash in list(self._file_hashes.items()):
            try:
                if os.path.exists(path):
                    with open(path, "rb") as f:
                        cur_hash = hashlib.sha256(f.read()).hexdigest()
                    if cur_hash != old_hash:
                        modified_files.append(path)
                        self._file_hashes[path] = cur_hash
                        self._emit_host_event(
                            category="Critical_File_Modified",
                            severity="high",
                            src_ip="127.0.0.1",
                            dst_ip=path,
                            summary=f"Critical system file modified: {path}",
                            details={"file": path, "old_sha256": old_hash, "new_sha256": cur_hash, "confidence": 0.92},
                            trigger_alert=True,
                        )
            except Exception:
                pass

        # 6. Scheduled tasks / Cron persistence count
        cron_count = 0
        for cron_rel in ["crontab", "cron.d", "cron.hourly", "cron.daily"]:
            cp = self._resolve_etc_path(cron_rel)
            if cp and os.path.isfile(cp):
                cron_count += 1

        # 7. Tail host authentication / system / kernel / firewall logs if enabled
        if settings.log_monitoring_enabled:
            self._tail_host_logs()

        with self._lock:
            total_ssh_fails = sum(len(v) for v in self._ssh_failures_by_ip.values())
            self._last_state = {
                "status": "critical" if suspicious_procs else ("warning" if modified_files or unexpected_ports else "secure"),
                "cpu_load_pct": cpu_pct,
                "memory_used_pct": mem_pct,
                "memory_total_mb": mem_total_mb,
                "memory_used_mb": mem_used_mb,
                "active_connections": active_conns,
                "established_connections": established_conns,
                "listening_ports": sorted(list(listening_ports)),
                "unexpected_ports": unexpected_ports,
                "running_processes": proc_count,
                "suspicious_processes": suspicious_procs,
                "file_integrity_status": "compromised" if modified_files else "verified",
                "monitored_files_count": len(self._file_hashes),
                "modified_files": modified_files,
                "cron_jobs_count": cron_count,
                "ssh_failed_attempts": total_ssh_fails,
                "network_rx_mb": round(rx_bytes / (1024 * 1024), 2),
                "network_tx_mb": round(tx_bytes / (1024 * 1024), 2),
                "last_scan_at": now.isoformat(),
            }
            return dict(self._last_state)

    def _tail_host_logs(self) -> None:
        log_files = ["auth.log", "secure", "syslog", "kern.log", "ufw.log", "messages"]
        for fname in log_files:
            for base in [settings.host_log_dir, "/var/log"]:
                fpath = os.path.join(base, fname)
                if not os.path.exists(fpath) or not os.path.isfile(fpath):
                    continue
                try:
                    size = os.path.getsize(fpath)
                    offset = self._log_offsets.get(fpath, max(0, size - 32768))
                    if size < offset:
                        offset = 0
                    if size == offset:
                        break
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(offset)
                        lines = f.readlines()
                        self._log_offsets[fpath] = f.tell()
                    for line in lines[-200:]:
                        self.ingest_log_line(line.strip(), source=fname)
                except Exception:
                    pass
                break

    def ingest_log_line(self, line: str, source: str = "auth.log") -> Optional[Dict[str, Any]]:
        """Parse and evaluate a single Linux host log line (SSH, sudo, kernel, firewall)."""
        if not line:
            return None
        now_ts = time.time()

        # 1. Check SSH authentication failure / brute force
        m_ssh = SSH_FAIL_RE.search(line)
        if m_ssh:
            src_ip = m_ssh.group(1)
            with self._lock:
                recent = [t for t in self._ssh_failures_by_ip[src_ip] if now_ts - t <= 300.0]
                recent.append(now_ts)
                self._ssh_failures_by_ip[src_ip] = recent
                fail_count = len(recent)

            is_brute = fail_count >= 3
            sev = "high" if is_brute else "medium"
            cat = "SSH-Patator" if is_brute else "SSH_Auth_Failure"
            conf = min(0.98, 0.72 + (fail_count * 0.05))
            return self._emit_host_event(
                category=cat,
                severity=sev,
                src_ip=src_ip,
                dst_ip="host:22",
                summary=f"SSH authentication failure from {src_ip} ({fail_count} attempts in 5m): {line[:140]}",
                details={"source": source, "fail_count": fail_count, "raw": line[:250], "confidence": conf, "dst_port": 22},
                trigger_alert=is_brute,
            )

        # 2. Check privilege escalation (sudo / su abuse)
        if PRIV_ESC_RE.search(line):
            return self._emit_host_event(
                category="Host_Privilege_Escalation",
                severity="critical",
                src_ip="127.0.0.1",
                dst_ip="host:sudo",
                summary=f"Privilege escalation attempt detected in {source}: {line[:150]}",
                details={"source": source, "raw": line[:250], "confidence": 0.93, "dst_port": 22},
                trigger_alert=True,
            )

        # 3. Check Firewall drop logs
        m_fw = FW_DROP_RE.search(line)
        if m_fw:
            src_ip = m_fw.group(1)
            dst_ip = m_fw.group(2)
            dport = int(m_fw.group(3) or 0)
            return self._emit_host_event(
                category="Firewall_Packet_Drop",
                severity="low",
                src_ip=src_ip,
                dst_ip=f"{dst_ip}:{dport}",
                summary=f"Host firewall dropped packet from {src_ip} to {dst_ip}:{dport}",
                details={"source": source, "dst_port": dport, "raw": line[:200], "confidence": 0.75},
                trigger_alert=False,
            )

        return None

    def _emit_host_event(
        self,
        category: str,
        severity: str,
        src_ip: str,
        dst_ip: str,
        summary: str,
        details: Dict[str, Any],
        trigger_alert: bool = False,
    ) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        ev = LayerSecurityEvent(
            event_id=str(uuid4()),
            created_at=now,
            layer="host",
            category=category,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            target="linux-host",
            namespace="host-system",
            summary=summary,
            details=details,
        )
        try:
            insert_security_event(ev)
        except Exception:
            pass

        if trigger_alert and self._on_alert:
            dport = int(details.get("dst_port", 22))
            alert = AlertRecord(
                alert_id=str(uuid4()),
                created_at=now,
                flow_id=f"host-{ev.event_id[:8]}",
                src_ip=src_ip,
                dst_ip=dst_ip.split(":")[0] if ":" in dst_ip else "127.0.0.1",
                src_port=0,
                dst_port=dport,
                protocol="TCP",
                severity=severity if severity in ("critical", "high", "medium", "low") else "high",
                label=category,
                confidence=float(details.get("confidence", 0.88)),
                signals={"layer": "host", "summary": summary, **details},
                geoip=None,
            )
            try:
                self._on_alert(alert, "Linux Host Monitor")
            except Exception:
                logger.exception("host_alert_callback_failed")

        return ev.model_dump(mode="json")

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._last_state)
