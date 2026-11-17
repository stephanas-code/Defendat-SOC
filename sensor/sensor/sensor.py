from __future__ import annotations

from collections import deque
import logging
import os
import threading
import time
from typing import Deque, Dict, List, Optional, Tuple

from scapy.all import sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP

from sensor.config import settings
from sensor.flow import Flow, new_flow
from sensor.kafka_out import FlowProducer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sensor")


FlowKey = Tuple[str, int, str, int, str]


class FlowTable:
    def __init__(self) -> None:
        self._by_key: Dict[FlowKey, Flow] = {}
        self._lock = threading.Lock()
        # Deduplicate identical packets seen across veth + CNI bridge when sniffing on 'any'
        self._recent_pkt_sigs: Deque[Tuple[str, str, int, int, int, int]] = deque(maxlen=512)

    def _get_or_create(self, fwd_key: FlowKey, rev_key: FlowKey, proto: str, ts: float) -> tuple[Flow, str]:
        with self._lock:
            if fwd_key in self._by_key:
                return self._by_key[fwd_key], "fwd"
            if rev_key in self._by_key:
                return self._by_key[rev_key], "bwd"
            flow = new_flow(fwd_key, proto=proto, ts=ts)
            self._by_key[fwd_key] = flow
            self._by_key[rev_key] = flow
            return flow, "fwd"

    def add_packet(self, ip_pkt: IP, ts: float) -> None:
        proto = "OTHER"
        src_port = 0
        dst_port = 0
        seq_or_id = int(getattr(ip_pkt, "id", 0))
        if ip_pkt.haslayer(TCP):
            proto = "TCP"
            src_port = int(ip_pkt[TCP].sport)
            dst_port = int(ip_pkt[TCP].dport)
            seq_or_id = int(getattr(ip_pkt[TCP], "seq", seq_or_id))
        elif ip_pkt.haslayer(UDP):
            proto = "UDP"
            src_port = int(ip_pkt[UDP].sport)
            dst_port = int(ip_pkt[UDP].dport)
        elif ip_pkt.haslayer(ICMP):
            proto = "ICMP"
            src_port = int(getattr(ip_pkt[ICMP], "type", 0))
            dst_port = int(getattr(ip_pkt[ICMP], "code", 0))
        else:
            proto = str(int(ip_pkt.proto))

        src_ip = str(ip_pkt.src)
        dst_ip = str(ip_pkt.dst)

        # Avoid duplicate packet counting across Kubernetes veth + CNI bridge interfaces
        pkt_sig = (src_ip, dst_ip, src_port, dst_port, seq_or_id, int(len(ip_pkt)))
        with self._lock:
            if pkt_sig in self._recent_pkt_sigs and seq_or_id != 0:
                return
            self._recent_pkt_sigs.append(pkt_sig)

        fwd_key: FlowKey = (src_ip, src_port, dst_ip, dst_port, proto)
        rev_key: FlowKey = (dst_ip, dst_port, src_ip, src_port, proto)

        flow, direction = self._get_or_create(fwd_key, rev_key, proto=proto, ts=ts)
        flow.add_packet(ip_pkt, ts=ts, direction=direction)

    def flush_expired(self, producer: FlowProducer, now_ts: float) -> int:
        expired_keys = []
        flushed = 0

        with self._lock:
            seen_flow_ids = set()
            for key, flow in list(self._by_key.items()):
                if flow.flow_id in seen_flow_ids:
                    continue
                seen_flow_ids.add(flow.flow_id)

                idle = now_ts - flow.last_ts
                active = now_ts - flow.first_ts
                if idle >= settings.sensor_idle_timeout_seconds or active >= settings.sensor_active_timeout_seconds:
                    expired_keys.append(flow)

            for flow in expired_keys:
                keys_to_del = [k for k, v in self._by_key.items() if v.flow_id == flow.flow_id]
                for k in keys_to_del:
                    self._by_key.pop(k, None)

        for flow in expired_keys:
            try:
                producer.send_flow(flow.to_record())
                flushed += 1
            except Exception:
                logger.exception("flow_send_failed")

        if flushed:
            try:
                producer.flush()
            except Exception:
                pass

        return flushed


def _resolve_interfaces(configured: str) -> Optional[str | List[str]]:
    cfg = (configured or "any").strip()
    if cfg.lower() in ("any", "all", "*"):
        return None  # Scapy sniff(iface=None) captures on all interfaces on Linux
    parts = [p.strip() for p in cfg.split(",") if p.strip()]
    valid = [p for p in parts if os.path.exists(f"/sys/class/net/{p}")]
    if not valid:
        logger.warning("configured_interfaces_not_found=%s; falling back to all interfaces (any)", cfg)
        return None
    return valid[0] if len(valid) == 1 else valid


def main() -> None:
    if not settings.network_monitoring_enabled:
        logger.info("network_monitoring_disabled")
        while True:
            time.sleep(60)

    producer = FlowProducer()
    table = FlowTable()

    def on_pkt(pkt) -> None:
        if IP not in pkt:
            return
        ip_pkt = pkt[IP]
        ts = float(getattr(pkt, "time", time.time()))
        table.add_packet(ip_pkt, ts=ts)

    def flusher() -> None:
        while True:
            time.sleep(settings.sensor_flush_interval_seconds)
            n = table.flush_expired(producer, now_ts=time.time())
            if n:
                logger.info("flows_flushed=%s", n)

    threading.Thread(target=flusher, daemon=True).start()

    iface = _resolve_interfaces(settings.sensor_interface)
    logger.info("sniff_start iface=%s filter=%s", iface or "any", settings.sensor_bpf_filter)
    sniff(iface=iface, filter=settings.sensor_bpf_filter, prn=on_pkt, store=False)


if __name__ == "__main__":
    main()
