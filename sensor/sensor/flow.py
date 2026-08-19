from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from uuid import uuid4

from scapy.layers.inet import IP, TCP, UDP, ICMP

from sensor.features import FlowFeatureInputs, compute_features_44


def _now_dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _tcp_flags(pkt: TCP) -> int:
    try:
        return int(pkt.flags)
    except Exception:
        return 0


def _hdr_len_bytes(ip: IP) -> int:
    ihl = int(getattr(ip, "ihl", 5)) * 4
    l4 = 0
    if ip.haslayer(TCP):
        tcp = ip[TCP]
        l4 = int(getattr(tcp, "dataofs", 5)) * 4
    elif ip.haslayer(UDP):
        l4 = 8
    elif ip.haslayer(ICMP):
        l4 = 8
    return int(ihl + l4)


@dataclass
class Flow:
    flow_id: str
    fwd_key: tuple
    protocol: str
    first_ts: float
    last_ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int

    fwd_pkt_lens: List[int] = field(default_factory=list)
    bwd_pkt_lens: List[int] = field(default_factory=list)
    all_pkt_lens: List[int] = field(default_factory=list)

    fwd_iats: List[float] = field(default_factory=list)
    bwd_iats: List[float] = field(default_factory=list)
    flow_iats: List[float] = field(default_factory=list)

    _last_fwd_ts: Optional[float] = None
    _last_bwd_ts: Optional[float] = None
    _last_any_ts: Optional[float] = None

    fwd_psh: int = 0
    bwd_psh: int = 0
    fwd_urg: int = 0
    bwd_urg: int = 0

    fwd_hdr_len: int = 0
    bwd_hdr_len: int = 0

    fin: int = 0
    syn: int = 0
    rst: int = 0
    ack: int = 0

    def add_packet(self, ip_pkt: IP, ts: float, direction: str) -> None:
        self.last_ts = max(self.last_ts, ts)
        pkt_len = int(len(ip_pkt))
        self.all_pkt_lens.append(pkt_len)

        if self._last_any_ts is not None:
            self.flow_iats.append(float(ts - self._last_any_ts))
        self._last_any_ts = ts

        hdr_len = _hdr_len_bytes(ip_pkt)

        if direction == "fwd":
            self.fwd_pkt_lens.append(pkt_len)
            self.fwd_hdr_len += hdr_len
            if self._last_fwd_ts is not None:
                self.fwd_iats.append(float(ts - self._last_fwd_ts))
            self._last_fwd_ts = ts
        else:
            self.bwd_pkt_lens.append(pkt_len)
            self.bwd_hdr_len += hdr_len
            if self._last_bwd_ts is not None:
                self.bwd_iats.append(float(ts - self._last_bwd_ts))
            self._last_bwd_ts = ts

        if ip_pkt.haslayer(TCP):
            tcp = ip_pkt[TCP]
            flags = _tcp_flags(tcp)

            if flags & 0x01:
                self.fin += 1
            if flags & 0x02:
                self.syn += 1
            if flags & 0x04:
                self.rst += 1
            if flags & 0x10:
                self.ack += 1

            if direction == "fwd":
                if flags & 0x08:
                    self.fwd_psh += 1
                if flags & 0x20:
                    self.fwd_urg += 1
            else:
                if flags & 0x08:
                    self.bwd_psh += 1
                if flags & 0x20:
                    self.bwd_urg += 1

    def to_record(self) -> dict:
        duration_ms = max(0.0, (self.last_ts - self.first_ts) * 1000.0)
        feats = compute_features_44(
            FlowFeatureInputs(
                duration_ms=duration_ms,
                fwd_pkt_lens=self.fwd_pkt_lens,
                bwd_pkt_lens=self.bwd_pkt_lens,
                all_pkt_lens=self.all_pkt_lens,
                fwd_iats=self.fwd_iats,
                bwd_iats=self.bwd_iats,
                flow_iats=self.flow_iats,
                fwd_psh=self.fwd_psh,
                bwd_psh=self.bwd_psh,
                fwd_urg=self.fwd_urg,
                bwd_urg=self.bwd_urg,
                fwd_hdr_len=self.fwd_hdr_len,
                bwd_hdr_len=self.bwd_hdr_len,
                fin=self.fin,
                syn=self.syn,
                rst=self.rst,
                ack=self.ack,
            )
        )

        feats.pop("_pkt_len_var", None)

        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "first_seen": _now_dt(self.first_ts).isoformat(),
            "last_seen": _now_dt(self.last_ts).isoformat(),
            "features": feats,
        }


def new_flow(fwd_key: tuple, proto: str, ts: float) -> Flow:
    src_ip, src_port, dst_ip, dst_port, _ = fwd_key
    return Flow(
        flow_id=str(uuid4()),
        fwd_key=fwd_key,
        protocol=proto,
        first_ts=ts,
        last_ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=int(src_port),
        dst_port=int(dst_port),
    )
