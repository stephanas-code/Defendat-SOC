from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, List, Tuple

import numpy as np


def _safe_stats(values: List[float]) -> tuple[float, float, float, float]:
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.array(values, dtype=np.float64)
    return float(arr.mean()), float(arr.std(ddof=0)), float(arr.max()), float(arr.min())


def _safe_min(values: List[float]) -> float:
    return float(min(values)) if values else 0.0


def _safe_max(values: List[float]) -> float:
    return float(max(values)) if values else 0.0


def _rate(count: float, duration_s: float) -> float:
    if duration_s <= 0:
        return 0.0
    return float(count) / float(duration_s)


@dataclass
class FlowFeatureInputs:
    duration_ms: float
    fwd_pkt_lens: List[int]
    bwd_pkt_lens: List[int]
    all_pkt_lens: List[int]
    fwd_iats: List[float]
    bwd_iats: List[float]
    flow_iats: List[float]
    fwd_psh: int
    bwd_psh: int
    fwd_urg: int
    bwd_urg: int
    fwd_hdr_len: int
    bwd_hdr_len: int
    fin: int
    syn: int
    rst: int
    ack: int


def compute_features_44(x: FlowFeatureInputs) -> dict[str, float]:
    dur_s = float(x.duration_ms) / 1000.0

    fwd_mean, fwd_std, fwd_max, fwd_min = _safe_stats([float(v) for v in x.fwd_pkt_lens])
    bwd_mean, bwd_std, bwd_max, bwd_min = _safe_stats([float(v) for v in x.bwd_pkt_lens])

    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _safe_stats(x.flow_iats)
    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _safe_stats(x.fwd_iats)
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _safe_stats(x.bwd_iats)

    pkt_len_mean, pkt_len_std, pkt_len_max, pkt_len_min = _safe_stats([float(v) for v in x.all_pkt_lens])
    pkt_len_var = float(pkt_len_std * pkt_len_std)

    tot_fwd_pkts = float(len(x.fwd_pkt_lens))
    tot_bwd_pkts = float(len(x.bwd_pkt_lens))
    tot_pkts = tot_fwd_pkts + tot_bwd_pkts
    totlen_fwd = float(sum(x.fwd_pkt_lens))
    totlen_bwd = float(sum(x.bwd_pkt_lens))
    tot_bytes = totlen_fwd + totlen_bwd

    return {
        "flow_duration_ms": float(x.duration_ms),
        "tot_fwd_pkts": tot_fwd_pkts,
        "tot_bwd_pkts": tot_bwd_pkts,
        "totlen_fwd_pkts": totlen_fwd,
        "totlen_bwd_pkts": totlen_bwd,
        "fwd_pkt_len_max": float(fwd_max),
        "fwd_pkt_len_min": float(fwd_min),
        "fwd_pkt_len_mean": float(fwd_mean),
        "fwd_pkt_len_std": float(fwd_std),
        "bwd_pkt_len_max": float(bwd_max),
        "bwd_pkt_len_min": float(bwd_min),
        "bwd_pkt_len_mean": float(bwd_mean),
        "bwd_pkt_len_std": float(bwd_std),
        "flow_byts_s": _rate(tot_bytes, dur_s),
        "flow_pkts_s": _rate(tot_pkts, dur_s),
        "flow_iat_mean": float(flow_iat_mean),
        "flow_iat_std": float(flow_iat_std),
        "flow_iat_max": float(flow_iat_max),
        "flow_iat_min": float(flow_iat_min),
        "fwd_iat_total": float(sum(x.fwd_iats)),
        "fwd_iat_mean": float(fwd_iat_mean),
        "fwd_iat_std": float(fwd_iat_std),
        "fwd_iat_max": float(fwd_iat_max),
        "fwd_iat_min": float(fwd_iat_min),
        "bwd_iat_total": float(sum(x.bwd_iats)),
        "bwd_iat_mean": float(bwd_iat_mean),
        "bwd_iat_std": float(bwd_iat_std),
        "bwd_iat_max": float(bwd_iat_max),
        "bwd_iat_min": float(bwd_iat_min),
        "fwd_psh_flags": float(x.fwd_psh),
        "bwd_psh_flags": float(x.bwd_psh),
        "fwd_urg_flags": float(x.fwd_urg),
        "bwd_urg_flags": float(x.bwd_urg),
        "fwd_header_len": float(x.fwd_hdr_len),
        "bwd_header_len": float(x.bwd_hdr_len),
        "fwd_pkts_s": _rate(tot_fwd_pkts, dur_s),
        "bwd_pkts_s": _rate(tot_bwd_pkts, dur_s),
        "pkt_len_min": float(pkt_len_min),
        "pkt_len_max": float(pkt_len_max),
        "pkt_len_mean": float(pkt_len_mean),
        "pkt_len_std": float(pkt_len_std),
        "fin_flag_cnt": float(x.fin),
        "syn_flag_cnt": float(x.syn),
        "rst_flag_cnt": float(x.rst),
        "ack_flag_cnt": float(x.ack),
        "_pkt_len_var": pkt_len_var,
    }
