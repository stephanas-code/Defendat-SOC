"""Replay network flow datasets from artifacts/CSVs for real ML attack detection & IDP validation.

This script extracts the 44 CICFlowMeter-style features from each CSV row using the
exact feature mapping used to train the models and sends real FlowRecord payloads
to POST /ingest/flow so Isolation Forest, XGBoost, LSTM, the Threat Correlation Engine,
and the IDP Responder are genuinely exercised.

Usage:
  python scripts/replay_network_flows.py --csv artifacts/CSVs/ddos_loit.csv --backend http://localhost:8000 --rate 10 --limit 50
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import time
import urllib.request
from datetime import datetime, timezone
from typing import Dict
from uuid import uuid4

CSV_TO_FEATURES = {
    "duration": "flow_duration_ms",
    "packets_count": "tot_fwd_pkts",
    "fwd_packets_count": "tot_fwd_pkts",
    "bwd_packets_count": "tot_bwd_pkts",
    "fwd_total_payload_bytes": "totlen_fwd_pkts",
    "bwd_total_payload_bytes": "totlen_bwd_pkts",
    "fwd_payload_bytes_max": "fwd_pkt_len_max",
    "fwd_payload_bytes_min": "fwd_pkt_len_min",
    "fwd_payload_bytes_mean": "fwd_pkt_len_mean",
    "fwd_payload_bytes_std": "fwd_pkt_len_std",
    "bwd_payload_bytes_max": "bwd_pkt_len_max",
    "bwd_payload_bytes_min": "bwd_pkt_len_min",
    "bwd_payload_bytes_mean": "bwd_pkt_len_mean",
    "bwd_payload_bytes_std": "bwd_pkt_len_std",
    "bytes_rate": "flow_byts_s",
    "packets_rate": "flow_pkts_s",
    "packets_IAT_mean": "flow_iat_mean",
    "packet_IAT_std": "flow_iat_std",
    "packet_IAT_max": "flow_iat_max",
    "packet_IAT_min": "flow_iat_min",
    "fwd_packets_IAT_mean": "fwd_iat_mean",
    "fwd_packets_IAT_std": "fwd_iat_std",
    "fwd_packets_IAT_max": "fwd_iat_max",
    "fwd_packets_IAT_min": "fwd_iat_min",
    "bwd_packets_IAT_mean": "bwd_iat_mean",
    "bwd_packets_IAT_std": "bwd_iat_std",
    "bwd_packets_IAT_max": "bwd_iat_max",
    "bwd_packets_IAT_min": "bwd_iat_min",
    "fwd_packets_rate": "fwd_pkts_s",
    "bwd_packets_rate": "bwd_pkts_s",
    "syn_flag_counts": "syn_flag_cnt",
    "ack_flag_counts": "ack_flag_cnt",
    "rst_flag_counts": "rst_flag_cnt",
    "fin_flag_counts": "fin_flag_cnt",
    "fwd_psh_flag_counts": "fwd_psh_flags",
    "bwd_psh_flag_counts": "bwd_psh_flags",
    "fwd_urg_flag_counts": "fwd_urg_flags",
    "bwd_urg_flag_counts": "bwd_urg_flags",
    "fwd_total_header_bytes": "fwd_header_len",
    "bwd_total_header_bytes": "bwd_header_len",
}

FEATURES_44 = [
    "flow_duration_ms", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "ack_flag_cnt",
]


def extract_44_features(row: Dict[str, str]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for name in FEATURES_44:
        if name in row:
            try:
                v = float(row[name])
                out[name] = 0.0 if (math.isnan(v) or math.isinf(v)) else v
                continue
            except (ValueError, TypeError):
                pass

        val = 0.0
        for csv_col, mapped in CSV_TO_FEATURES.items():
            if mapped == name and csv_col in row:
                try:
                    val = float(row[csv_col])
                    if math.isnan(val) or math.isinf(val):
                        val = 0.0
                    elif "variance" in csv_col.lower() and val > 0:
                        val = math.sqrt(val)
                    break
                except (ValueError, TypeError):
                    pass

        if name == "pkt_len_mean" and val == 0.0:
            try:
                fm = float(row.get("fwd_payload_bytes_mean") or 0.0)
                bm = float(row.get("bwd_payload_bytes_mean") or 0.0)
                if fm or bm:
                    val = (fm + bm) / 2.0
            except (ValueError, TypeError):
                pass

        if name == "pkt_len_max" and val == 0.0:
            try:
                val = max(
                    float(row.get("fwd_payload_bytes_max") or 0.0),
                    float(row.get("bwd_payload_bytes_max") or 0.0),
                )
            except (ValueError, TypeError):
                pass

        out[name] = val
    return out


def post_json(url: str, obj: dict) -> dict:
    data = json.dumps(obj, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description="Replay 44-feature network flow data for real ML attack detection")
    ap.add_argument("--csv", required=True, help="Path to network flow CSV file")
    ap.add_argument("--backend", default="http://localhost:8000", help="Backend URL")
    ap.add_argument("--rate", type=float, default=10.0, help="Flows per second")
    ap.add_argument("--limit", type=int, default=50, help="Max number of flows to replay")
    ap.add_argument("--src-ip", default=None, help="Optional override source IP for testing external attacker IPs")
    ap.add_argument("--shuffle", action="store_true", help="Shuffle the flow order")
    args = ap.parse_args()

    ingest_url = args.backend.rstrip("/") + "/ingest/flow"
    delay = 1.0 / args.rate if args.rate > 0 else 0.0

    flows = []
    with open(args.csv, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append(row)
            if not args.shuffle and args.limit and len(flows) >= args.limit:
                break

    if args.shuffle:
        random.shuffle(flows)
    if args.limit:
        flows = flows[: args.limit]

    print(f"Replaying {len(flows)} 44-feature flows from {args.csv} at {args.rate} flows/sec")
    print(f"Target ML Inference Endpoint: {ingest_url}")
    print("-" * 60)

    success_count = 0
    detected_count = 0
    error_count = 0

    sample_public_ips = ["185.220.101.42", "45.33.32.156", "103.253.41.98", "91.240.118.172", "198.51.100.77"]

    for idx, row in enumerate(flows):
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            src_ip = args.src_ip or row.get("src_ip") or row.get("Src IP") or sample_public_ips[idx % len(sample_public_ips)]
            if src_ip in ("0.0.0.0", ""):
                src_ip = sample_public_ips[idx % len(sample_public_ips)]
            dst_ip = row.get("dst_ip") or row.get("Dst IP") or "10.96.0.10"
            src_port = int(float(row.get("src_port") or row.get("Src Port") or 49152))
            dst_port = int(float(row.get("dst_port") or row.get("Dst Port") or 80))
            protocol = str(row.get("protocol") or row.get("Protocol") or "TCP")

            features_44 = extract_44_features(row)
            flow_payload = {
                "flow_id": str(uuid4()),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "features": features_44,
            }

            res = post_json(ingest_url, flow_payload)
            success_count += 1
            if res.get("detected"):
                detected_count += 1

            if (idx + 1) % 25 == 0 or (idx + 1) == len(flows):
                print(f"Progress: {idx + 1}/{len(flows)} flows evaluated | Alerts triggered: {detected_count}")

            if delay:
                time.sleep(delay)
        except Exception as e:
            error_count += 1
            print(f"Error at flow {idx + 1}: {e}")
            if error_count > 10:
                print("Too many errors, stopping replay")
                break

    print("-" * 60)
    print(f"Replay complete: {success_count} flows processed by ML, {detected_count} threats detected, {error_count} errors")


if __name__ == "__main__":
    main()
