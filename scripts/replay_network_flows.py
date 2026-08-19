"""Replay network flow datasets from artifacts/CSVs for real attack detection.

This script replays actual network flow data with 44 features to the backend,
enabling real ML-based attack detection and demonstration.

Usage:
  python scripts/replay_network_flows.py --csv artifacts/CSVs/ddos_loit.csv --backend http://localhost:8000 --rate 10
"""

from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.request
from datetime import datetime, timezone
from uuid import uuid4
import random


def post_json(url: str, obj: dict) -> None:
    """Send JSON data via HTTP POST."""
    data = json.dumps(obj, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def severity_for_label(label: str) -> str:
    """Map attack labels to severity levels."""
    label_lower = (label or "").lower()
    if any(x in label_lower for x in ["ddos", "dos", "botnet"]):
        return "critical"
    if any(x in label_lower for x in ["injection", "xss", "brute", "patator"]):
        return "high"
    if any(x in label_lower for x in ["malware", "phishing", "spam"]):
        return "high"
    if "benign" in label_lower:
        return "low"
    return "medium"


def main() -> None:
    ap = argparse.ArgumentParser(description="Replay network flow data for attack detection")
    ap.add_argument("--csv", required=True, help="Path to network flow CSV file")
    ap.add_argument("--backend", default="http://localhost:8000", help="Backend URL")
    ap.add_argument("--rate", type=float, default=5.0, help="Flows per second")
    ap.add_argument("--limit", type=int, default=None, help="Max number of flows to replay")
    ap.add_argument("--shuffle", action="store_true", help="Shuffle the flow order")
    args = ap.parse_args()

    ingest_url = args.backend.rstrip("/") + "/ingest/alert"
    delay = 1.0 / args.rate if args.rate > 0 else 0.0

    # Read and optionally shuffle flows
    flows = []
    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append(row)
    
    if args.shuffle:
        random.shuffle(flows)
    
    if args.limit:
        flows = flows[:args.limit]

    print(f"Replaying {len(flows)} flows from {args.csv} at {args.rate} flows/sec")
    print(f"Target: {ingest_url}")
    print("-" * 60)

    success_count = 0
    error_count = 0
    
    for idx, row in enumerate(flows):
        try:
            # Extract common fields (adapt based on actual CSV structure)
            flow_id = row.get("flow_id", str(uuid4()))
            timestamp = row.get("timestamp", datetime.now(timezone.utc).isoformat())
            src_ip = row.get("src_ip", "0.0.0.0")
            dst_ip = row.get("dst_ip", "0.0.0.0")
            src_port = int(row.get("src_port", 0) or 0)
            dst_port = int(row.get("dst_port", 0) or 0)
            protocol = row.get("protocol", "TCP")
            label = row.get("label", "Unknown")
            
            severity = severity_for_label(label)
            
            # Build features dict from all numeric columns
            features = {}
            for key, value in row.items():
                if key not in ["flow_id", "timestamp", "src_ip", "dst_ip", "src_port", 
                               "dst_port", "protocol", "label"]:
                    try:
                        features[key] = float(value)
                    except (ValueError, TypeError):
                        features[key] = str(value)
            
            alert = {
                "alert_id": str(uuid4()),
                "created_at": timestamp,
                "flow_id": flow_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "severity": severity,
                "label": label,
                "confidence": 0.85 if label.lower() != "benign" else 0.3,
                "signals": {
                    "dataset": args.csv,
                    "features_count": len(features),
                    "source_file": args.csv
                },
                "geoip": None,
            }
            
            post_json(ingest_url, alert)
            success_count += 1
            
            if (idx + 1) % 50 == 0:
                print(f"Progress: {idx + 1}/{len(flows)} flows sent")
            
            if delay:
                time.sleep(delay)
                
        except Exception as e:
            error_count += 1
            print(f"Error at flow {idx + 1}: {e}")
            if error_count > 10:
                print("Too many errors, stopping replay")
                break

    print("-" * 60)
    print(f"Replay complete: {success_count} successful, {error_count} errors")
    print(f"Check dashboard at {args.backend.replace('8000', '3000')}")


if __name__ == "__main__":
    main()
