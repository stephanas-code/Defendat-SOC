"""Replay the provided 'Global_Cybersecurity_Threats_2015-2024.csv' into the dashboard.

This dataset is NOT network-flow telemetry. It cannot train the 44-feature NIDS models.
Instead, use it to demo your SOC dashboard + alert pipeline.

Usage (example):

  python scripts/replay_global_threats_csv.py \
    --csv dataset/Global_Cybersecurity_Threats_2015-2024.csv \
    --backend http://localhost:8000 \
    --rate 25
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from uuid import uuid4


def severity_for_attack(attack_type: str, loss_million: float) -> str:
    a = (attack_type or "").lower()
    if "ddos" in a or "ransom" in a:
        return "critical" if loss_million >= 50 else "high"
    if "sql" in a or "injection" in a:
        return "high" if loss_million >= 50 else "medium"
    if "phish" in a or "malware" in a or "mitm" in a:
        return "medium" if loss_million >= 50 else "low"
    return "low"


def stable_ip(seed: str, base: str = "10") -> str:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    a = int(h[0])
    b = int(h[1])
    c = int(h[2])
    # 10.x.y.z private range, avoid .0/.255
    return f"{base}.{a}.{b}.{(c % 254) + 1}"


def post_json(url: str, obj: dict) -> None:
    data = json.dumps(obj, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--backend", default="http://localhost:8000")
    ap.add_argument("--rate", type=float, default=20.0, help="alerts per second")
    args = ap.parse_args()

    ingest_url = args.backend.rstrip("/") + "/ingest/alert"
    delay = 1.0 / args.rate if args.rate > 0 else 0.0

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            year = int(row.get("Year") or 2024)
            attack_type = row.get("Attack Type") or "Unknown"
            industry = row.get("Target Industry") or "Unknown"
            country = row.get("Country") or "Unknown"
            source = row.get("Attack Source") or "Unknown"
            vuln = row.get("Security Vulnerability Type") or "Unknown"
            defense = row.get("Defense Mechanism Used") or "Unknown"
            try:
                loss = float(row.get("Financial Loss (in Million $)") or 0.0)
            except Exception:
                loss = 0.0

            src_ip = stable_ip(f"{country}:{source}:{attack_type}")
            dst_ip = stable_ip(f"{country}:{industry}", base="192")

            sev = severity_for_attack(attack_type, loss)
            created_at = datetime(year, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

            alert = {
                "alert_id": str(uuid4()),
                "created_at": created_at.isoformat(),
                "flow_id": str(uuid4()),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "DEMO",
                "severity": sev,
                "label": attack_type,
                "confidence": 0.8,
                "signals": {
                    "dataset": "Global_Cybersecurity_Threats_2015-2024",
                    "country": country,
                    "target_industry": industry,
                    "attack_source": source,
                    "vulnerability": vuln,
                    "defense": defense,
                    "financial_loss_million": loss,
                    "affected_users": row.get("Number of Affected Users"),
                    "resolution_time_hours": row.get("Incident Resolution Time (in Hours)"),
                },
                "geoip": None,
            }

            post_json(ingest_url, alert)
            if delay:
                time.sleep(delay)


if __name__ == "__main__":
    main()
