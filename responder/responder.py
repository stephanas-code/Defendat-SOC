from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone

from kafka import KafkaConsumer
from pythonjsonlogger import jsonlogger


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

IDP_ENABLED = os.getenv("IDP_ENABLED", "false").lower() == "true"
IDP_BLOCK_SECONDS = int(os.getenv("IDP_BLOCK_SECONDS", "600"))
IDP_MAX_BLOCKS = int(os.getenv("IDP_MAX_BLOCKS", "50"))
IDP_CHAIN = os.getenv("IDP_CHAIN", "AI_IDS_BLOCK")


def ensure_chain() -> None:
    subprocess.run(["iptables", "-N", IDP_CHAIN], check=False)
    # ensure chain is referenced from INPUT once
    subprocess.run(["iptables", "-C", "INPUT", "-j", IDP_CHAIN], check=False)
    if subprocess.run(["iptables", "-C", "INPUT", "-j", IDP_CHAIN]).returncode != 0:
        subprocess.run(["iptables", "-I", "INPUT", "-j", IDP_CHAIN], check=False)


def block_ip(ip: str) -> None:
    # best-effort; duplicates ignored
    subprocess.run(["iptables", "-C", IDP_CHAIN, "-s", ip, "-j", "DROP"], check=False)
    if subprocess.run(["iptables", "-C", IDP_CHAIN, "-s", ip, "-j", "DROP"]).returncode != 0:
        subprocess.run(["iptables", "-I", IDP_CHAIN, "-s", ip, "-j", "DROP"], check=False)


def main() -> None:
    consumer = KafkaConsumer(
        KAFKA_TOPIC_ALERTS,
        bootstrap_servers=KAFKA_BROKERS.split(","),
        group_id=KAFKA_GROUP_ID,
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )

    blocked = []  # list of (ip, unblock_epoch)

    if IDP_ENABLED:
        ensure_chain()
        logger.info("idp_enabled")
    else:
        logger.info("idp_disabled")

    for msg in consumer:
        now = time.time()
        # cleanup expired blocks
        if IDP_ENABLED and blocked:
            still = []
            for ip, until in blocked:
                if now >= until:
                    subprocess.run(["iptables", "-D", IDP_CHAIN, "-s", ip, "-j", "DROP"], check=False)
                else:
                    still.append((ip, until))
            blocked = still

        alert = json.loads(msg.value.decode("utf-8"))
        src_ip = alert.get("src_ip")
        severity = (alert.get("severity") or "").lower()

        if not src_ip:
            continue

        if not IDP_ENABLED:
            continue

        # conservative: only block critical/high
        if severity not in {"critical", "high"}:
            continue

        if len(blocked) >= IDP_MAX_BLOCKS:
            logger.warning("idp_max_blocks_reached")
            continue

        block_ip(src_ip)
        blocked.append((src_ip, now + IDP_BLOCK_SECONDS))
        logger.info("ip_blocked", extra={"src_ip": src_ip, "severity": severity})


if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception:
            logger.exception("responder_crashed")
            time.sleep(2)
