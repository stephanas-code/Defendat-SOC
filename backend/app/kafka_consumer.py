from __future__ import annotations

import gzip
import json
import logging
import threading
import time
from datetime import datetime
from typing import Callable, Optional

from kafka import KafkaConsumer

from app.config import settings
from app.schemas import FlowRecord

logger = logging.getLogger(__name__)


def _parse_flow_message(raw: bytes) -> FlowRecord:
    try:
        # sensor can optionally gzip payload
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
    except Exception:
        pass

    obj = json.loads(raw.decode("utf-8"))

    # datetime fields are ISO strings
    obj["first_seen"] = datetime.fromisoformat(obj["first_seen"])
    obj["last_seen"] = datetime.fromisoformat(obj["last_seen"])
    return FlowRecord(**obj)


class FlowConsumer(threading.Thread):
    def __init__(self, on_flow: Callable[[FlowRecord], None]) -> None:
        super().__init__(daemon=True)
        self._on_flow = on_flow
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        if not settings.kafka_brokers or settings.kafka_brokers.lower() in {"disabled", "none", "off"}:
            logger.info("kafka_consumer_disabled")
            return
        while not self._stop.is_set():
            try:
                consumer = KafkaConsumer(
                    settings.kafka_topic_flows,
                    bootstrap_servers=settings.kafka_brokers.split(","),
                    group_id=settings.kafka_group_id,
                    enable_auto_commit=True,
                    auto_offset_reset="latest",
                    consumer_timeout_ms=1000,
                )
                logger.info("kafka_consumer_started")

                for msg in consumer:
                    if self._stop.is_set():
                        break
                    try:
                        flow = _parse_flow_message(msg.value)
                        self._on_flow(flow)
                    except Exception:
                        logger.exception("flow_parse_or_handle_failed")

                consumer.close()
            except Exception:
                logger.exception("kafka_consumer_connect_failed")
                time.sleep(2)
