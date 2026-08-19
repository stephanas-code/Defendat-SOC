from __future__ import annotations

import gzip
import json
from typing import Any, Dict

from kafka import KafkaProducer

from sensor.config import settings


class FlowProducer:
    def __init__(self) -> None:
        self._producer = KafkaProducer(bootstrap_servers=settings.kafka_brokers.split(","))

    def send_flow(self, record: Dict[str, Any]) -> None:
        payload = json.dumps(record).encode("utf-8")
        if settings.sensor_compress_gzip:
            payload = gzip.compress(payload)
        self._producer.send(settings.kafka_topic_flows, payload)

    def flush(self) -> None:
        self._producer.flush(timeout=2)
