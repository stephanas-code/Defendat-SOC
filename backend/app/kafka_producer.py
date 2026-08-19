from __future__ import annotations

import json
import logging
from typing import Any, Dict

from kafka import KafkaProducer

from app.config import settings

logger = logging.getLogger(__name__)


class AlertProducer:
    def __init__(self) -> None:
        if not settings.kafka_brokers or settings.kafka_brokers.lower() in {"disabled", "none", "off"}:
            self._producer = None
            logger.info("kafka_producer_disabled")
            return
        try:
            self._producer = KafkaProducer(
                bootstrap_servers=settings.kafka_brokers.split(","),
                value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            )
        except Exception:
            logger.exception("kafka_producer_init_failed; continuing without Kafka")
            self._producer = None

    def send_alert(self, alert: Dict[str, Any]) -> None:
        try:
            if not self._producer:
                return
            self._producer.send(settings.kafka_topic_alerts, alert)
            self._producer.flush(timeout=2)
        except Exception:
            logger.exception("kafka_alert_send_failed")
