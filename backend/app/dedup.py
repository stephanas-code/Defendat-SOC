from __future__ import annotations

import logging
import redis

from app.config import settings

logger = logging.getLogger(__name__)


class AlertDeduplicator:
    def __init__(self) -> None:
        self._r = redis.Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)

    def should_emit(self, key: str) -> bool:
        try:
            ok = self._r.set(name=key, value="1", nx=True, ex=settings.alert_dedup_ttl_seconds)
            return bool(ok)
        except Exception:
            # If Redis is temporarily unreachable, fail open so alerts are not dropped
            return True

    def clear(self) -> None:
        try:
            keys = list(self._r.scan_iter(match="dedup:*", count=500))
            if keys:
                self._r.delete(*keys)
        except Exception:
            logger.warning("redis_dedup_clear_failed")
