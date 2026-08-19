from __future__ import annotations

import redis

from app.config import settings


class AlertDeduplicator:
    def __init__(self) -> None:
        self._r = redis.Redis(host=settings.redis_host, port=settings.redis_port, decode_responses=True)

    def should_emit(self, key: str) -> bool:
        # set if not exists
        ok = self._r.set(name=key, value="1", nx=True, ex=settings.alert_dedup_ttl_seconds)
        return bool(ok)
