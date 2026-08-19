from __future__ import annotations

import asyncio
from typing import Any, Dict, Set

from fastapi import WebSocket



class WebSocketManager:
    def __init__(self) -> None:
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)

    async def broadcast_json(self, message: Dict[str, Any]) -> None:
        async with self._lock:
            connections = list(self._connections)
        if not connections:
            return

        # fan-out; ignore individual failures
        for ws in connections:
            try:
                await ws.send_json(message)
            except Exception:
                pass


class ThreadsafeBroadcaster:
    def __init__(self, manager: WebSocketManager) -> None:
        self._manager = manager
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def broadcast(self, message: Dict[str, Any]) -> None:
        if not self._loop:
            return
        self._loop.call_soon_threadsafe(asyncio.create_task, self._manager.broadcast_json(message))
