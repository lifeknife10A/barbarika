"""In-process pub/sub so the SSE endpoint can push live events + incidents.

The sync /ingest handler runs in a worker thread; subscribers live on the event
loop. Publishing hops threads via loop.call_soon_threadsafe.
"""

from __future__ import annotations

import asyncio
from typing import Any


class Broadcaster:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def publish(self, message: dict[str, Any]) -> None:
        """Thread-safe fan-out to all current subscribers (drops if a queue is full)."""
        loop = self._loop
        if loop is None:
            return
        for q in list(self._subscribers):
            def _put(q=q, message=message) -> None:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    pass
            loop.call_soon_threadsafe(_put)
