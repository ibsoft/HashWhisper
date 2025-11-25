import json
import queue
import threading
import time
from datetime import datetime, timedelta
from typing import Dict

from flask import Response, current_app, stream_with_context

try:
    import redis  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    redis = None


class BasePresenceBus:
    def publish(self, user_id: int, status: str, typing: bool = False):  # pragma: no cover - interface
        raise NotImplementedError

    def stream(self):  # pragma: no cover - interface
        raise NotImplementedError


class InMemoryPresenceBus(BasePresenceBus):
    def __init__(self, ttl: int = 30):
        self.ttl = ttl
        self.status: Dict[int, dict] = {}
        self.listeners: list[queue.Queue] = []
        self.lock = threading.Lock()

    def publish(self, user_id: int, status: str, typing: bool = False):
        payload = {
            "user_id": user_id,
            "status": status,
            "typing": typing,
            "at": datetime.utcnow().isoformat(),
        }
        with self.lock:
            self.status[user_id] = payload
            for listener in list(self.listeners):
                try:
                    listener.put_nowait(payload)
                except queue.Full:
                    continue

    def subscribe(self):
        q: queue.Queue = queue.Queue(maxsize=100)
        with self.lock:
            self.listeners.append(q)
        return q

    def cleanup(self):
        cutoff = datetime.utcnow() - timedelta(seconds=self.ttl)
        with self.lock:
            expired = [uid for uid, data in self.status.items() if datetime.fromisoformat(data["at"]) < cutoff]
            for uid in expired:
                del self.status[uid]

    def stream(self):
        q = self.subscribe()

        def event_stream():
            heartbeat = time.time()
            while True:
                try:
                    payload = q.get(timeout=5)
                    yield f"data: {json.dumps(payload)}\n\n"
                except queue.Empty:
                    pass
                if time.time() - heartbeat > 10:
                    yield "data: {\"type\": \"ping\"}\n\n"
                    heartbeat = time.time()

        return event_stream()


class RedisPresenceBus(BasePresenceBus):
    def __init__(self, url: str, ttl: int = 30, channel: str = "hw:presence"):
        if not redis:
            raise RuntimeError("redis dependency not installed")
        self.redis = redis.Redis.from_url(url)
        self.ttl = ttl
        self.channel = channel
        self.hash_key = f"{channel}:status"

    def publish(self, user_id: int, status: str, typing: bool = False):
        payload = {
            "user_id": user_id,
            "status": status,
            "typing": typing,
            "at": datetime.utcnow().isoformat(),
        }
        data = json.dumps(payload)
        self.redis.hset(self.hash_key, user_id, data)
        self.redis.expire(self.hash_key, self.ttl * 2)
        self.redis.publish(self.channel, data)

    def stream(self):
        pubsub = self.redis.pubsub(ignore_subscribe_messages=True)
        pubsub.subscribe(self.channel)

        def event_stream():
            heartbeat = time.time()
            # Send current presence snapshot
            snapshot = self.redis.hvals(self.hash_key) or []
            for val in snapshot:
                try:
                    yield f"data: {val.decode()}\n\n"
                except Exception:
                    continue
            while True:
                msg = pubsub.get_message(timeout=1)
                if msg and msg.get("type") == "message":
                    try:
                        payload = msg.get("data", b"")
                        if isinstance(payload, bytes):
                            payload = payload.decode()
                        yield f"data: {payload}\n\n"
                    except Exception:
                        continue
                if time.time() - heartbeat > 10:
                    yield "data: {\"type\": \"ping\"}\n\n"
                    heartbeat = time.time()

        return event_stream()


def create_presence_bus(app) -> BasePresenceBus:
    url = app.config.get("REDIS_URL")
    ttl = app.config.get("PRESENCE_BROADCAST_TTL", 30)
    if url:
        if not redis:
            app.logger.warning("REDIS_URL set but redis package missing; falling back to in-memory presence")
        else:
            return RedisPresenceBus(url, ttl=ttl)
    return InMemoryPresenceBus(ttl=ttl)


def get_presence_bus():
    bus = current_app.extensions.get("presence_bus")
    if not bus:
        bus = InMemoryPresenceBus(ttl=current_app.config.get("PRESENCE_BROADCAST_TTL", 30))
        current_app.extensions["presence_bus"] = bus
    return bus


def sse_stream(bus: BasePresenceBus):
    return Response(stream_with_context(bus.stream()), mimetype="text/event-stream")
