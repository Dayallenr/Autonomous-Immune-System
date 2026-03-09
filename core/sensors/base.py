"""Base sensor class — all sensors inherit from this."""
import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

import redis.asyncio as aioredis

from config.settings import settings
from config.logging_config import setup_logging

THREAT_CHANNEL = "immune:threats"


class ThreatEvent:
    """Standardized threat event emitted by sensors."""

    def __init__(
        self,
        source: str,
        event_type: str,
        source_ip: Optional[str] = None,
        target_endpoint: Optional[str] = None,
        severity: str = "medium",
        payload_sample: Optional[str] = None,
        raw_data: Optional[dict] = None,
        confidence: float = 0.7,
    ):
        self.source = source
        self.event_type = event_type
        self.source_ip = source_ip
        self.target_endpoint = target_endpoint
        self.severity = severity
        self.payload_sample = payload_sample
        self.raw_data = raw_data or {}
        self.confidence = confidence
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "target_endpoint": self.target_endpoint,
            "severity": self.severity,
            "payload_sample": self.payload_sample,
            "raw_data": self.raw_data,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class BaseSensor(ABC):
    """Abstract base for all sensors."""

    def __init__(self, name: str):
        self.name = name
        self.logger = setup_logging(f"sensor.{name}")
        self._redis: Optional[aioredis.Redis] = None
        self._running = False

    async def _get_redis(self) -> Optional[aioredis.Redis]:
        if self._redis is None:
            try:
                self._redis = await aioredis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                )
                await self._redis.ping()
            except Exception as e:
                self.logger.warning(f"Redis unavailable, running in log-only mode: {e}")
                self._redis = None
        return self._redis

    async def emit(self, event: ThreatEvent):
        """Publish threat event to Redis channel and log it."""
        self.logger.warning(
            f"[{self.name.upper()}] THREAT DETECTED — {event.event_type} "
            f"from {event.source_ip} (severity={event.severity}, confidence={event.confidence:.2f})"
        )

        redis = await self._get_redis()
        if redis:
            try:
                await redis.publish(THREAT_CHANNEL, event.to_json())
            except Exception as e:
                self.logger.error(f"Failed to publish to Redis: {e}")

    async def start(self):
        self._running = True
        self.logger.info(f"[{self.name}] Sensor started")
        try:
            await self.run()
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            if self._redis:
                await self._redis.aclose()
            self.logger.info(f"[{self.name}] Sensor stopped")

    def stop(self):
        self._running = False

    @abstractmethod
    async def run(self):
        """Main sensor loop — implemented by each subclass."""
        ...
