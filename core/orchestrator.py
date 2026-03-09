"""
Immune Response Orchestrator — the central nervous system.
Subscribes to the Redis threat channel, enriches events with detector analysis,
then runs each threat through a LangGraph StateGraph immune response pipeline.

Graph: sentinel → investigator → (conditional) → [healer →] [hunter →] memory_agent
"""
import asyncio
import json
import time
from datetime import datetime
from typing import Optional

import redis.asyncio as aioredis
from langgraph.graph import StateGraph, END

from agents.base import ImmuneState, initial_state
from agents.sentinel import sentinel_node
from agents.investigator import investigator_node
from agents.healer import healer_node
from agents.hunter import hunter_node
from agents.memory_agent import memory_agent_node
from core.detector.signatures import get_matcher
from config.settings import settings
from config.logging_config import setup_logging
from memory import store

logger = setup_logging("orchestrator")

_active_responses: dict[str, dict] = {}


# ─────────────────────────────────────────────
# Routing logic
# ─────────────────────────────────────────────

def _needs_healing(state: ImmuneState) -> bool:
    return state.get("requires_healing", True) or state.get("attack_type") in ("sql_injection", "file_injection")


def _needs_hunting(state: ImmuneState) -> bool:
    return state.get("requires_hunting", False) or state.get("attack_type") in (
        "port_scan", "sql_injection", "file_injection"
    )


def _route_after_investigator(state: ImmuneState) -> str:
    """Conditional edge: decide which node runs after the investigator."""
    if _needs_healing(state):
        return "healer"
    if _needs_hunting(state):
        return "hunter"
    return "memory_agent"


def _route_after_healer(state: ImmuneState) -> str:
    """Conditional edge: after healing, only hunt if needed."""
    if _needs_hunting(state):
        return "hunter"
    return "memory_agent"


# ─────────────────────────────────────────────
# LangGraph pipeline
# ─────────────────────────────────────────────

def _build_graph() -> StateGraph:
    graph = StateGraph(ImmuneState)

    graph.add_node("sentinel", sentinel_node)
    graph.add_node("investigator", investigator_node)
    graph.add_node("healer", healer_node)
    graph.add_node("hunter", hunter_node)
    graph.add_node("memory_agent", memory_agent_node)

    graph.set_entry_point("sentinel")
    graph.add_edge("sentinel", "investigator")
    graph.add_conditional_edges(
        "investigator",
        _route_after_investigator,
        {"healer": "healer", "hunter": "hunter", "memory_agent": "memory_agent"},
    )
    graph.add_conditional_edges(
        "healer",
        _route_after_healer,
        {"hunter": "hunter", "memory_agent": "memory_agent"},
    )
    graph.add_edge("hunter", "memory_agent")
    graph.add_edge("memory_agent", END)

    return graph.compile()


_immune_graph = _build_graph()


# ─────────────────────────────────────────────
# Threat processor
# ─────────────────────────────────────────────

async def process_threat(event: dict):
    threat_id = f"{event.get('event_type', 'unknown')}_{int(time.time())}"
    _active_responses[threat_id] = {
        "started_at": datetime.utcnow().isoformat(),
        "status": "processing",
        "event": event,
    }

    try:
        # Enrich with signature matching
        matcher = get_matcher()
        enriched = await matcher.classify_event(event)

        # Store initial threat record
        db_event = await store.record_threat_event({
            "attack_type": enriched.get("matched_signature_type") or enriched.get("event_type", "unknown"),
            "attack_vector": enriched.get("target_endpoint"),
            "severity": enriched.get("severity", "medium"),
            "source_ip": enriched.get("source_ip"),
            "source_port": None,
            "target_endpoint": enriched.get("target_endpoint"),
            "raw_event": enriched,
            "payload_sample": (enriched.get("payload_sample") or "")[:500],
            "confidence_score": enriched.get("final_confidence", 0.5),
        })

        state = initial_state(enriched)
        state["event_id"] = db_event.id

        logger.info(
            f"[Orchestrator] Immune response #{db_event.id} — "
            f"{enriched.get('event_type')} | known={enriched.get('known_attack')}"
        )

        final_state = await _immune_graph.ainvoke(state)

        _active_responses[threat_id]["status"] = "resolved"
        _active_responses[threat_id]["event_id"] = db_event.id
        _active_responses[threat_id]["final_status"] = final_state.get("final_status", "resolved")
        _active_responses[threat_id]["response_time"] = round(
            time.time() - state["response_start_time"], 2
        )

        logger.info(
            f"[Orchestrator] Threat #{db_event.id} resolved in "
            f"{_active_responses[threat_id]['response_time']}s"
        )

    except Exception as e:
        logger.error(f"[Orchestrator] Error processing threat: {e}", exc_info=True)
        _active_responses[threat_id]["status"] = "error"
        _active_responses[threat_id]["error"] = str(e)
    finally:
        if len(_active_responses) > 100:
            oldest = next(iter(_active_responses))
            del _active_responses[oldest]


def get_active_responses() -> dict:
    return dict(_active_responses)


# ─────────────────────────────────────────────
# Redis subscriber loop
# ─────────────────────────────────────────────

async def run_orchestrator():
    await store.init_db()
    logger.info("[Orchestrator] Database initialized")

    redis_client = None
    try:
        redis_client = await aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=3,
        )
        await redis_client.ping()
        logger.info(f"[Orchestrator] Connected to Redis at {settings.redis_url}")
        await _redis_loop(redis_client)
    except Exception as e:
        logger.warning(f"[Orchestrator] Redis unavailable ({e}) — starting demo mode")
        await _demo_mode()
    finally:
        if redis_client:
            await redis_client.aclose()


async def _redis_loop(redis_client: aioredis.Redis):
    from core.sensors.base import THREAT_CHANNEL
    from core.sensors.log_sensor import LogSensor
    from core.sensors.network_sensor import NetworkSensor
    from core.sensors.db_sensor import DBSensor

    log_sensor = LogSensor()
    net_sensor = NetworkSensor()
    db_sensor = DBSensor()

    sensor_tasks = [
        asyncio.create_task(log_sensor.start()),
        asyncio.create_task(net_sensor.start()),
        asyncio.create_task(db_sensor.start()),
    ]
    logger.info("[Orchestrator] All sensors started")

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(THREAT_CHANNEL)
    logger.info(f"[Orchestrator] Subscribed to {THREAT_CHANNEL}")

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                event = json.loads(message["data"])
                asyncio.create_task(process_threat(event))
            except json.JSONDecodeError as e:
                logger.error(f"[Orchestrator] Invalid event JSON: {e}")
    finally:
        for task in sensor_tasks:
            task.cancel()
        await pubsub.unsubscribe(THREAT_CHANNEL)


# ─────────────────────────────────────────────
# Demo mode (no Redis)
# ─────────────────────────────────────────────

DEMO_EVENTS = [
    {
        "source": "demo", "event_type": "sql_injection", "source_ip": "10.0.1.42",
        "target_endpoint": "/login", "severity": "high",
        "payload_sample": "' OR 1=1--", "confidence": 0.92,
    },
    {
        "source": "demo", "event_type": "brute_force", "source_ip": "10.0.2.88",
        "target_endpoint": "/login", "severity": "high",
        "payload_sample": "30 failed login attempts in 60s", "confidence": 0.88,
    },
    {
        "source": "demo", "event_type": "port_scan", "source_ip": "10.0.3.15",
        "target_endpoint": "multiple", "severity": "medium",
        "payload_sample": "Scanned 25 endpoints in 8s", "confidence": 0.80,
    },
    {
        "source": "demo", "event_type": "file_injection", "source_ip": "10.0.4.200",
        "target_endpoint": "/upload", "severity": "critical",
        "payload_sample": "<?php system($_GET['cmd']); ?>", "confidence": 0.95,
    },
    {
        "source": "demo", "event_type": "ddos", "source_ip": "10.0.5.77",
        "target_endpoint": "/api/users", "severity": "high",
        "payload_sample": "80 req/s from single IP", "confidence": 0.75,
    },
]


async def _demo_mode():
    logger.info("[Orchestrator] DEMO MODE — generating synthetic threats every 12s")
    i = 0
    while True:
        event = dict(DEMO_EVENTS[i % len(DEMO_EVENTS)])
        event["timestamp"] = datetime.utcnow().isoformat()
        event["raw_data"] = {}
        logger.info(f"[Demo] Firing synthetic {event['event_type']} event")
        await process_threat(event)
        i += 1
        await asyncio.sleep(12)


if __name__ == "__main__":
    asyncio.run(run_orchestrator())
