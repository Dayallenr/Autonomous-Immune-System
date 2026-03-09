"""
Base state and shared types for all immune system agents.
The ImmuneState dict flows through the sequential pipeline,
accumulating data from each agent as the response progresses.
"""
import time
from typing import Any, Optional


def initial_state(threat_event: dict) -> dict:
    """Create a fresh state for a new threat."""
    return {
        # ── Input ─────────────────────────────────────
        "threat_event": threat_event,
        "event_id": None,

        # ── Sentinel ──────────────────────────────────
        "containment_actions": [],
        "blocked_ips": [],
        "is_contained": False,

        # ── Investigator ──────────────────────────────
        "attack_type": threat_event.get("event_type", "unknown"),
        "attack_severity": threat_event.get("severity", "medium"),
        "attack_vector": threat_event.get("target_endpoint", "unknown"),
        "iocs": [],
        "recommended_actions": [],
        "analysis_summary": "",
        "requires_healing": True,
        "requires_hunting": True,

        # ── Healer ────────────────────────────────────
        "repair_actions": [],
        "repair_status": "pending",

        # ── Hunter ────────────────────────────────────
        "additional_threats": [],
        "related_iocs": [],
        "hunt_summary": "",

        # ── Memory Agent ──────────────────────────────
        "memory_record_id": None,
        "adaptive_rules_created": [],
        "playbook_updated": False,

        # ── Metadata ──────────────────────────────────
        "response_start_time": time.time(),
        "final_status": "in_progress",
    }


# Type alias for clarity
ImmuneState = dict
