"""
Base state and shared types for all immune system agents.
ImmuneState is a LangGraph-compatible TypedDict that flows through the
graph, accumulating data from each node as the response progresses.

List fields use Annotated[list, operator.add] so LangGraph merges
them rather than overwrites when multiple nodes write to the same key.
"""
import operator
import time
from typing import Annotated, Optional
from typing_extensions import TypedDict


class ImmuneState(TypedDict, total=False):
    # ── Input ─────────────────────────────────────
    threat_event: dict
    event_id: Optional[int]

    # ── Sentinel ──────────────────────────────────
    containment_actions: Annotated[list, operator.add]
    blocked_ips: Annotated[list, operator.add]
    is_contained: bool

    # ── Investigator ──────────────────────────────
    attack_type: str
    attack_severity: str
    attack_vector: str
    iocs: Annotated[list, operator.add]
    recommended_actions: Annotated[list, operator.add]
    analysis_summary: str
    requires_healing: bool
    requires_hunting: bool

    # ── Healer ────────────────────────────────────
    repair_actions: Annotated[list, operator.add]
    repair_status: str

    # ── Hunter ────────────────────────────────────
    additional_threats: Annotated[list, operator.add]
    related_iocs: Annotated[list, operator.add]
    hunt_summary: str
    hunt_findings: Annotated[list, operator.add]

    # ── Memory Agent ──────────────────────────────
    memory_record_id: Optional[int]
    adaptive_rules_created: Annotated[list, operator.add]
    playbook_updated: bool

    # ── Metadata ──────────────────────────────────
    response_start_time: float
    final_status: str


def initial_state(threat_event: dict) -> ImmuneState:
    """Create a fresh LangGraph-compatible state for a new threat."""
    return ImmuneState(
        threat_event=threat_event,
        event_id=None,
        containment_actions=[],
        blocked_ips=[],
        is_contained=False,
        attack_type=threat_event.get("event_type", "unknown"),
        attack_severity=threat_event.get("severity", "medium"),
        attack_vector=threat_event.get("target_endpoint", "unknown"),
        iocs=[],
        recommended_actions=[],
        analysis_summary="",
        requires_healing=True,
        requires_hunting=True,
        repair_actions=[],
        repair_status="pending",
        additional_threats=[],
        related_iocs=[],
        hunt_summary="",
        hunt_findings=[],
        memory_record_id=None,
        adaptive_rules_created=[],
        playbook_updated=False,
        response_start_time=time.time(),
        final_status="in_progress",
    )
