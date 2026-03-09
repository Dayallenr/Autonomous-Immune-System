"""
Memory Agent — B-Cell / Antibody Production.
The final step in the immune response: writes everything learned from this
incident into the immunological memory so future attacks are handled faster.
"""
import time
from datetime import datetime

from config.logging_config import setup_logging
from memory import store
from memory.immunization import immunize_from_event

logger = setup_logging("agent.memory")


async def memory_agent_node(state: dict) -> dict:
    """Sequential pipeline node: Memory Agent — the final learning step."""
    attack_type = state["attack_type"]
    severity_str = state["attack_severity"]
    event = state["threat_event"]
    source_ip = event.get("source_ip")
    payload = event.get("payload_sample", "")
    event_id = state.get("event_id")

    logger.info(f"[Memory] Writing immunological memory for {attack_type} ({severity_str})")

    # ── 1. Update threat event record ──────────────
    response_time = time.time() - state["response_start_time"]

    if event_id:
        await store.update_threat_event(
            event_id,
            {
                "status": "resolved",
                "resolved_at": datetime.utcnow(),
                "attack_type": attack_type,
                "severity": severity_str,
                "sentinel_actions": state.get("containment_actions", []),
                "investigator_analysis": state.get("analysis_summary", ""),
                "healer_actions": state.get("repair_actions", []),
                "hunter_findings": state.get("additional_threats", []),
                "was_blocked": bool(state.get("blocked_ips")),
                "response_time_seconds": round(response_time, 2),
            },
        )
        logger.info(f"[Memory] Updated threat event #{event_id}")

    # ── 2. Generate adaptive immunization rules ─────
    rules_created = await immunize_from_event(
        attack_type=attack_type,
        source_ip=source_ip,
        payload_sample=payload,
        event_id=event_id,
    )

    # ── 3. Write / reinforce response playbook ───────
    playbook_data = {
        "sentinel_steps": _build_sentinel_steps(attack_type),
        "healer_steps": state.get("repair_actions", [])[:5],
        "hunter_ioc_patterns": state.get("related_iocs", [])[:5],
        "investigator_prompt_hints": state.get("analysis_summary", "")[:500],
    }

    success = state.get("repair_status") in ("success", "skipped")
    playbook = await store.upsert_playbook(
        attack_type=attack_type,
        severity=severity_str,
        playbook_data=playbook_data,
        success=success,
        response_time=response_time,
    )

    logger.info(
        f"[Memory] Playbook updated — attack={attack_type}, "
        f"confidence={playbook.get('confidence_score', 0):.2f}, "
        f"success_count={playbook.get('success_count', 0)}"
    )

    # ── 4. Log immune memory effect ──────────────────
    sigs = await store.get_signatures_for_type(attack_type)
    if sigs:
        total_hits = sum(s.get("hit_count", 1) for s in sigs)
        if total_hits > 1:
            logger.info(
                f"[Memory] Immune memory effect — {attack_type}: "
                f"{len(sigs)} signatures, {total_hits} total hits, "
                f"detection threshold reduced"
            )

    summary = (
        f"Memory updated: {len(rules_created)} rules created, "
        f"playbook confidence={playbook.get('confidence_score', 0):.2f}"
    )
    logger.info(f"[Memory] {summary}")

    return {
        "memory_record_id": event_id,
        "adaptive_rules_created": rules_created,
        "playbook_updated": True,
        "final_status": "resolved",
    }


def _build_sentinel_steps(attack_type: str) -> list[str]:
    from agents.sentinel import RESPONSE_RULES
    return RESPONSE_RULES.get(attack_type, RESPONSE_RULES["unknown"])
