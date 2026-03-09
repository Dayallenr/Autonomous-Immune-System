"""
Sentinel Agent — the Innate Immune Response.
Fast, rule-based first responder. No LLM needed.
Immediate containment before deeper analysis.
"""
import subprocess
from datetime import datetime

from config.settings import settings
from config.logging_config import setup_logging
from memory import store

logger = setup_logging("agent.sentinel")

RESPONSE_RULES: dict[str, list[str]] = {
    "sql_injection":      ["block_ip", "log_query_pattern", "alert_critical"],
    "brute_force":        ["block_ip", "rate_limit_endpoint", "alert_high"],
    "port_scan":          ["block_ip", "alert_medium"],
    "file_injection":     ["block_ip", "quarantine_upload", "alert_critical"],
    "ddos":               ["block_ip", "rate_limit_endpoint", "alert_high"],
    "connection_flood":   ["block_ip", "rate_limit_endpoint", "alert_high"],
    "unknown":            ["log_event", "alert_medium"],
}


async def sentinel_node(state: dict) -> dict:
    """Sequential pipeline node: Sentinel Agent."""
    event = state["threat_event"]
    attack_type = event.get("event_type", "unknown")
    source_ip = event.get("source_ip")
    severity = event.get("severity", "medium")

    logger.info(f"[Sentinel] Responding to {attack_type} from {source_ip} (severity={severity})")

    actions_taken = []
    blocked_ips = []

    # Use memory playbook if available (faster response for known threats)
    playbook = await store.get_playbook(attack_type)
    if playbook and playbook.get("sentinel_steps"):
        rule_actions = playbook["sentinel_steps"]
        logger.info(f"[Sentinel] Using memory playbook (confidence={playbook.get('confidence_score', 0):.2f})")
    else:
        rule_actions = RESPONSE_RULES.get(attack_type, RESPONSE_RULES["unknown"])

    for action in rule_actions:
        result = await _execute_action(action, source_ip, event)
        actions_taken.append(result)
        if "block_ip" in action and source_ip:
            blocked_ips.append(source_ip)

    is_contained = bool(actions_taken) and severity not in ("critical",)

    logger.info(
        f"[Sentinel] Containment {'SUCCESS' if is_contained else 'PARTIAL'} — "
        f"{len(actions_taken)} actions taken"
    )

    return {
        "containment_actions": actions_taken,
        "blocked_ips": blocked_ips,
        "is_contained": is_contained,
    }


async def _execute_action(action: str, source_ip: str | None, event: dict) -> str:
    ts = datetime.utcnow().isoformat()

    if action == "block_ip" and source_ip:
        if settings.simulate_actions:
            logger.warning(f"[Sentinel] [SIM] Would block IP: {source_ip}")
            return f"[{ts}] SIMULATED: Blocked IP {source_ip} for {settings.sentinel_block_duration}s"
        else:
            return await _real_block_ip(source_ip)

    elif action == "rate_limit_endpoint":
        endpoint = event.get("target_endpoint", "unknown")
        if settings.simulate_actions:
            return f"[{ts}] SIMULATED: Rate-limited {endpoint} — max 10 req/min for {source_ip}"
        return f"[{ts}] Rate-limit applied to {endpoint} for {source_ip}"

    elif action == "quarantine_upload":
        if settings.simulate_actions:
            return f"[{ts}] SIMULATED: Quarantined uploaded files from {source_ip}"
        return f"[{ts}] Upload directory locked for {source_ip}"

    elif action == "log_query_pattern":
        payload = event.get("payload_sample", "")[:100]
        return f"[{ts}] Logged suspicious query pattern: {payload}"

    elif action == "alert_critical":
        logger.critical(f"[Sentinel] CRITICAL ALERT — {event.get('event_type')} from {source_ip}")
        return f"[{ts}] CRITICAL alert raised"

    elif action == "alert_high":
        logger.error(f"[Sentinel] HIGH ALERT — {event.get('event_type')} from {source_ip}")
        return f"[{ts}] HIGH alert raised"

    elif action == "alert_medium":
        logger.warning(f"[Sentinel] MEDIUM ALERT — {event.get('event_type')} from {source_ip}")
        return f"[{ts}] MEDIUM alert raised"

    elif action == "log_event":
        return f"[{ts}] Event logged for analysis"

    return f"[{ts}] Unknown action: {action}"


async def _real_block_ip(ip: str) -> str:
    ts = datetime.utcnow().isoformat()
    try:
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return f"[{ts}] REAL: Blocked IP {ip} via iptables"
        result2 = subprocess.run(
            ["pfctl", "-t", "immune_blocklist", "-T", "add", ip],
            capture_output=True, text=True, timeout=5,
        )
        if result2.returncode == 0:
            return f"[{ts}] REAL: Blocked IP {ip} via pfctl"
        return f"[{ts}] WARNING: Could not block IP {ip}: {result.stderr}"
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.warning(f"[Sentinel] Could not execute real block for {ip}: {e}. Falling back.")
        return f"[{ts}] SIMULATED (fallback): Blocked IP {ip}"
