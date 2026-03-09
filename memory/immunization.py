"""
Immunization — generates adaptive security rules from resolved threat incidents.
"""
import re
from typing import Optional

from config.settings import settings
from config.logging_config import setup_logging
from memory import store

logger = setup_logging("immunization")

IMMUNIZATION_STRATEGIES = {
    "brute_force":    {"rule_type": "rate_limit",    "ttl": 7200},
    "sql_injection":  {"rule_type": "pattern_block", "ttl": None},
    "port_scan":      {"rule_type": "ip_block",      "ttl": 3600},
    "file_injection": {"rule_type": "pattern_block", "ttl": None},
    "ddos":           {"rule_type": "rate_limit",    "ttl": 1800},
}

SQL_INJECTION_PATTERNS = [
    r"('|\")\s*(OR|AND)\s*('|\"|\d)",
    r"UNION\s+SELECT",
    r"DROP\s+TABLE",
    r"--\s*$",
    r"xp_cmdshell",
    r"EXEC\s*\(",
]

FILE_INJECTION_PATTERNS = [
    r"<\s*script",
    r"javascript:",
    r"\.\./\.\.",
    r"(?i)(passwd|shadow|etc/hosts)",
    r"(?i)(cmd\.exe|/bin/sh|/bin/bash)",
]


async def immunize_from_event(
    attack_type: str,
    source_ip: Optional[str],
    payload_sample: Optional[str],
    event_id: Optional[int] = None,
) -> list[str]:
    rules_created = []
    strategy = IMMUNIZATION_STRATEGIES.get(attack_type, {})
    rule_type = strategy.get("rule_type", "ip_block")
    ttl = strategy.get("ttl", settings.sentinel_block_duration)

    if source_ip:
        await store.add_adaptive_rule(
            rule_type=rule_type,
            rule_value=source_ip,
            description=f"Auto-generated from {attack_type} incident",
            source_threat_type=attack_type,
            source_event_id=event_id,
            ttl_seconds=ttl,
        )
        rules_created.append(f"{rule_type}:{source_ip}")
        logger.info(f"[Immunize] Created {rule_type} rule for IP {source_ip}")

    if payload_sample:
        for pattern in _extract_patterns(attack_type, payload_sample):
            sig = await store.add_or_reinforce_signature(
                attack_type=attack_type,
                pattern=pattern,
                pattern_type="regex",
                description=f"Auto-extracted from event {event_id}",
            )
            rules_created.append(f"signature:{attack_type}:{pattern[:40]}")
            logger.info(
                f"[Immunize] Signature for {attack_type} — "
                f"hit_count={sig.get('hit_count', 1)}, "
                f"threshold={sig.get('detection_threshold', 0.7):.2f}"
            )

    return rules_created


def _extract_patterns(attack_type: str, payload: str) -> list[str]:
    if attack_type == "sql_injection":
        return [p for p in SQL_INJECTION_PATTERNS if re.search(p, payload, re.IGNORECASE)]
    elif attack_type == "file_injection":
        return [p for p in FILE_INJECTION_PATTERNS if re.search(p, payload, re.IGNORECASE)]
    return []


async def get_blocked_ips() -> set[str]:
    rules = await store.get_active_rules(rule_type="ip_block")
    rate_rules = await store.get_active_rules(rule_type="rate_limit")
    ips = {r["rule_value"] for r in rules}
    ips.update(r["rule_value"] for r in rate_rules)
    return ips


async def is_payload_blocked(payload: str) -> tuple[bool, str]:
    signatures = await store.get_all_active_signatures()
    for sig in signatures:
        try:
            if re.search(sig["pattern"], payload, re.IGNORECASE):
                return True, sig["pattern"]
        except re.error:
            pass
    return False, ""
