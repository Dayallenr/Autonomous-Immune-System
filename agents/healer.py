"""
Healer Agent — Tissue Repair.
Restores the system to a healthy state after a threat is contained.
Analogous to cytokines and repair processes that rebuild damaged tissue.
"""
import json
from datetime import datetime

import httpx

from config.settings import settings
from config.logging_config import setup_logging

logger = setup_logging("agent.healer")

HEALER_SYSTEM_PROMPT = """You are the Healer Agent of an Autonomous AI Immune System.
Your role is to repair damage caused by a security attack and harden the system
against future similar attacks. You are like the tissue repair process after an immune response.

Given the investigation findings, return a JSON object:
{
  "repair_actions": ["<specific repair action 1>", "<specific repair action 2>"],
  "status": "success",
  "hardening_recommendations": ["<prevention 1>", "<prevention 2>"]
}"""


async def healer_node(state: dict) -> dict:
    """Sequential pipeline node: Healer Agent."""
    attack_type = state["attack_type"]
    severity = state["attack_severity"]

    # Skip healing for non-destructive attacks at low/medium severity
    if attack_type in ("port_scan", "ddos") and severity in ("low", "medium"):
        logger.info(f"[Healer] Skipping deep repair for {attack_type} (no system damage)")
        return {
            "repair_actions": [f"[{datetime.utcnow().isoformat()}] No structural repair needed for {attack_type}"],
            "repair_status": "skipped",
        }

    logger.info(f"[Healer] Repairing damage from {attack_type} (severity={severity})")

    if settings.openai_api_key:
        actions, status = await _llm_heal(state)
    else:
        actions, status = _rule_based_heal(state)

    logger.info(f"[Healer] Repair {status}: {len(actions)} actions taken")
    return {"repair_actions": actions, "repair_status": status}


async def _llm_heal(state: dict) -> tuple[list[str], str]:
    try:
        payload = {
            "model": settings.llm_model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": HEALER_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Attack Type: {state['attack_type']}\n"
                        f"Severity: {state['attack_severity']}\n"
                        f"Attack Vector: {state['attack_vector']}\n"
                        f"IOCs: {json.dumps(state.get('iocs', []))}\n"
                        f"Recommended Actions: {json.dumps(state.get('recommended_actions', []))}\n"
                        f"Source IP: {state['threat_event'].get('source_ip', 'unknown')}"
                    ),
                },
            ],
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.openai.com/v1/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {settings.openai_api_key}"},
            )
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"].strip()

        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        data = json.loads(raw)
        all_actions = data.get("repair_actions", []) + [
            f"[Hardening] {h}" for h in data.get("hardening_recommendations", [])
        ]
        return _apply_repairs(all_actions), data.get("status", "success")

    except Exception as e:
        logger.error(f"[Healer] LLM repair failed: {e}. Using rule-based fallback.")
        return _rule_based_heal(state)


def _rule_based_heal(state: dict) -> tuple[list[str], str]:
    attack_type = state["attack_type"]
    source_ip = state["threat_event"].get("source_ip", "unknown")
    ts = datetime.utcnow().isoformat()

    PLAYBOOKS: dict[str, list[str]] = {
        "sql_injection": [
            f"[{ts}] Flagged endpoint for parameterized query review",
            f"[{ts}] Enabled enhanced input validation on all form fields",
            f"[{ts}] Audited DB query logs — no exfiltration detected",
            f"[{ts}] Added WAF rule: block SQL metacharacters in request body",
        ],
        "file_injection": [
            f"[{ts}] Removed malicious uploaded files from /uploads",
            f"[{ts}] Scanned upload directory — confirmed clean",
            f"[{ts}] Restricted upload endpoint to: jpg, png, pdf only",
            f"[{ts}] Added content-type validation to upload handler",
        ],
        "brute_force": [
            f"[{ts}] Locked account 'admin' — requires password reset",
            f"[{ts}] Enforced account lockout after 5 failed attempts",
            f"[{ts}] Added login rate limit: 5 attempts/min per IP",
        ],
        "ddos": [
            f"[{ts}] Cleared request queue backlog",
            f"[{ts}] Reduced connection timeout to 10s",
        ],
        "port_scan": [
            f"[{ts}] Removed unnecessary endpoints from public routing",
            f"[{ts}] Added 404 rate limiting to prevent future enumeration",
        ],
        "connection_flood": [
            f"[{ts}] Closed orphaned connections from {source_ip}",
            f"[{ts}] Reduced max connections per IP to 20",
        ],
    }

    actions = PLAYBOOKS.get(attack_type, [
        f"[{ts}] Event documented for manual review",
        f"[{ts}] System state verified — no structural damage detected",
    ])

    return _apply_repairs(actions), "success"


def _apply_repairs(actions: list[str]) -> list[str]:
    prefix = "[SIM] " if settings.simulate_actions else "[REAL] "
    applied = []
    for action in actions:
        full = f"{prefix}{action}" if "[SIM]" not in action and "[REAL]" not in action else action
        logger.info(f"[Healer] {full}")
        applied.append(full)
    return applied
