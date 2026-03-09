"""
Investigator Agent — the Adaptive Immune Response (T-Cell).
LLM-powered deep analysis of the threat. Classifies attack type, severity,
identifies indicators of compromise, and recommends repair actions.

Uses httpx to call OpenAI API directly (no langchain required).
Falls back to deterministic analysis if no OpenAI key is set.
"""
import json

import httpx

from config.settings import settings
from config.logging_config import setup_logging

logger = setup_logging("agent.investigator")

SYSTEM_PROMPT = """You are the Investigator Agent of an Autonomous AI Immune System.
Your role is identical to a T-cell in the human immune system: perform deep analysis of
a security threat, identify exactly what happened, and recommend precise remediation steps.

You will receive a raw threat event and must return a structured JSON analysis.

Return ONLY valid JSON with this exact structure:
{
  "attack_type": "<brute_force|sql_injection|port_scan|file_injection|ddos|unknown>",
  "attack_severity": "<low|medium|high|critical>",
  "attack_vector": "<description of how the attack is being executed>",
  "iocs": ["<indicator of compromise 1>", "<indicator of compromise 2>"],
  "recommended_actions": ["<action 1>", "<action 2>", "<action 3>"],
  "analysis_summary": "<2-3 sentence plain-English explanation of the threat>",
  "requires_healing": true,
  "requires_hunting": true
}"""


async def investigator_node(state: dict) -> dict:
    """Sequential pipeline node: Investigator Agent."""
    event = state["threat_event"]
    logger.info(f"[Investigator] Analyzing {event.get('event_type')} threat...")

    if settings.openai_api_key:
        analysis = await _llm_analyze(event)
    else:
        logger.warning("[Investigator] No API key — using rule-based fallback analysis")
        analysis = _rule_based_analyze(event)

    logger.info(
        f"[Investigator] Analysis complete — type={analysis['attack_type']}, "
        f"severity={analysis['attack_severity']}, requires_healing={analysis['requires_healing']}"
    )

    return {
        "attack_type": analysis["attack_type"],
        "attack_severity": analysis["attack_severity"],
        "attack_vector": analysis["attack_vector"],
        "iocs": analysis["iocs"],
        "recommended_actions": analysis["recommended_actions"],
        "analysis_summary": analysis["analysis_summary"],
        "requires_healing": analysis.get("requires_healing", True),
        "requires_hunting": analysis.get("requires_hunting", False),
    }


async def _llm_analyze(event: dict) -> dict:
    try:
        payload = {
            "model": settings.llm_model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Source IP: {event.get('source_ip', 'unknown')}\n"
                        f"Attack Type (initial): {event.get('event_type', 'unknown')}\n"
                        f"Target: {event.get('target_endpoint', 'unknown')}\n"
                        f"Severity: {event.get('severity', 'medium')}\n"
                        f"Payload sample: {str(event.get('payload_sample', ''))[:500]}\n"
                        f"Raw data: {json.dumps(event.get('raw_data', {}))[:300]}"
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

        return json.loads(raw)

    except Exception as e:
        logger.error(f"[Investigator] LLM analysis failed: {e}. Using fallback.")
        return _rule_based_analyze(event)


def _rule_based_analyze(event: dict) -> dict:
    """Deterministic fallback analysis when LLM is unavailable."""
    attack_type = event.get("event_type", "unknown")
    severity = event.get("severity", "medium")
    source_ip = event.get("source_ip", "unknown")
    endpoint = event.get("target_endpoint", "unknown")

    PROFILES = {
        "sql_injection": {
            "attack_vector": "Malicious SQL in HTTP request body/parameters",
            "iocs": [f"Source IP: {source_ip}", "SQL metacharacters in input", f"Endpoint: {endpoint}"],
            "recommended_actions": [
                "Sanitize all user inputs with parameterized queries",
                "Review and patch vulnerable endpoint",
                "Audit database access logs for data exfiltration",
                "Enable WAF SQL injection rules",
            ],
            "analysis_summary": (
                f"SQL injection attack detected from {source_ip} targeting {endpoint}. "
                f"Attacker is attempting to manipulate database queries via unsanitized input. "
                f"Immediate patching of input validation required."
            ),
            "requires_healing": True,
            "requires_hunting": True,
        },
        "brute_force": {
            "attack_vector": "Automated credential stuffing / password spraying",
            "iocs": [f"Source IP: {source_ip}", "High failed auth rate"],
            "recommended_actions": [
                "Implement account lockout after N failures",
                "Add CAPTCHA to login endpoint",
                "Enable MFA for all accounts",
            ],
            "analysis_summary": (
                f"Brute force login attack from {source_ip}. "
                f"Attacker is systematically attempting credential combinations. "
                f"Account lockout and MFA are the primary defenses."
            ),
            "requires_healing": False,
            "requires_hunting": False,
        },
        "port_scan": {
            "attack_vector": "Automated enumeration of available services and endpoints",
            "iocs": [f"Source IP: {source_ip}", "Rapid sequential HTTP requests"],
            "recommended_actions": [
                "Block scanning IP at firewall level",
                "Review exposed endpoints for unnecessary disclosure",
                "Implement honeypot endpoints",
            ],
            "analysis_summary": (
                f"Port/endpoint scanning activity from {source_ip}. "
                f"Attacker is mapping available services as reconnaissance. "
                f"IP block and endpoint hardening recommended."
            ),
            "requires_healing": False,
            "requires_hunting": True,
        },
        "file_injection": {
            "attack_vector": "Malicious file upload attempting code execution or path traversal",
            "iocs": [f"Source IP: {source_ip}", "Malicious filename/content"],
            "recommended_actions": [
                "Remove uploaded malicious files immediately",
                "Restrict upload file types to whitelist",
                "Scan all uploads before storage",
            ],
            "analysis_summary": (
                f"File injection attack from {source_ip} targeting upload endpoint. "
                f"Attacker attempted to upload malicious content for remote code execution. "
                f"Immediate file removal and input validation required."
            ),
            "requires_healing": True,
            "requires_hunting": True,
        },
        "ddos": {
            "attack_vector": "High-volume request flood targeting service availability",
            "iocs": [f"Source IP: {source_ip}", "Request rate exceeds baseline"],
            "recommended_actions": [
                "Enable global rate limiting",
                "Deploy CDN/DDoS protection",
                "Block source IP at edge",
            ],
            "analysis_summary": (
                f"DDoS/flood attack from {source_ip}. "
                f"Request rate significantly exceeds baseline, threatening service availability."
            ),
            "requires_healing": False,
            "requires_hunting": False,
        },
    }

    profile = PROFILES.get(attack_type, {
        "attack_vector": "Unknown attack vector",
        "iocs": [f"Source IP: {source_ip}"],
        "recommended_actions": ["Monitor closely", "Investigate manually"],
        "analysis_summary": f"Unknown threat type detected from {source_ip}. Manual investigation required.",
        "requires_healing": False,
        "requires_hunting": True,
    })

    return {
        "attack_type": attack_type,
        "attack_severity": severity,
        **profile,
    }
