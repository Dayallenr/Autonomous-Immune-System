"""
Hunter Agent — Natural Killer (NK) Cell.
Proactively hunts for related threats and lateral movement after initial detection.
Scans for additional IOCs across the system based on the Investigator's findings.
"""
import asyncio
import re
from datetime import datetime

import httpx

from config.settings import settings
from config.logging_config import setup_logging
from agents.base import ImmuneState

logger = setup_logging("agent.hunter")

HUNT_PATHS = [
    "/admin", "/config", "/.env", "/backup", "/.git/config",
    "/api/v1/admin", "/api/v2/admin", "/debug", "/console",
    "/actuator/health", "/actuator/env", "/metrics",
]


async def hunter_node(state: ImmuneState) -> dict:
    """LangGraph node: Hunter Agent."""
    attack_type = state["attack_type"]
    iocs = state.get("iocs", [])
    source_ip = state["threat_event"].get("source_ip")
    severity = state["attack_severity"]

    # Only hunt for medium+ severity or when specifically recommended
    if severity == "low" and attack_type not in ("port_scan", "file_injection"):
        logger.info("[Hunter] Low severity — skipping active hunt")
        return {
            "additional_threats": [],
            "related_iocs": [],
            "hunt_summary": "Hunt skipped (low severity)",
        }

    logger.info(f"[Hunter] Starting hunt for IOCs related to {attack_type}")

    additional_threats = []
    related_iocs = list(iocs)

    # Hunt 1: Scan for exposed sensitive endpoints
    endpoint_findings = await _hunt_exposed_endpoints()
    additional_threats.extend(endpoint_findings)

    # Hunt 2: Look for related activity in logs
    log_findings = await _hunt_log_patterns(attack_type, source_ip)
    related_iocs.extend(log_findings)

    # Hunt 3: Check for lateral movement indicators
    if attack_type in ("file_injection", "sql_injection"):
        lateral_findings = await _hunt_lateral_movement(source_ip)
        additional_threats.extend(lateral_findings)

    total_findings = len(additional_threats) + len(related_iocs)
    summary = (
        f"Hunt complete: {len(additional_threats)} additional threats, "
        f"{len(related_iocs)} related IOCs found"
    )

    logger.info(f"[Hunter] {summary}")

    return {
        "additional_threats": additional_threats,
        "related_iocs": related_iocs,
        "hunt_summary": summary,
        "hunt_findings": additional_threats,
    }


async def _hunt_exposed_endpoints() -> list[dict]:
    """Check if sensitive endpoints are publicly accessible on the target."""
    findings = []
    target = settings.simulation_target_url

    async with httpx.AsyncClient(timeout=3) as client:
        tasks = [
            (path, client.get(f"{target}{path}"))
            for path in HUNT_PATHS
        ]
        for path, coro in tasks:
            try:
                resp = await coro
                if resp.status_code < 400:
                    findings.append({
                        "type": "exposed_endpoint",
                        "endpoint": path,
                        "status_code": resp.status_code,
                        "severity": "high" if path in ("/admin", "/config", "/.env") else "medium",
                        "description": f"Sensitive endpoint {path} is publicly accessible (HTTP {resp.status_code})",
                    })
                    logger.warning(f"[Hunter] Exposed endpoint found: {path} ({resp.status_code})")
            except Exception:
                pass

    return findings


async def _hunt_log_patterns(attack_type: str, source_ip: str | None) -> list[str]:
    """Search logs for related activity from the same IP or with similar patterns."""
    findings = []

    try:
        with open("logs/target_requests.log", "r") as f:
            lines = f.readlines()[-500:]  # Last 500 entries
    except FileNotFoundError:
        return findings

    import json
    suspicious_ips = set()
    for line in lines:
        try:
            entry = json.loads(line.strip())
            ip = entry.get("source_ip", "")
            if source_ip and ip == source_ip:
                path = entry.get("path", "")
                if path not in ("/health", "/"):
                    suspicious_ips.add(ip)
                    findings.append(f"Related activity from {ip}: {entry.get('method')} {path}")
        except Exception:
            continue

    if suspicious_ips:
        findings.append(f"Correlated activity: {len(suspicious_ips)} IPs with suspicious patterns")

    return findings[:10]  # Cap at 10 IOCs


async def _hunt_lateral_movement(source_ip: str | None) -> list[dict]:
    """Look for signs of lateral movement — access to internal resources."""
    findings = []

    try:
        with open("logs/target_requests.log", "r") as f:
            lines = f.readlines()[-200:]
    except FileNotFoundError:
        return findings

    import json
    INTERNAL_PATHS = {"/admin", "/config", "/database", "/db", "/backup", "/.env"}

    for line in lines:
        try:
            entry = json.loads(line.strip())
            ip = entry.get("source_ip", "")
            path = entry.get("path", "")
            if path in INTERNAL_PATHS and (not source_ip or ip == source_ip):
                findings.append({
                    "type": "lateral_movement",
                    "source_ip": ip,
                    "endpoint": path,
                    "severity": "high",
                    "description": f"Potential lateral movement: {ip} accessed {path}",
                })
        except Exception:
            continue

    return findings
