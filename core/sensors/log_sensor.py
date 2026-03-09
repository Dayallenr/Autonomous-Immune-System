"""
Log Sensor — tails the target app's request log and detects suspicious patterns.
Watches for SQL injection, brute force, port scanning, and file injection patterns.
"""
import asyncio
import json
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from config.settings import settings
from core.sensors.base import BaseSensor, ThreatEvent

LOG_FILE = "logs/target_requests.log"

# Detection patterns
SQL_PATTERNS = re.compile(
    r"('|\")\s*(OR|AND|UNION|SELECT|DROP|INSERT|DELETE|UPDATE)\s|"
    r"--\s*$|;\s*(DROP|DELETE|UPDATE|INSERT)|xp_cmdshell|EXEC\s*\(|"
    r"1\s*=\s*1|OR\s+1\s*=\s*1",
    re.IGNORECASE,
)

FILE_INJECTION_PATTERNS = re.compile(
    r"\.\./|<\s*script|javascript:|/etc/(passwd|shadow)|"
    r"\.(php|sh|exe|bat|cmd)\b|base64_decode|system\(",
    re.IGNORECASE,
)

BRUTE_FORCE_WINDOW = 60   # seconds
PORT_SCAN_WINDOW = 10     # seconds


class LogSensor(BaseSensor):
    def __init__(self):
        super().__init__("log_sensor")
        # Track per-IP activity for brute force / port scan detection
        self._ip_failed_auths: dict[str, deque] = defaultdict(lambda: deque())
        self._ip_paths: dict[str, deque] = defaultdict(lambda: deque())
        self._ip_requests: dict[str, deque] = defaultdict(lambda: deque())
        self._file_position = 0

    async def run(self):
        self.logger.info(f"[LogSensor] Watching {LOG_FILE}")

        # Create log file if it doesn't exist yet
        os.makedirs("logs", exist_ok=True)
        if not os.path.exists(LOG_FILE):
            open(LOG_FILE, "w").close()

        while self._running:
            await self._tail_log()
            await asyncio.sleep(1)

    async def _tail_log(self):
        try:
            with open(LOG_FILE, "r") as f:
                f.seek(self._file_position)
                new_lines = f.readlines()
                self._file_position = f.tell()
        except FileNotFoundError:
            return

        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                await self._analyze_entry(entry)
            except json.JSONDecodeError:
                continue

    async def _analyze_entry(self, entry: dict):
        ip = entry.get("source_ip", "unknown")
        path = entry.get("path", "")
        body = entry.get("body_sample", "")
        status = entry.get("status_code", 200)
        timestamp = datetime.utcnow()

        # Track requests per IP
        self._ip_requests[ip].append(timestamp)
        self._ip_paths[ip].append((timestamp, path))

        # ── SQL Injection Detection ─────────────────────
        combined = f"{path} {body} {entry.get('query', '')}"
        if SQL_PATTERNS.search(combined):
            await self.emit(ThreatEvent(
                source="log_sensor",
                event_type="sql_injection",
                source_ip=ip,
                target_endpoint=path,
                severity="high",
                payload_sample=combined[:300],
                raw_data=entry,
                confidence=0.9,
            ))

        # ── File Injection Detection ────────────────────
        if FILE_INJECTION_PATTERNS.search(body) or FILE_INJECTION_PATTERNS.search(path):
            await self.emit(ThreatEvent(
                source="log_sensor",
                event_type="file_injection",
                source_ip=ip,
                target_endpoint=path,
                severity="critical",
                payload_sample=body[:300],
                raw_data=entry,
                confidence=0.85,
            ))

        # ── Brute Force Detection ───────────────────────
        if status == 401 or (path == "/login" and status != 200):
            self._ip_failed_auths[ip].append(timestamp)

        self._prune_deque(self._ip_failed_auths[ip], BRUTE_FORCE_WINDOW)
        if len(self._ip_failed_auths[ip]) >= settings.brute_force_threshold:
            await self.emit(ThreatEvent(
                source="log_sensor",
                event_type="brute_force",
                source_ip=ip,
                target_endpoint="/login",
                severity="high",
                payload_sample=f"{len(self._ip_failed_auths[ip])} failed auth attempts in {BRUTE_FORCE_WINDOW}s",
                raw_data={"failed_count": len(self._ip_failed_auths[ip]), "window_seconds": BRUTE_FORCE_WINDOW},
                confidence=0.92,
            ))
            # Reset to avoid re-alerting every request
            self._ip_failed_auths[ip].clear()

        # ── Port Scan Detection ─────────────────────────
        self._prune_path_deque(self._ip_paths[ip], PORT_SCAN_WINDOW)
        unique_paths = {p for _, p in self._ip_paths[ip]}
        if len(unique_paths) >= settings.port_scan_threshold:
            await self.emit(ThreatEvent(
                source="log_sensor",
                event_type="port_scan",
                source_ip=ip,
                target_endpoint="multiple",
                severity="medium",
                payload_sample=f"Scanned {len(unique_paths)} unique paths in {PORT_SCAN_WINDOW}s",
                raw_data={"unique_paths": list(unique_paths)[:20], "window_seconds": PORT_SCAN_WINDOW},
                confidence=0.80,
            ))
            self._ip_paths[ip].clear()

        # ── DDoS / Rate Detection ───────────────────────
        self._prune_deque(self._ip_requests[ip], 60)
        if len(self._ip_requests[ip]) >= settings.rate_limit_threshold:
            await self.emit(ThreatEvent(
                source="log_sensor",
                event_type="ddos",
                source_ip=ip,
                target_endpoint=path,
                severity="high",
                payload_sample=f"{len(self._ip_requests[ip])} requests in 60s from {ip}",
                raw_data={"request_count": len(self._ip_requests[ip])},
                confidence=0.75,
            ))
            self._ip_requests[ip].clear()

    @staticmethod
    def _prune_deque(dq: deque, window_seconds: int):
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        while dq and dq[0] < cutoff:
            dq.popleft()

    @staticmethod
    def _prune_path_deque(dq: deque, window_seconds: int):
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        while dq and dq[0][0] < cutoff:
            dq.popleft()
