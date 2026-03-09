"""
DB Sensor — monitors the database query log for suspicious SQL patterns.
Detects SQL injection attempts, unusual query structures, and data exfiltration.
"""
import asyncio
import json
import os
import re
from datetime import datetime

from core.sensors.base import BaseSensor, ThreatEvent

DB_QUERY_LOG = "logs/target_db_queries.log"

# High-confidence SQL injection indicators
HIGH_CONFIDENCE_PATTERNS = re.compile(
    r"('|\")\s*(OR|AND)\s+('|\"|1|\d)|"         # OR/AND injection
    r"UNION\s+SELECT|"                            # UNION-based injection
    r";\s*(DROP|DELETE|TRUNCATE|ALTER)\s+|"       # destructive statements
    r"xp_cmdshell|EXEC\s*\(|EXECUTE\s*\(|"       # command execution
    r"SLEEP\s*\(\s*\d+\s*\)|WAITFOR\s+DELAY|"    # time-based blind injection
    r"LOAD_FILE\s*\(|INTO\s+OUTFILE",             # file read/write
    re.IGNORECASE,
)

# Medium-confidence patterns (tautologies, comment injection)
MEDIUM_CONFIDENCE_PATTERNS = re.compile(
    r"--\s*$|#\s*$|/\*.*\*/|"         # comment stripping
    r"1\s*=\s*1|'='|\"=\"|"           # tautology
    r"OR\s+\d+\s*=\s*\d+",            # numeric tautology
    re.IGNORECASE,
)


class DBSensor(BaseSensor):
    def __init__(self):
        super().__init__("db_sensor")
        self._file_position = 0

    async def run(self):
        self.logger.info(f"[DBSensor] Watching {DB_QUERY_LOG}")

        os.makedirs("logs", exist_ok=True)
        if not os.path.exists(DB_QUERY_LOG):
            open(DB_QUERY_LOG, "w").close()

        while self._running:
            await self._tail_log()
            await asyncio.sleep(1)

    async def _tail_log(self):
        try:
            with open(DB_QUERY_LOG, "r") as f:
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
                await self._analyze_query(entry)
            except json.JSONDecodeError:
                continue

    async def _analyze_query(self, entry: dict):
        query = entry.get("query", "")
        context = entry.get("context", "")
        timestamp = entry.get("timestamp", datetime.utcnow().isoformat())

        if HIGH_CONFIDENCE_PATTERNS.search(query):
            await self.emit(ThreatEvent(
                source="db_sensor",
                event_type="sql_injection",
                source_ip=None,
                target_endpoint=f"db:{context}",
                severity="high",
                payload_sample=query[:500],
                raw_data=entry,
                confidence=0.93,
            ))

        elif MEDIUM_CONFIDENCE_PATTERNS.search(query):
            await self.emit(ThreatEvent(
                source="db_sensor",
                event_type="sql_injection",
                source_ip=None,
                target_endpoint=f"db:{context}",
                severity="medium",
                payload_sample=query[:500],
                raw_data=entry,
                confidence=0.65,
            ))
