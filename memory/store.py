"""
Immunological Memory Store — sqlite3-based read/write interface.
Uses asyncio.to_thread to keep all DB operations non-blocking.
"""
import asyncio
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional

from config.settings import settings
from memory.models import ThreatEvent, AttackSignature, ResponsePlaybook, AdaptiveRule

DB_PATH = "immune_memory.db"


@contextmanager
def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_db_sync():
    with _db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT NOT NULL,
                resolved_at TEXT,
                attack_type TEXT NOT NULL,
                attack_vector TEXT,
                severity TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'detected',
                source_ip TEXT,
                source_port INTEGER,
                target_endpoint TEXT,
                raw_event TEXT,
                payload_sample TEXT,
                sentinel_actions TEXT,
                investigator_analysis TEXT,
                healer_actions TEXT,
                hunter_findings TEXT,
                was_blocked INTEGER DEFAULT 0,
                response_time_seconds REAL,
                confidence_score REAL DEFAULT 0.5
            );

            CREATE TABLE IF NOT EXISTS attack_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                pattern_type TEXT DEFAULT 'regex',
                description TEXT,
                hit_count INTEGER DEFAULT 1,
                detection_threshold REAL DEFAULT 0.7,
                false_positive_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS response_playbooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                sentinel_steps TEXT,
                investigator_prompt_hints TEXT,
                healer_steps TEXT,
                hunter_ioc_patterns TEXT,
                success_count INTEGER DEFAULT 1,
                failure_count INTEGER DEFAULT 0,
                avg_response_time REAL,
                confidence_score REAL DEFAULT 0.5,
                is_active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS adaptive_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                rule_value TEXT NOT NULL,
                description TEXT,
                source_threat_type TEXT,
                source_event_id INTEGER,
                expires_at TEXT,
                is_active INTEGER DEFAULT 1,
                trigger_count INTEGER DEFAULT 0
            );
        """)


async def init_db():
    await asyncio.to_thread(_init_db_sync)


def _now() -> str:
    return datetime.utcnow().isoformat()


# ─────────────────────────────────────────────
# Threat Events
# ─────────────────────────────────────────────

def _record_threat_sync(data: dict) -> int:
    with _db() as conn:
        cur = conn.execute(
            """INSERT INTO threat_events
               (detected_at, attack_type, attack_vector, severity, status,
                source_ip, source_port, target_endpoint, raw_event,
                payload_sample, confidence_score)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                _now(), data.get("attack_type", "unknown"),
                data.get("attack_vector"), data.get("severity", "medium"),
                "detected", data.get("source_ip"), data.get("source_port"),
                data.get("target_endpoint"), json.dumps(data.get("raw_event") or {}),
                (data.get("payload_sample") or "")[:500],
                data.get("confidence_score", 0.5),
            ),
        )
        return cur.lastrowid


async def record_threat_event(data: dict):
    row_id = await asyncio.to_thread(_record_threat_sync, data)

    class _Row:
        id = row_id
    return _Row()


def _update_threat_sync(event_id: int, updates: dict):
    allowed = {
        "status", "resolved_at", "attack_type", "severity",
        "sentinel_actions", "investigator_analysis", "healer_actions",
        "hunter_findings", "was_blocked", "response_time_seconds",
    }
    cols, vals = [], []
    for k, v in updates.items():
        if k not in allowed:
            continue
        if isinstance(v, (list, dict)):
            v = json.dumps(v)
        elif isinstance(v, datetime):
            v = v.isoformat()
        elif isinstance(v, bool):
            v = int(v)
        cols.append(f"{k} = ?")
        vals.append(v)
    if not cols:
        return
    vals.append(event_id)
    with _db() as conn:
        conn.execute(f"UPDATE threat_events SET {', '.join(cols)} WHERE id = ?", vals)


async def update_threat_event(event_id: int, updates: dict):
    await asyncio.to_thread(_update_threat_sync, event_id, updates)


def _get_recent_threats_sync(limit: int) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM threat_events ORDER BY detected_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


async def get_recent_threats(limit: int = 50) -> list[dict]:
    rows = await asyncio.to_thread(_get_recent_threats_sync, limit)
    result = []
    for r in rows:
        for field in ("raw_event", "sentinel_actions", "healer_actions", "hunter_findings"):
            if r.get(field):
                try:
                    r[field] = json.loads(r[field])
                except Exception:
                    pass
        result.append(r)
    return result


def _get_threat_by_id_sync(event_id: int) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM threat_events WHERE id = ?", (event_id,)
        ).fetchone()
    return dict(row) if row else None


async def get_threat_by_id(event_id: int) -> Optional[dict]:
    return await asyncio.to_thread(_get_threat_by_id_sync, event_id)


# ─────────────────────────────────────────────
# Attack Signatures
# ─────────────────────────────────────────────

def _add_or_reinforce_sync(attack_type: str, pattern: str, pattern_type: str, description: str) -> dict:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM attack_signatures WHERE attack_type=? AND pattern=? AND is_active=1",
            (attack_type, pattern),
        ).fetchone()
        if row:
            conn.execute(
                """UPDATE attack_signatures
                   SET hit_count = hit_count + 1,
                       last_seen = ?,
                       detection_threshold = MAX(0.3, detection_threshold - 0.05)
                   WHERE id = ?""",
                (_now(), row["id"]),
            )
            return {"id": row["id"], "hit_count": row["hit_count"] + 1,
                    "detection_threshold": max(0.3, row["detection_threshold"] - 0.05)}
        else:
            cur = conn.execute(
                """INSERT INTO attack_signatures
                   (created_at, last_seen, attack_type, pattern, pattern_type, description)
                   VALUES (?,?,?,?,?,?)""",
                (_now(), _now(), attack_type, pattern, pattern_type, description),
            )
            return {"id": cur.lastrowid, "hit_count": 1, "detection_threshold": 0.7}


async def add_or_reinforce_signature(
    attack_type: str, pattern: str, pattern_type: str = "regex", description: str = ""
) -> dict:
    return await asyncio.to_thread(
        _add_or_reinforce_sync, attack_type, pattern, pattern_type, description
    )


def _get_all_sigs_sync() -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT * FROM attack_signatures WHERE is_active=1 ORDER BY hit_count DESC"
        ).fetchall()
    return [dict(r) for r in rows]


async def get_all_active_signatures() -> list[dict]:
    return await asyncio.to_thread(_get_all_sigs_sync)


async def get_signatures_for_type(attack_type: str) -> list[dict]:
    def _sync():
        with _db() as conn:
            rows = conn.execute(
                "SELECT * FROM attack_signatures WHERE attack_type=? AND is_active=1",
                (attack_type,),
            ).fetchall()
        return [dict(r) for r in rows]
    return await asyncio.to_thread(_sync)


# ─────────────────────────────────────────────
# Response Playbooks
# ─────────────────────────────────────────────

def _upsert_playbook_sync(
    attack_type: str, severity: str, data: dict, success: bool, response_time: Optional[float]
) -> dict:
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM response_playbooks WHERE attack_type=? AND severity=? AND is_active=1",
            (attack_type, severity),
        ).fetchone()

        if row:
            total = row["success_count"] + row["failure_count"] + 1
            new_success = row["success_count"] + (1 if success else 0)
            new_fail = row["failure_count"] + (0 if success else 1)
            confidence = new_success / total
            new_rt = row["avg_response_time"]
            if response_time:
                new_rt = ((row["avg_response_time"] or response_time) + response_time) / 2
            conn.execute(
                """UPDATE response_playbooks
                   SET success_count=?, failure_count=?, confidence_score=?,
                       avg_response_time=?, updated_at=?,
                       sentinel_steps=COALESCE(?, sentinel_steps),
                       healer_steps=COALESCE(?, healer_steps),
                       hunter_ioc_patterns=COALESCE(?, hunter_ioc_patterns),
                       investigator_prompt_hints=COALESCE(?, investigator_prompt_hints)
                   WHERE id=?""",
                (new_success, new_fail, confidence, new_rt, _now(),
                 json.dumps(data.get("sentinel_steps")) if data.get("sentinel_steps") else None,
                 json.dumps(data.get("healer_steps")) if data.get("healer_steps") else None,
                 json.dumps(data.get("hunter_ioc_patterns")) if data.get("hunter_ioc_patterns") else None,
                 data.get("investigator_prompt_hints"),
                 row["id"]),
            )
            return {"id": row["id"], "confidence_score": confidence,
                    "success_count": new_success, "failure_count": new_fail}
        else:
            cur = conn.execute(
                """INSERT INTO response_playbooks
                   (created_at, updated_at, attack_type, severity,
                    sentinel_steps, healer_steps, hunter_ioc_patterns, investigator_prompt_hints,
                    avg_response_time)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    _now(), _now(), attack_type, severity,
                    json.dumps(data.get("sentinel_steps") or []),
                    json.dumps(data.get("healer_steps") or []),
                    json.dumps(data.get("hunter_ioc_patterns") or []),
                    data.get("investigator_prompt_hints", ""),
                    response_time,
                ),
            )
            return {"id": cur.lastrowid, "confidence_score": 0.5, "success_count": 1, "failure_count": 0}


async def upsert_playbook(
    attack_type: str, severity, playbook_data: dict,
    success: bool = True, response_time: Optional[float] = None
) -> dict:
    sev = severity.value if hasattr(severity, "value") else str(severity)
    return await asyncio.to_thread(
        _upsert_playbook_sync, attack_type, sev, playbook_data, success, response_time
    )


async def get_playbook(attack_type: str, severity=None) -> Optional[dict]:
    def _sync():
        sev = severity.value if severity and hasattr(severity, "value") else severity
        with _db() as conn:
            if sev:
                row = conn.execute(
                    """SELECT * FROM response_playbooks
                       WHERE attack_type=? AND severity=? AND is_active=1
                       ORDER BY confidence_score DESC LIMIT 1""",
                    (attack_type, sev),
                ).fetchone()
            else:
                row = conn.execute(
                    """SELECT * FROM response_playbooks
                       WHERE attack_type=? AND is_active=1
                       ORDER BY confidence_score DESC LIMIT 1""",
                    (attack_type,),
                ).fetchone()
        if not row:
            return None
        r = dict(row)
        for f in ("sentinel_steps", "healer_steps", "hunter_ioc_patterns"):
            if r.get(f):
                try:
                    r[f] = json.loads(r[f])
                except Exception:
                    pass
        return r

    return await asyncio.to_thread(_sync)


async def get_all_playbooks() -> list[dict]:
    def _sync():
        with _db() as conn:
            rows = conn.execute(
                "SELECT * FROM response_playbooks WHERE is_active=1 ORDER BY confidence_score DESC"
            ).fetchall()
        result = []
        for row in rows:
            r = dict(row)
            for f in ("sentinel_steps", "healer_steps", "hunter_ioc_patterns"):
                if r.get(f):
                    try:
                        r[f] = json.loads(r[f])
                    except Exception:
                        pass
            result.append(r)
        return result
    return await asyncio.to_thread(_sync)


# ─────────────────────────────────────────────
# Adaptive Rules
# ─────────────────────────────────────────────

def _add_rule_sync(
    rule_type: str, rule_value: str, description: str,
    source_threat_type: str, source_event_id: Optional[int],
    expires_at: Optional[str],
) -> dict:
    with _db() as conn:
        cur = conn.execute(
            """INSERT INTO adaptive_rules
               (created_at, rule_type, rule_value, description,
                source_threat_type, source_event_id, expires_at)
               VALUES (?,?,?,?,?,?,?)""",
            (_now(), rule_type, rule_value, description,
             source_threat_type, source_event_id, expires_at),
        )
    return {"id": cur.lastrowid}


async def add_adaptive_rule(
    rule_type: str, rule_value: str, description: str = "",
    source_threat_type: str = "", source_event_id: Optional[int] = None,
    ttl_seconds: Optional[int] = None,
) -> dict:
    expires_at = None
    if ttl_seconds:
        expires_at = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat()
    return await asyncio.to_thread(
        _add_rule_sync, rule_type, rule_value, description,
        source_threat_type, source_event_id, expires_at,
    )


async def get_active_rules(rule_type: Optional[str] = None) -> list[dict]:
    def _sync():
        with _db() as conn:
            now = _now()
            if rule_type:
                rows = conn.execute(
                    """SELECT * FROM adaptive_rules WHERE is_active=1 AND rule_type=?
                       AND (expires_at IS NULL OR expires_at > ?)""",
                    (rule_type, now),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM adaptive_rules WHERE is_active=1
                       AND (expires_at IS NULL OR expires_at > ?)""",
                    (now,),
                ).fetchall()
        return [dict(r) for r in rows]
    return await asyncio.to_thread(_sync)


# ─────────────────────────────────────────────
# Memory Stats
# ─────────────────────────────────────────────

async def get_memory_stats() -> dict:
    def _sync():
        with _db() as conn:
            now = _now()
            sig_count = conn.execute(
                "SELECT COUNT(*) FROM attack_signatures WHERE is_active=1"
            ).fetchone()[0]
            playbook_count = conn.execute(
                "SELECT COUNT(*) FROM response_playbooks WHERE is_active=1"
            ).fetchone()[0]
            rule_count = conn.execute(
                "SELECT COUNT(*) FROM adaptive_rules WHERE is_active=1 AND (expires_at IS NULL OR expires_at > ?)",
                (now,),
            ).fetchone()[0]
            threat_count = conn.execute(
                "SELECT COUNT(*) FROM threat_events"
            ).fetchone()[0]
            resolved_count = conn.execute(
                "SELECT COUNT(*) FROM threat_events WHERE status='resolved'"
            ).fetchone()[0]
        return {
            "total_threats_seen": threat_count,
            "threats_resolved": resolved_count,
            "known_signatures": sig_count,
            "response_playbooks": playbook_count,
            "adaptive_rules": rule_count,
        }
    return await asyncio.to_thread(_sync)
