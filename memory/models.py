"""
Data models as plain dataclasses — no external ORM dependency.
The actual storage is handled by store.py using sqlite3.
"""
import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(str, enum.Enum):
    DETECTED = "detected"
    CONTAINED = "contained"
    INVESTIGATING = "investigating"
    HEALED = "healed"
    RESOLVED = "resolved"


@dataclass
class ThreatEvent:
    id: Optional[int]
    detected_at: datetime
    resolved_at: Optional[datetime]
    attack_type: str
    attack_vector: Optional[str]
    severity: str
    status: str
    source_ip: Optional[str]
    source_port: Optional[int]
    target_endpoint: Optional[str]
    raw_event: Optional[dict]
    payload_sample: Optional[str]
    sentinel_actions: Optional[list]
    investigator_analysis: Optional[str]
    healer_actions: Optional[list]
    hunter_findings: Optional[list]
    was_blocked: bool
    response_time_seconds: Optional[float]
    confidence_score: float


@dataclass
class AttackSignature:
    id: Optional[int]
    created_at: datetime
    last_seen: datetime
    attack_type: str
    pattern: str
    pattern_type: str
    description: Optional[str]
    hit_count: int
    detection_threshold: float
    false_positive_count: int
    is_active: bool


@dataclass
class ResponsePlaybook:
    id: Optional[int]
    created_at: datetime
    updated_at: datetime
    attack_type: str
    severity: str
    sentinel_steps: Optional[list]
    investigator_prompt_hints: Optional[str]
    healer_steps: Optional[list]
    hunter_ioc_patterns: Optional[list]
    success_count: int
    failure_count: int
    avg_response_time: Optional[float]
    confidence_score: float
    is_active: bool


@dataclass
class AdaptiveRule:
    id: Optional[int]
    created_at: datetime
    rule_type: str
    rule_value: str
    description: Optional[str]
    source_threat_type: Optional[str]
    source_event_id: Optional[int]
    expires_at: Optional[datetime]
    is_active: bool
    trigger_count: int
