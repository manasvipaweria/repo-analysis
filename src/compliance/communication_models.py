"""
Framework-neutral communication channel models and evidence schemas.
Consumed by TCPA, TRAI/DLT (future), and ePrivacy (future) compliance engines.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional

class CommunicationChannel(str, Enum):
    SMS = "SMS"
    VOICE_CALL = "VOICE_CALL"
    EMAIL = "EMAIL"
    UNKNOWN = "UNKNOWN"

class CommunicationPurpose(str, Enum):
    TRANSACTIONAL = "TRANSACTIONAL"
    MARKETING = "MARKETING"
    MIXED = "MIXED"
    UNKNOWN = "UNKNOWN"

class PurposeConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class EvidenceStatus(str, Enum):
    DETECTED = "DETECTED"
    NOT_DETECTED = "NOT_DETECTED"
    INDETERMINATE = "INDETERMINATE"
    NOT_APPLICABLE = "NOT_APPLICABLE"

@dataclass
class CommunicationFlowEvidence:
    flow_id: str
    channel: str                                 # SMS, VOICE_CALL, EMAIL, UNKNOWN
    provider: Optional[str] = None              # Twilio, SendGrid, Plivo, Bandwidth, etc.
    recipient_field: Optional[str] = None       # phone, mobile, email, etc.
    destination: Optional[str] = None          # external service endpoint or system role
    purpose: str = "UNKNOWN"                     # TRANSACTIONAL, MARKETING, MIXED, UNKNOWN
    purpose_confidence: str = "LOW"             # LOW, MEDIUM, HIGH
    automated: bool = False                      # True if Celery/Bull/cron/queue detected
    bulk: bool = False                           # True if batch/broadcast/bulk dispatch detected
    consent_evidence: List[str] = field(default_factory=list)      # Source references for opt-in consent
    opt_out_evidence: List[str] = field(default_factory=list)      # Source references for STOP/unsubscribe
    suppression_evidence: List[str] = field(default_factory=list)  # Source references for DNC/suppression list
    source_locations: List[Dict[str, Any]] = field(default_factory=list)
    evidence_status: str = "DETECTED"           # DETECTED, NOT_DETECTED, INDETERMINATE, NOT_APPLICABLE
