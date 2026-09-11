"""
Requirement Mapping and Communication Classification Helpers for US TCPA (47 U.S.C. § 227 & 47 C.F.R. § 64.1200).
"""

from typing import List, Dict, Any, Optional, Tuple
from src.compliance.tcpa_constants import (
    FRAMEWORK_TCPA,
    TCPA_CHANNELS,
    TCPA_PURPOSES,
    TCPA_REQUIREMENTS
)

TELEPHONY_PROVIDERS = ["twilio", "plivo", "bandwidth", "vonage", "nexmo", "sinch", "telnyx", "messagebird"]
VOICE_SPECIFIC_KEYWORDS = ["voice", "call", "ivr", "asterisk", "freeswitch", "telephony", "audio", "speech"]
SMS_SPECIFIC_KEYWORDS = ["sms", "text", "message", "otp", "2fa", "mms"]
EMAIL_PROVIDERS = ["sendgrid", "ses", "mailgun", "postmark", "mailchimp", "sparkpost"]

MARKETING_KEYWORDS = [
    "marketing", "promo", "promotional", "campaign", "offer", "discount",
    "advertisement", "ad", "deal", "lead", "newsletter", "telemarketing", "sales"
]

TRANSACTIONAL_KEYWORDS = [
    "otp", "2fa", "verification", "auth", "login", "password_reset", "security_code",
    "receipt", "invoice", "order_status", "order_update", "shipping", "delivery",
    "appointment", "alert", "notification"
]

def classify_communication_channel(evidence_text: str, metadata: Optional[Dict[str, Any]] = None) -> str:
    """
    Classifies a communication channel based on evidence text and metadata:
    - SMS
    - VOICE_CALL
    - EMAIL
    - UNKNOWN
    """
    if not evidence_text:
        return TCPA_CHANNELS["UNKNOWN"]

    text_lower = evidence_text.lower()
    meta = metadata or {}

    has_voice = any(kw in text_lower for kw in VOICE_SPECIFIC_KEYWORDS)
    has_sms = any(kw in text_lower for kw in SMS_SPECIFIC_KEYWORDS) or "phone" in text_lower or "mobile" in text_lower
    has_email = any(kw in text_lower for kw in EMAIL_PROVIDERS) or "email" in text_lower

    # Provider metadata checks
    provider = str(meta.get("provider", "")).lower()
    if any(p in provider for p in TELEPHONY_PROVIDERS):
        if "voice" in text_lower or "call" in text_lower:
            return TCPA_CHANNELS["VOICE_CALL"]
        return TCPA_CHANNELS["SMS"]

    if has_voice and not has_sms:
        return TCPA_CHANNELS["VOICE_CALL"]
    if has_sms:
        return TCPA_CHANNELS["SMS"]
    if has_email:
        return TCPA_CHANNELS["EMAIL"]

    return TCPA_CHANNELS["UNKNOWN"]

def classify_communication_purpose(evidence_text: str) -> str:
    """
    Classifies communication purpose into TRANSACTIONAL, MARKETING, MIXED, or UNKNOWN.
    """
    if not evidence_text:
        return TCPA_PURPOSES["UNKNOWN"]

    text_lower = evidence_text.lower()

    has_mkt = any(kw in text_lower for kw in MARKETING_KEYWORDS)
    has_txn = any(kw in text_lower for kw in TRANSACTIONAL_KEYWORDS)

    if has_mkt and has_txn:
        return TCPA_PURPOSES["MIXED"]
    if has_mkt:
        return TCPA_PURPOSES["MARKETING"]
    if has_txn:
        return TCPA_PURPOSES["TRANSACTIONAL"]

    return TCPA_PURPOSES["UNKNOWN"]

def get_tcpa_references_for_rule(
    rule_id: str,
    detected_by: Optional[List[str]] = None,
    severity: Optional[str] = None
) -> List[str]:
    """
    Maps security scanner rule IDs / tool outputs to relevant TCPA requirement IDs where appropriate.
    Only maps security findings that touch communication endpoints, auth, or input verification.
    """
    if not rule_id:
        return []

    r_lower = rule_id.lower()
    tools = [t.lower() for t in (detected_by or [])]

    # Phone/SMS verification or auth security findings
    if any(kw in r_lower for kw in ["phone", "sms", "twilio", "otp", "2fa", "mfa"]):
        return ["TCPA-227-B-1-A-CALLS-CONSENT", "TCPA-64-1200-IDENTIFICATION"]

    return []
