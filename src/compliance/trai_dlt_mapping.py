"""
Requirement Mapping and Classification Helpers for India TRAI / TCCCPR 2018 / DLT Technical Readiness.
"""

import re
from typing import List, Dict, Any, Optional
from src.compliance.trai_dlt_constants import (
    FRAMEWORK_TRAI_DLT,
    TRAI_COMMUNICATION_TYPES,
    TRAI_DLT_REQUIREMENTS
)

PROMOTIONAL_KEYWORDS = [
    "promo", "promotional", "campaign", "offer", "discount",
    "deal", "newsletter", "telemarketing", "sales", "marketing", "advertisement"
]

TRANSACTIONAL_KEYWORDS = [
    "otp", "2fa", "verification", "auth", "login", "password", "reset",
    "receipt", "invoice", "order", "shipping", "delivery", "appointment", "alert"
]

def classify_trai_communication_type(evidence_purpose: str, text_context: str = "") -> str:
    """
    Classifies shared communication flow evidence into TRAI statutory categories:
    - SERVICE_TRANSACTIONAL
    - PROMOTIONAL_COMMERCIAL
    - UNKNOWN
    """
    if evidence_purpose == "TRANSACTIONAL":
        return TRAI_COMMUNICATION_TYPES["SERVICE_TRANSACTIONAL"]
    if evidence_purpose in ("MARKETING", "MIXED"):
        return TRAI_COMMUNICATION_TYPES["PROMOTIONAL_COMMERCIAL"]

    # Fallback to inspecting text context if evidence_purpose is UNKNOWN
    if text_context:
        t_lower = text_context.lower()
        has_promo = any(kw in t_lower for kw in PROMOTIONAL_KEYWORDS)
        has_txn = any(kw in t_lower for kw in TRANSACTIONAL_KEYWORDS)
        if has_promo and not has_txn:
            return TRAI_COMMUNICATION_TYPES["PROMOTIONAL_COMMERCIAL"]
        if has_txn:
            return TRAI_COMMUNICATION_TYPES["SERVICE_TRANSACTIONAL"]

    return TRAI_COMMUNICATION_TYPES["UNKNOWN"]

# DLT Entity / Parameter Regex Patterns
PE_ID_PARAM_PATTERN = re.compile(r'\b(pe_id|entity_id|principal_entity_id|dlt_entity_id|entityId|peId)\b', re.IGNORECASE)
HEADER_PARAM_PATTERN = re.compile(r'\b(sender_id|dlt_header_id|header_id|senderId|headerId|from_header|sms_header)\b', re.IGNORECASE)
TEMPLATE_PARAM_PATTERN = re.compile(r'\b(template_id|dlt_template_id|templateId|content_template_id)\b', re.IGNORECASE)

PE_ID_VALUE_PATTERN = re.compile(r'\b1\d{18}\b') # Standard 19-digit Indian DLT PE ID starting with 1
TEMPLATE_ID_VALUE_PATTERN = re.compile(r'\b1[0-9]{11,18}\b') # DLT template ID format (12-19 digits)

def detect_dlt_parameters_in_text(text: str) -> Dict[str, bool]:
    """
    Detects presence of DLT entity, header, or template parameter names or value patterns in a given text snippet.
    """
    if not text:
        return {"has_pe_id": False, "has_header": False, "has_template_id": False}

    has_pe = bool(PE_ID_PARAM_PATTERN.search(text) or PE_ID_VALUE_PATTERN.search(text))
    has_hdr = bool(HEADER_PARAM_PATTERN.search(text))
    has_tpl = bool(TEMPLATE_PARAM_PATTERN.search(text) or TEMPLATE_ID_VALUE_PATTERN.search(text))

    return {
        "has_pe_id": has_pe,
        "has_header": has_hdr,
        "has_template_id": has_tpl
    }

def get_trai_dlt_references_for_rule(
    rule_id: str,
    detected_by: Optional[List[str]] = None
) -> List[str]:
    """
    Maps security scanner rule IDs / tool outputs to relevant TRAI requirement IDs where appropriate.
    Attached ONLY when the underlying finding genuinely relates to SMS, telephony, or DLT messaging.
    Unrelated security findings (e.g. SQL injection, JWT secrets) receive empty references.
    """
    if not rule_id:
        return []

    r_lower = rule_id.lower()
    tools = [t.lower() for t in (detected_by or [])]

    if any(kw in r_lower for kw in ["sms", "twilio", "dlt", "telecom"]) or ("phone" in r_lower and "message" in r_lower):
        return ["TRAI-TCCCPR-REG-PE-ID", "TRAI-TCCCPR-REG-HEADER-ID", "TRAI-TCCCPR-REG-TEMPLATE-ID"]

    return []
