"""
Requirement Mapping and SPDI Classification Helpers for India IT (SPDI Rules, 2011).
"""

from typing import List, Dict, Any, Optional, Tuple
from src.compliance.spdi_constants import (
    FRAMEWORK_SPDI,
    SPDI_CATEGORIES,
    SPDI_REQUIREMENTS
)

# Canonical Sensitive Keyword Patterns (Rule 3)
SENSITIVE_PATTERNS = {
    SPDI_CATEGORIES["PASSWORDS"]: [
        "password", "passwd", "pwd", "passcode", "secret_pin", "auth_token_secret", "user_password"
    ],
    SPDI_CATEGORIES["FINANCIAL_INFO"]: [
        "bank_account", "account_number", "card_number", "credit_card", "debit_card",
        "cvv", "pan_number", "financial_details", "iban", "swift_code", "payment_card", "bank_details"
    ],
    SPDI_CATEGORIES["HEALTH_CONDITION"]: [
        "health_condition", "physical_health", "mental_health", "diagnosis", "medical_condition"
    ],
    SPDI_CATEGORIES["SEXUAL_ORIENTATION"]: [
        "sexual_orientation", "gender_identity_sensitive"
    ],
    SPDI_CATEGORIES["MEDICAL_RECORDS"]: [
        "medical_history", "medical_record", "patient_record", "prescription", "health_record"
    ],
    SPDI_CATEGORIES["BIOMETRIC_INFO"]: [
        "biometric", "fingerprint", "face_id", "retina_scan", "iris_scan", "dna_profile"
    ]
}

# Ordinary PII Patterns (Explicitly NOT SPDI under Rule 3)
ORDINARY_PII_PATTERNS = [
    "phone", "mobile", "telephone", "phone_number", "email", "email_address",
    "first_name", "last_name", "full_name", "name", "address", "street_address",
    "ip_address", "user_id", "username", "customer_id", "postal_code", "city", "country"
]

# Public Domain / Lawful Disclosure Context Keys
PUBLIC_DOMAIN_KEYWORDS = [
    "public_profile", "public_feed", "open_data", "public_registry", "rti_disclosure", "public_directory"
]

def classify_spdi_field(
    field_name: str,
    context: Optional[Dict[str, Any]] = None
) -> Tuple[str, Optional[str], str]:
    """
    Classifies a data field into the 4-tier SPDI taxonomy:
    1. 'SPDI_SENSITIVE' -> (True, category_name, 'DETECTED')
    2. 'ORDINARY_PII' -> (False, None, 'DETECTED')
    3. 'PUBLIC_DOMAIN' -> (False, None, 'PUBLIC_EXEMPT')
    4. 'AMBIGUOUS' -> (False, None, 'INDETERMINATE')

    Returns tuple: (taxonomy_tier, spdi_category_key, evidence_status)
    """
    if not field_name:
        return ("AMBIGUOUS", None, "INDETERMINATE")

    field_lower = field_name.lower().strip()
    ctx = context or {}

    # Check for public domain / lawful disclosure exclusion first
    if any(k in field_lower for k in PUBLIC_DOMAIN_KEYWORDS) or ctx.get("is_public_domain"):
        return ("PUBLIC_DOMAIN", None, "PUBLIC_EXEMPT")

    # Check SPDI Sensitive categories
    for cat_key, patterns in SENSITIVE_PATTERNS.items():
        for pat in patterns:
            if pat in field_lower:
                return ("SPDI_SENSITIVE", cat_key, "DETECTED")

    # Check Ordinary PII
    for pat in ORDINARY_PII_PATTERNS:
        if pat in field_lower:
            return ("ORDINARY_PII", None, "DETECTED")

    # If evidence is insufficient/ambiguous, return INDETERMINATE
    return ("AMBIGUOUS", None, "INDETERMINATE")

def get_spdi_references_for_rule(
    rule_id: str,
    detected_by: Optional[List[str]] = None,
    severity: Optional[str] = None
) -> List[str]:
    """
    Maps security scanner rule IDs / tool outputs to SPDI Rule 8 reasonable security practice references.
    """
    if not rule_id:
        return []

    r_lower = rule_id.lower()
    tools = [t.lower() for t in (detected_by or [])]

    # Rule 8 Reasonable Security Practices mapping for security scanner findings
    if any(tool in ["snyk", "semgrep", "bandit", "codex-security", "sonarqube"] for tool in tools):
        return ["SPDI-RULE-8-REASONABLE-SECURITY", "SPDI-RULE-5-8-SECURITY-PRACTICES"]

    if any(kw in r_lower for kw in ["crypto", "cipher", "ssl", "tls", "auth", "login", "jwt", "session", "sqli", "xss", "rce"]):
        return ["SPDI-RULE-8-REASONABLE-SECURITY"]

    return []
