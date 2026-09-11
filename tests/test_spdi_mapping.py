"""
Unit tests for SPDI mapping and field classification.
"""
import pytest
from src.compliance.spdi_mapping import classify_spdi_field, get_spdi_references_for_rule
from src.compliance.spdi_constants import SPDI_CATEGORIES, SPDI_REQUIREMENTS

def test_spdi_taxonomy_classification():
    # 1. Passwords -> SPDI Sensitive
    tier, cat, status = classify_spdi_field("user_password")
    assert tier == "SPDI_SENSITIVE"
    assert cat == SPDI_CATEGORIES["PASSWORDS"]
    assert status == "DETECTED"

    # 2. Financial Info -> SPDI Sensitive
    tier, cat, status = classify_spdi_field("bank_account_number")
    assert tier == "SPDI_SENSITIVE"
    assert cat == SPDI_CATEGORIES["FINANCIAL_INFO"]
    assert status == "DETECTED"

    tier, cat, status = classify_spdi_field("credit_card")
    assert tier == "SPDI_SENSITIVE"
    assert cat == SPDI_CATEGORIES["FINANCIAL_INFO"]

    # 3. Health Info -> SPDI Sensitive
    tier, cat, status = classify_spdi_field("health_condition_notes")
    assert tier == "SPDI_SENSITIVE"
    assert cat == SPDI_CATEGORIES["HEALTH_CONDITION"]

    # 4. Biometric Info -> SPDI Sensitive
    tier, cat, status = classify_spdi_field("fingerprint_hash")
    assert tier == "SPDI_SENSITIVE"
    assert cat == SPDI_CATEGORIES["BIOMETRIC_INFO"]

    # 5. Sexual Orientation -> SPDI Sensitive
    tier, cat, status = classify_spdi_field("sexual_orientation")
    assert tier == "SPDI_SENSITIVE"
    assert cat == SPDI_CATEGORIES["SEXUAL_ORIENTATION"]

    # 6. Phone / Email -> Ordinary PII (NOT SPDI Sensitive)
    tier, cat, status = classify_spdi_field("phone_number")
    assert tier == "ORDINARY_PII"
    assert cat is None
    assert status == "DETECTED"

    tier, cat, status = classify_spdi_field("email_address")
    assert tier == "ORDINARY_PII"
    assert cat is None

    # 7. Public domain exemption
    tier, cat, status = classify_spdi_field("public_profile_data", context={"is_public_domain": True})
    assert tier == "PUBLIC_DOMAIN"
    assert status == "PUBLIC_EXEMPT"

    # 8. Ambiguous Field -> Indeterminate
    tier, cat, status = classify_spdi_field("unknown_generic_field")
    assert tier == "AMBIGUOUS"
    assert cat is None
    assert status == "INDETERMINATE"

def test_spdi_rule_mapping_helpers():
    refs = get_spdi_references_for_rule("snyk/vuln-123", detected_by=["snyk"], severity="high")
    assert "SPDI-RULE-8-REASONABLE-SECURITY" in refs

    refs_empty = get_spdi_references_for_rule("unknown-rule", detected_by=["custom"], severity="info")
    assert refs_empty == []
