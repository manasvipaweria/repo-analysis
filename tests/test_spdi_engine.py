"""
Comprehensive unit tests for SPDI Engine (India IT SPDI Rules, 2011).
"""
import pytest
import os
import json
from src.core.models import Finding, Report, ComplianceFindingType, Category, CategorySummary, CategoryStatus
from src.compliance.spdi_engine import (
    evaluate_spdi_applicability,
    check_spdi_sensitive_data_inventory,
    check_spdi_rule5_provisions,
    check_spdi_privacy_policy,
    check_spdi_security_practices,
    check_spdi_third_party_disclosure,
    check_spdi_cross_border_transfer,
    check_spdi_retention_deletion,
    check_spdi_grievance_contact,
    run_spdi_checks
)

def test_spdi_applicability_evaluation(tmp_path):
    repo_dir = str(tmp_path)
    state, reason = evaluate_spdi_applicability(repo_dir)
    assert state in ["APPLICABLE", "INDETERMINATE"]

    # Test env override
    os.environ["SPDI_APPLICABILITY"] = "APPLICABLE"
    try:
        state_env, _ = evaluate_spdi_applicability(repo_dir)
        assert state_env == "APPLICABLE"
    finally:
        os.environ.pop("SPDI_APPLICABILITY", None)

def test_spdi_sensitive_vs_ordinary_pii_inventory():
    flow_data = {
        "pii_fields": [
            {"field": "user_password", "file": "src/auth.py", "line": 12},
            {"field": "bank_account_no", "file": "src/pay.py", "line": 45},
            {"field": "phone_number", "file": "src/user.py", "line": 10},
            {"field": "email_address", "file": "src/user.py", "line": 11},
            {"field": "ambiguous_data", "file": "src/util.py", "line": 5}
        ]
    }

    findings = check_spdi_sensitive_data_inventory(flow_data)
    rule_ids = [f.rule_id for f in findings]

    assert "spdi-rule3-sensitive-data-detected" in rule_ids
    assert "spdi-rule3-ordinary-pii-detected" in rule_ids
    assert "spdi-rule3-ambiguous-data-classification" in rule_ids

    # Verify phone/email is Ordinary PII and NOT SPDI Sensitive
    phone_finding = next(f for f in findings if f.title == "SPDI Ordinary PII: phone_number")
    assert phone_finding.spdi_references == ["SPDI-RULE-3-ORDINARY-PII"]
    assert "are not automatically SPDI Sensitive Personal Data" in phone_finding.description

    # Verify password is SPDI Sensitive
    pass_finding = next(f for f in findings if f.title == "SPDI Sensitive Data: user_password")
    assert pass_finding.spdi_references == ["SPDI-RULE-3-SENSITIVE-TAXONOMY"]

def test_spdi_privacy_policy_detection(tmp_path):
    repo_dir = str(tmp_path)
    # Absent policy
    absent_findings = check_spdi_privacy_policy(repo_dir)
    assert absent_findings[0].evidence_status == "NOT_DETECTED"
    assert absent_findings[0].compliance_finding_type == ComplianceFindingType.ATTESTATION_REQUIRED

    # Create Privacy Policy file
    p_file = tmp_path / "PRIVACY_POLICY.md"
    p_file.write_text("# Privacy Policy\nWe protect your SPDI data.", encoding="utf-8")

    present_findings = check_spdi_privacy_policy(repo_dir)
    assert present_findings[0].evidence_status == "DETECTED"
    assert present_findings[0].spdi_references == ["SPDI-RULE-4-PRIVACY-POLICY"]

def test_spdi_security_practices_iso27001_guardrail(tmp_path):
    repo_dir = str(tmp_path)

    # Absent ISMS
    absent_findings = check_spdi_security_practices(repo_dir, [])
    assert absent_findings[0].evidence_status == "NOT_DETECTED"
    assert absent_findings[0].compliance_finding_type == ComplianceFindingType.ATTESTATION_REQUIRED

    # Create document with ISO 27001 reference
    sec_file = tmp_path / "SECURITY.md"
    sec_file.write_text("Complies with ISO/IEC 27001 ISMS standard.", encoding="utf-8")

    present_findings = check_spdi_security_practices(repo_dir, [])
    assert present_findings[0].evidence_status == "DETECTED"
    assert "ISO/IEC 27001" in present_findings[0].description
    assert "Confirm independent audit status" in present_findings[0].human_review_required

def test_spdi_third_party_disclosure_and_cross_border():
    flow_data = {
        "third_party_transfers": [
            {"processor": "stripe", "field": "bank_account_no", "file": "src/pay.py", "line": 50},
            {"processor": "twilio", "field": "phone_number", "file": "src/sms.py", "line": 20}
        ],
        "outbound_calls": ["api.stripe.com/v1/charges"]
    }

    disc_findings = check_spdi_third_party_disclosure(flow_data)
    assert len(disc_findings) == 1
    assert disc_findings[0].spdi_references == ["SPDI-RULE-6-THIRD-PARTY-DISCLOSURE"]
    assert disc_findings[0].compliance_finding_type == ComplianceFindingType.THIRD_PARTY_RISK

    cb_findings = check_spdi_cross_border_transfer(flow_data)
    assert len(cb_findings) == 1
    assert cb_findings[0].spdi_references == ["SPDI-RULE-7-CROSS-BORDER-TRANSFER"]

def test_spdi_retention_deletion_detection(tmp_path):
    repo_dir = str(tmp_path)
    del_file = tmp_path / "cleanup.py"
    del_file.write_text("def purge_user(): expireAfterSeconds = 86400", encoding="utf-8")

    ret_findings = check_spdi_retention_deletion(repo_dir)
    assert ret_findings[0].evidence_status == "DETECTED"
    assert "SPDI-RULE-7-RETENTION-DELETION" in ret_findings[0].spdi_references

def test_multi_framework_coexistence_and_serialization():
    # Test single finding carrying GDPR, CRA, CERT-In, and SPDI references simultaneously
    f = Finding(
        category=Category.SECURITY.value,
        severity="high",
        file="src/auth.py",
        line=10,
        message="Vulnerable encryption algorithm used.",
        rule_id="snyk/vuln-crypto-1",
        detected_by=["snyk"],
        gdpr_references=["Art. 32"],
        cra_references=["CRA-I-1"],
        cert_in_references=["CERT-IN-INCIDENT-CAT-1"],
        spdi_references=["SPDI-RULE-8-REASONABLE-SECURITY"]
    )

    assert "Art. 32" in f.gdpr_references
    assert "CRA-I-1" in f.cra_references
    assert "CERT-IN-INCIDENT-CAT-1" in f.cert_in_references
    assert "SPDI-RULE-8-REASONABLE-SECURITY" in f.spdi_references

    report = Report(
        repo="test-repo",
        timestamp="2026-09-11T12:00:00Z",
        summary={"security": CategorySummary(status=CategoryStatus.ISSUES_FOUND, count=1)},
        findings=[f]
    )

    r_dict = report.to_dict()
    assert r_dict["findings"][0]["spdi_references"] == ["SPDI-RULE-8-REASONABLE-SECURITY"]

    restored_report = Report.from_dict(json.loads(json.dumps(r_dict)))
    restored_f = restored_report.findings[0]
    assert restored_f.spdi_references == ["SPDI-RULE-8-REASONABLE-SECURITY"]
    assert restored_f.gdpr_references == ["Art. 32"]
    assert restored_f.cra_references == ["CRA-I-1"]
    assert restored_f.cert_in_references == ["CERT-IN-INCIDENT-CAT-1"]
