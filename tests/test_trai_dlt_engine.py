"""
Unit tests for India TRAI / TCCCPR / DLT compliance engine.
"""

import os
import pytest
from src.core.models import Finding, ComplianceFindingType, Category, Severity
from src.compliance.communication_models import CommunicationFlowEvidence
from src.compliance.trai_dlt_engine import (
    evaluate_trai_dlt_applicability,
    check_trai_dlt_entity_registration,
    check_trai_dlt_header_sender_id,
    check_trai_dlt_template_registration,
    check_trai_dlt_promotional_controls,
    generate_trai_dlt_attestations,
    run_trai_dlt_checks
)

def test_trai_dlt_applicability_env_overrides(monkeypatch):
    monkeypatch.setenv("TRAI_APPLICABILITY", "APPLICABLE")
    res = evaluate_trai_dlt_applicability(".", None, [])
    assert res["status"] == "APPLICABLE"
    assert res["evaluation_method"] == "ENVIRONMENT_OVERRIDE"

    monkeypatch.setenv("TRAI_APPLICABILITY", "NOT_APPLICABLE")
    res = evaluate_trai_dlt_applicability(".", None, [])
    assert res["status"] == "NOT_APPLICABLE"

    monkeypatch.setenv("TRAI_APPLICABILITY", "INDETERMINATE")
    res = evaluate_trai_dlt_applicability(".", None, [])
    assert res["status"] == "INDETERMINATE"

    monkeypatch.setenv("TRAI_APPLICABILITY", "INVALID_VALUE")
    with pytest.raises(ValueError, match="Invalid TRAI_APPLICABILITY environment variable value"):
        evaluate_trai_dlt_applicability(".", None, [])

def test_trai_dlt_applicability_technical_evidence(monkeypatch):
    monkeypatch.delenv("TRAI_APPLICABILITY", raising=False)

    # 1. No SMS flows -> NOT_APPLICABLE
    res_none = evaluate_trai_dlt_applicability(".", None, [])
    assert res_none["status"] == "NOT_APPLICABLE"

    # 2. SMS flow with +91 country code -> APPLICABLE
    ev_india = [
        CommunicationFlowEvidence(
            flow_id="f1",
            channel="SMS",
            provider="twilio",
            purpose="TRANSACTIONAL",
            source_locations=[{"file": "src/services/sms.py", "line": 10}]
        )
    ]
    # Attach code_snippet for context
    setattr(ev_india[0], "code_snippet", "client.messages.create(to='+919876543210', body='OTP 1234')")

    res_app = evaluate_trai_dlt_applicability(".", None, ev_india)
    assert res_app["status"] == "APPLICABLE"

    # 3. SMS flow without India indicator -> INDETERMINATE
    ev_generic = [
        CommunicationFlowEvidence(
            flow_id="f2",
            channel="SMS",
            provider="twilio",
            purpose="TRANSACTIONAL",
            source_locations=[{"file": "src/services/sms.py", "line": 10}]
        )
    ]
    res_ind = evaluate_trai_dlt_applicability(".", None, ev_generic)
    assert res_ind["status"] == "INDETERMINATE"

def test_check_trai_dlt_entity_registration():
    ev_missing = [
        CommunicationFlowEvidence(
            flow_id="f1",
            channel="SMS",
            provider="twilio",
            purpose="TRANSACTIONAL",
            source_locations=[{"file": "src/sms.py", "line": 15}]
        )
    ]
    findings_missing = check_trai_dlt_entity_registration(".", ev_missing)
    assert len(findings_missing) == 1
    assert findings_missing[0].rule_id == "TRAI-TCCCPR-REG-PE-ID"
    assert findings_missing[0].compliance_finding_type == ComplianceFindingType.ATTESTATION_REQUIRED
    # Must never be reported as automatic statutory VIOLATION
    assert findings_missing[0].compliance_finding_type != ComplianceFindingType.VIOLATION

    ev_present = [
        CommunicationFlowEvidence(
            flow_id="f2",
            channel="SMS",
            provider="twilio",
            purpose="TRANSACTIONAL",
            source_locations=[{"file": "src/sms.py", "line": 15}]
        )
    ]
    setattr(ev_present[0], "code_snippet", "pe_id='1401999999999999999'")

    findings_present = check_trai_dlt_entity_registration(".", ev_present)
    assert len(findings_present) == 1
    assert findings_present[0].compliance_finding_type == ComplianceFindingType.INVENTORY

def test_check_trai_dlt_promotional_controls():
    ev_promo = [
        CommunicationFlowEvidence(
            flow_id="f1",
            channel="SMS",
            provider="twilio",
            purpose="MARKETING",
            source_locations=[{"file": "src/marketing.py", "line": 20}]
        )
    ]
    findings = check_trai_dlt_promotional_controls(".", ev_promo)
    assert len(findings) == 2
    rule_ids = [f.rule_id for f in findings]
    assert "TRAI-TCCCPR-PROMOTIONAL-TIMING" in rule_ids
    assert "TRAI-TCCCPR-PREFERENCE-DND" in rule_ids

def test_run_trai_dlt_checks_decoupled_with_mock_evidence(monkeypatch):
    monkeypatch.setenv("TRAI_APPLICABILITY", "APPLICABLE")

    # Mock shared communication flow evidence
    mock_comm_evidence = [
        CommunicationFlowEvidence(
            flow_id="f1",
            channel="SMS",
            provider="twilio",
            purpose="TRANSACTIONAL",
            source_locations=[{"file": "src/otp.py", "line": 10}]
        )
    ]

    shared_finding = Finding(
        category=Category.SECURITY.value,
        severity="medium",
        file="src/otp.py",
        line=10,
        message="Hardcoded SMS credential in twilio call",
        rule_id="twilio-hardcoded-secret",
        detected_by=["semgrep"]
    )

    findings = run_trai_dlt_checks(
        repo_path=".",
        flow_data=None,
        shared_findings=[shared_finding],
        comm_evidence=mock_comm_evidence
    )

    assert len(findings) > 0

    # Ensure all generated findings have framework set to TRAI_DLT and trai_dlt_references
    for f in findings:
        assert f.framework == "TRAI_DLT"
        assert f.effective_status == "IN_FORCE"
        assert f.trai_dlt_references is not None
        assert len(f.trai_dlt_references) > 0

    # Verify shared security finding was enriched with TRAI references
    assert shared_finding.trai_dlt_references is not None
    assert "TRAI-TCCCPR-REG-PE-ID" in shared_finding.trai_dlt_references
