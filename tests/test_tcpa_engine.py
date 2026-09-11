"""
Unit tests for US TCPA compliance engine.
"""

import os
import pytest
from src.core.models import Finding, ComplianceFindingType, ToolStatus
from src.compliance.tcpa_engine import (
    evaluate_tcpa_applicability,
    check_tcpa_communication_channels,
    check_tcpa_consent_evidence,
    check_tcpa_opt_out_stop,
    check_tcpa_suppression,
    check_tcpa_automation_autodialer,
    check_tcpa_voice_calling,
    generate_tcpa_attestations,
    run_tcpa_checks
)

def test_tcpa_applicability_env_overrides(monkeypatch):
    monkeypatch.setenv("TCPA_APPLICABILITY", "APPLICABLE")
    state, reasons, source = evaluate_tcpa_applicability(".")
    assert state == "APPLICABLE"
    assert source == "ENVIRONMENT_OVERRIDE"

    monkeypatch.setenv("TCPA_APPLICABILITY", "NOT_APPLICABLE")
    state, reasons, source = evaluate_tcpa_applicability(".")
    assert state == "NOT_APPLICABLE"
    assert source == "ENVIRONMENT_OVERRIDE"

    monkeypatch.setenv("TCPA_APPLICABILITY", "INDETERMINATE")
    state, reasons, source = evaluate_tcpa_applicability(".")
    assert state == "INDETERMINATE"
    assert source == "ENVIRONMENT_OVERRIDE"

    monkeypatch.setenv("TCPA_APPLICABILITY", "INVALID_VAL")
    with pytest.raises(ValueError, match="Invalid TCPA_APPLICABILITY override value"):
        evaluate_tcpa_applicability(".")

def test_tcpa_applicability_technical_evidence(monkeypatch):
    monkeypatch.delenv("TCPA_APPLICABILITY", raising=False)
    flow_data = {
        "third_party_transfers": [{"service": "Twilio SMS", "processor": "twilio", "field": "phone_number"}],
        "personal_data_inventory": [{"field_name": "phone_number", "location": {"file": "user.py", "line": 10}}]
    }
    state, reasons, source = evaluate_tcpa_applicability(".", flow_data)
    assert state == "APPLICABLE"
    assert source == "TECHNICAL_EVIDENCE"
    assert len(reasons) > 0

def test_tcpa_applicability_indeterminate_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("TCPA_APPLICABILITY", raising=False)
    empty_dir = str(tmp_path)
    state, reasons, source = evaluate_tcpa_applicability(empty_dir, {})
    assert state == "INDETERMINATE"
    assert source == "HUMAN_REVIEW"

def test_check_tcpa_communication_channels():
    flow_data = {
        "personal_data_inventory": [{"field_name": "mobile_phone", "location": {"file": "auth.py", "line": 5}}],
        "third_party_transfers": [{"service": "Twilio", "field": "mobile_phone"}]
    }
    findings = check_tcpa_communication_channels(".", flow_data)
    assert len(findings) == 1
    assert findings[0].rule_id == "TCPA-227-B-1-A-CALLS-CONSENT"
    assert findings[0].compliance_finding_type == ComplianceFindingType.INVENTORY

def test_check_tcpa_consent_evidence(tmp_path):
    # Test when consent flag exists
    consent_file = tmp_path / "signup.js"
    consent_file.write_text("const tcpa_consent = true; const phone_consent = checkOptIn();", encoding="utf-8")
    
    findings = check_tcpa_consent_evidence(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].compliance_finding_type == ComplianceFindingType.INVENTORY

    # Test when no consent flag exists
    empty_path = tmp_path / "empty_dir"
    empty_path.mkdir()
    findings_empty = check_tcpa_consent_evidence(str(empty_path))
    assert len(findings_empty) == 1
    assert findings_empty[0].compliance_finding_type == ComplianceFindingType.ATTESTATION_REQUIRED

def test_check_tcpa_opt_out_stop(tmp_path):
    webhook_file = tmp_path / "sms_webhook.py"
    webhook_file.write_text("def handle_incoming_sms(body):\n    if body.lower() == 'stop':\n        unsubscribe_user()", encoding="utf-8")
    
    findings = check_tcpa_opt_out_stop(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].compliance_finding_type == ComplianceFindingType.INVENTORY
    assert "TCPA-64-1200-SMS-OPT-OUT" in findings[0].tcpa_references

def test_check_tcpa_suppression(tmp_path):
    model_file = tmp_path / "models.py"
    model_file.write_text("class DoNotCallList(db.Model):\n    phone_number = db.Column(db.String)\n    suppression_date = db.Column(db.DateTime)", encoding="utf-8")
    
    findings = check_tcpa_suppression(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].compliance_finding_type == ComplianceFindingType.INVENTORY

def test_check_tcpa_automation_autodialer(tmp_path):
    task_file = tmp_path / "tasks.py"
    task_file.write_text("from celery import shared_task\nimport twilio\n@shared_task\ndef batch_sms_dispatch(): pass", encoding="utf-8")
    
    findings = check_tcpa_automation_autodialer(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "TCPA-AUTODIALER-ATDS-MONITOR"

def test_check_tcpa_voice_calling(tmp_path):
    ivr_file = tmp_path / "ivr.py"
    ivr_file.write_text("twiml = '<Response><Say>Hello customer</Say></Response>'", encoding="utf-8")
    
    findings = check_tcpa_voice_calling(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "TCPA-227-B-1-B-PRERECORDED-VOICE"

def test_generate_tcpa_attestations():
    attestations = generate_tcpa_attestations("APPLICABLE")
    assert len(attestations) == 2
    assert all(a.compliance_finding_type == ComplianceFindingType.ATTESTATION_REQUIRED for a in attestations)

def test_run_tcpa_checks(tmp_path, monkeypatch):
    monkeypatch.setenv("TCPA_APPLICABILITY", "APPLICABLE")
    
    shared_finding = Finding(
        category="security",
        severity="high",
        file="auth.py",
        line=10,
        message="Insecure Twilio SMS authentication bypass pattern",
        rule_id="twilio-auth-bypass",
        status="OPEN"
    )

    summary, findings = run_tcpa_checks(str(tmp_path), {}, [shared_finding])
    assert summary["status"] == ToolStatus.COMPLETED.value
    assert summary["applicability"] == "APPLICABLE"
    assert len(findings) > 0
    assert "TCPA-227-B-1-A-CALLS-CONSENT" in shared_finding.tcpa_references
