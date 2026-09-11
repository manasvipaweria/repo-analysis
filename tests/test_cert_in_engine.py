import os
import pytest
from src.core.models import Finding, ComplianceFindingType
from src.compliance.cert_in_engine import (
    evaluate_cert_in_applicability,
    check_log_retention_and_residency,
    check_ntp_synchronization,
    generate_cert_in_attestations,
    run_cert_in_checks
)

def test_cert_in_entity_type_validation_default(tmp_path):
    with patch_env({"CERTIN_ENTITY_TYPE": "GENERAL"}):
        app, entity, reason = evaluate_cert_in_applicability(str(tmp_path))
        assert app == "APPLICABLE"
        assert entity == "GENERAL"

def test_cert_in_entity_type_validation_invalid(tmp_path):
    with patch_env({"CERTIN_ENTITY_TYPE": "UNSUPPORTED_TYPE"}):
        with pytest.raises(ValueError) as excinfo:
            evaluate_cert_in_applicability(str(tmp_path))
        assert "Invalid CERTIN_ENTITY_TYPE" in str(excinfo.value)

def test_cert_in_entity_type_general_no_kyc(tmp_path):
    attestations = generate_cert_in_attestations("GENERAL")
    kyc_items = [a for a in attestations if a.rule_id == "cert-in-5vi-5yr-kyc-recordkeeping-attestation"]
    assert len(kyc_items) == 0

def test_cert_in_entity_type_datacenter_has_kyc(tmp_path):
    attestations = generate_cert_in_attestations("DATA_CENTER")
    kyc_items = [a for a in attestations if a.rule_id == "cert-in-5vi-5yr-kyc-recordkeeping-attestation"]
    assert len(kyc_items) == 1
    assert "DATA_CENTER" in kyc_items[0].title

def test_log_retention_and_residency_detected(tmp_path):
    (tmp_path / "main.tf").write_text('provider "aws" { region = "ap-south-1" }\nresource "aws_cloudwatch_log_group" "app" { retention_in_days = 180 }')
    finding = check_log_retention_and_residency(str(tmp_path))
    assert finding.evidence_status == "DETECTED"
    assert finding.compliance_finding_type == ComplianceFindingType.INVENTORY
    assert "evidence of configured retention/residency" in finding.description
    assert "NOT proof" in finding.description

def test_log_retention_missing_not_a_violation(tmp_path):
    (tmp_path / "README.md").write_text("# Project")
    finding = check_log_retention_and_residency(str(tmp_path))
    assert finding.evidence_status == "NOT_DETECTED"
    assert finding.compliance_finding_type == ComplianceFindingType.SECURITY_GAP
    assert "not automatically a CERT-In violation" in finding.description

def test_ntp_sync_detected(tmp_path):
    (tmp_path / "Dockerfile").write_text('RUN apt-get update && apt-get install -y chrony\nRUN echo "server pool.ntp.org iburst" >> /etc/chrony/chrony.conf')
    finding = check_ntp_synchronization(str(tmp_path))
    assert finding.evidence_status == "DETECTED"
    assert finding.compliance_finding_type == ComplianceFindingType.INVENTORY
    assert "evidence of configured time sync only" in finding.description

def test_ntp_sync_missing_not_a_violation(tmp_path):
    (tmp_path / "README.md").write_text("# Project")
    finding = check_ntp_synchronization(str(tmp_path))
    assert finding.evidence_status == "NOT_DETECTED"
    assert finding.compliance_finding_type == ComplianceFindingType.SECURITY_GAP
    assert "not automatically a CERT-In violation" in finding.description

def test_run_cert_in_checks_reference_tagging_and_errored_tool_isolation(tmp_path):
    f_completed = Finding(
        category="security",
        severity="high",
        file="src/db.py",
        line=10,
        message="SQL Injection flaw",
        rule_id="codex-sec/sql-injection",
        detected_by=["codex-security"]
    )
    
    # Existing findings to tag
    shared_findings = [f_completed]
    
    with patch_env({"CERTIN_ENTITY_TYPE": "GENERAL"}):
        cert_findings = run_cert_in_checks(str(tmp_path), shared_findings)
        
        # Verify reference tagging on completed finding
        assert "CERT-IN-ANNEX-3" in f_completed.cert_in_references
        assert "CERT-IN-ANNEX-10" in f_completed.cert_in_references
        
        # Verify dedicated findings created
        dedicated = [f for f in cert_findings if f.framework == "CERT-IN"]
        assert len(dedicated) >= 4  # retention, ntp, 6h SLA, log attestation, ntp attestation

def patch_env(env_dict):
    from unittest.mock import patch
    return patch.dict(os.environ, env_dict, clear=False)
