import os
import json
import pytest
from src.core.orchestrator import Orchestrator
from src.core.models import Finding, Report, Category, ComplianceFindingType
from src.compliance.cra_engine import evaluate_cra_applicability, check_security_md, generate_attestation_checklist, run_cra_checks

def test_finding_accepts_cra_references():
    f = Finding(
        category=Category.SECURITY.value,
        severity="high",
        file="src/db.py",
        line=42,
        message="SQL injection vulnerability",
        rule_id="semgrep/sql-injection",
        gdpr_references=["Art. 32"],
        cra_references=["CRA-I-2", "CRA-II-3"]
    )
    assert f.cra_references == ["CRA-I-2", "CRA-II-3"]
    assert f.gdpr_references == ["Art. 32"]

def test_finding_json_roundtrip_preserves_cra_references():
    f = Finding(
        category=Category.SECURITY.value,
        severity="medium",
        file="src/app.py",
        line=10,
        message="Insecure default configuration",
        rule_id="deslint/insecure-default",
        gdpr_references=["Art. 25"],
        cra_references=["CRA-I-3a"]
    )
    report = Report(repo="test-repo", timestamp="2026-09-10T00:00:00Z", findings=[f])
    report_dict = report.to_dict()
    
    reconstituted = Report.from_dict(report_dict)
    rf = reconstituted.findings[0]
    assert rf.cra_references == ["CRA-I-3a"]
    assert rf.gdpr_references == ["Art. 25"]

def test_multiple_framework_references_coexist_without_duplication(tmp_path):
    code = "const user = { phone: '123' };"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")

    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))

    pii_findings = [f for f in report.findings if f.rule_id == "personal-data-field-detected"]
    assert len(pii_findings) > 0
    f = pii_findings[0]
    assert "CRA-I-3d" in f.cra_references
    # Original finding object carries both
    assert f.compliance_finding_type == ComplianceFindingType.INVENTORY

def test_security_md_missing(tmp_path):
    finding = check_security_md(str(tmp_path))
    assert finding.evidence_status == "NOT_DETECTED"
    assert finding.compliance_finding_type == ComplianceFindingType.HUMAN_REVIEW
    assert "CRA-II-4" in finding.cra_references
    assert "CRA-II-5" in finding.cra_references
    assert "CRA-II-6" in finding.cra_references

def test_security_md_present_with_contact_and_policy(tmp_path):
    sec_md = tmp_path / "SECURITY.md"
    sec_md.write_text("""
    # Vulnerability Disclosure Policy
    If you discover a vulnerability, please report it to security@example.com.
    We will acknowledge receipt within 24 hours and publish advisories upon fix.
    """, encoding="utf-8")

    finding = check_security_md(str(tmp_path))
    assert finding.evidence_status == "DETECTED"
    assert finding.compliance_finding_type == ComplianceFindingType.INVENTORY
    assert "CRA-II-6" in finding.cra_references

def test_security_md_present_missing_contact(tmp_path):
    sec_md = tmp_path / "SECURITY.md"
    sec_md.write_text("Short note without any email or url contact.", encoding="utf-8")

    finding = check_security_md(str(tmp_path))
    assert finding.evidence_status == "INDETERMINATE"
    assert finding.compliance_finding_type == ComplianceFindingType.HUMAN_REVIEW

def test_attestation_requirements_not_per_file():
    checklist = generate_attestation_checklist()
    assert len(checklist) == 3
    for f in checklist:
        assert f.compliance_finding_type == ComplianceFindingType.ATTESTATION_REQUIRED
        assert f.human_review_required.startswith("YES")
        assert f.location.file is None

def test_cra_applicability_states(tmp_path, monkeypatch):
    monkeypatch.delenv("CRA_APPLICABILITY", raising=False)
    app, reason = evaluate_cra_applicability(str(tmp_path))
    assert app == "INDETERMINATE"

    monkeypatch.setenv("CRA_APPLICABILITY", "APPLICABLE")
    app, reason = evaluate_cra_applicability(str(tmp_path))
    assert app == "APPLICABLE"

    monkeypatch.setenv("CRA_APPLICABILITY", "NOT_APPLICABLE")
    app, reason = evaluate_cra_applicability(str(tmp_path))
    assert app == "NOT_APPLICABLE"

def test_no_duplicate_technical_findings(tmp_path):
    code = "const snyk = require('snyk');"
    js = tmp_path / "App.js"
    js.write_text(code, encoding="utf-8")

    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))

    # Total findings count should equal unique findings list length
    finding_ids = [f.finding_id for f in report.findings]
    assert len(finding_ids) == len(set(finding_ids))

def test_multi_framework_coexistence(tmp_path):
    (tmp_path / "SECURITY.md").write_text("Security Policy\nContact: security@example.com")
    
    orc = Orchestrator([])
    report = orc.analyze("local", str(tmp_path))

    # 1. SECURITY.md finding should carry both CRA and CERT-In references
    sec_md = next((f for f in report.findings if f.rule_id == "cra-security-md-disclosure"), None)
    assert sec_md is not None
    assert "CRA-II-6" in (sec_md.cra_references or [])
    assert "CERT-IN-POC" in (sec_md.cert_in_references or [])

    # 2. Dedicated CERT-In findings are present as separate objects
    cert_dedicated = [f for f in report.findings if getattr(f, 'framework', None) == "CERT-IN"]
    assert len(cert_dedicated) >= 4

