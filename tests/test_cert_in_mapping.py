import pytest
from src.compliance.cert_in_mapping import get_cert_in_references_for_rule, CERT_IN_REQUIREMENTS

def test_cert_in_mapping_high_severity_security_finding():
    refs = get_cert_in_references_for_rule("CWE-89", detected_by=["codex-security"], severity="high")
    assert "CERT-IN-ANNEX-3" in refs
    assert "CERT-IN-ANNEX-10" in refs

def test_cert_in_mapping_low_severity_security_finding_filtered():
    # Low severity tool finding should not be tagged under Annexure I wildcard rule
    refs = get_cert_in_references_for_rule("snyk/vuln-1", detected_by=["snyk"], severity="low")
    assert len(refs) == 0

def test_cert_in_mapping_security_md_contact():
    refs = get_cert_in_references_for_rule("cra-security-md-disclosure")
    assert "CERT-IN-POC" in refs

def test_cert_in_requirements_metadata():
    assert "CERT-IN-ANNEX-1" in CERT_IN_REQUIREMENTS
    assert "CERT-IN-ANNEX-20" in CERT_IN_REQUIREMENTS
    assert "CERT-IN-POC" in CERT_IN_REQUIREMENTS
    assert "CERT-IN-LOG-RETENTION" in CERT_IN_REQUIREMENTS
    assert "CERT-IN-NTP" in CERT_IN_REQUIREMENTS
    assert "CERT-IN-KYC" in CERT_IN_REQUIREMENTS
