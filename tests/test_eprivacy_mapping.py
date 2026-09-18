import pytest
from src.compliance.eprivacy_mapping import get_eprivacy_references_for_rule

def test_eprivacy_security_mapping():
    # Security properties map to Art 4/5
    assert "EPRIVACY-ART4-SECURITY" in get_eprivacy_references_for_rule("CWE-319", ["bandit"])
    assert "EPRIVACY-ART5-CONFIDENTIALITY" in get_eprivacy_references_for_rule("insecure-transport", ["bandit"])

def test_eprivacy_generic_security_unmapped():
    # Generic security findings like SQLi should NOT map to ePrivacy automatically
    assert not get_eprivacy_references_for_rule("CWE-89", ["bandit"])
    assert not get_eprivacy_references_for_rule("generic-xss", ["semgrep"])

def test_eprivacy_cleartext_mapping():
    assert "EPRIVACY-ART4-SECURITY" not in get_eprivacy_references_for_rule("cleartext-transmission") 
    # Actually wait, cleartext-transmission maps to Art 5
    refs = get_eprivacy_references_for_rule("cleartext-transmission")
    assert "EPRIVACY-ART5-CONFIDENTIALITY" in refs
