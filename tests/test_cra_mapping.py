import pytest
from src.core.models import Finding, Report, Category, ComplianceFindingType
from src.compliance.cra_mapping import get_cra_references_for_rule, CRA_REQUIREMENTS

def test_cra_mapping_snyk():
    refs = get_cra_references_for_rule("snyk/SNYK-JS-LODASH-567746")
    assert "CRA-I-2" in refs
    assert "CRA-II-2" in refs

def test_cra_mapping_depscan():
    refs = get_cra_references_for_rule("dep-scan/vulnerability-123")
    assert "CRA-I-2" in refs
    assert "CRA-II-2" in refs

def test_cra_mapping_pip_audit():
    refs = get_cra_references_for_rule("pip-audit/PYSEC-2023-1")
    assert "CRA-I-2" in refs
    assert "CRA-II-2" in refs

def test_cra_mapping_semgrep():
    refs = get_cra_references_for_rule("semgrep/java.lang.security.audit.crypto")
    assert "CRA-II-3" in refs

def test_cra_mapping_bandit():
    refs = get_cra_references_for_rule("bandit/B101")
    assert "CRA-II-3" in refs

def test_cra_mapping_codex_security():
    refs = get_cra_references_for_rule("codex-security/CWE-89")
    assert "CRA-II-3" in refs

def test_cra_mapping_codex_architecture():
    refs = get_cra_references_for_rule("codex-architecture/tight-coupling")
    assert "CRA-I-1" in refs

def test_cra_mapping_sbom_cdxgen():
    refs = get_cra_references_for_rule("cdxgen/sbom-outdated")
    assert "CRA-II-1" in refs

def test_cra_mapping_storage_protection():
    refs = get_cra_references_for_rule("unprotected-pii-storage")
    assert "CRA-I-3b" in refs

def test_cra_mapping_deduplication():
    refs = get_cra_references_for_rule("snyk/CVE-2023-1234", detected_by=["snyk"])
    assert len(refs) == len(set(refs))
    assert refs == sorted(refs)
