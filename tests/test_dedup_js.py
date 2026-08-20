from src.core.models import Finding, Category
from src.core.dedup import deduplicate_findings

def test_dedup_snyk_depscan():
    f1 = Finding(
        category=Category.DEPENDENCIES.value,
        severity="high",
        file="package.json",
        line=0,
        message="Prototype Pollution in lodash@4.17.15",
        rule_id="CVE-2019-10744",
        detected_by=["snyk"]
    )
    
    f2 = Finding(
        category=Category.DEPENDENCIES.value,
        severity="high",
        file="package.json",
        line=0,
        message="Prototype Pollution in lodash@4.17.15",
        rule_id="CVE-2019-10744",
        detected_by=["dep-scan"]
    )
    
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 1
    assert set(deduped[0].detected_by) == {"snyk", "dep-scan"}

def test_no_dedup_different_vulns():
    f1 = Finding(
        category=Category.DEPENDENCIES.value,
        severity="high",
        file="package.json",
        line=0,
        message="Prototype Pollution in lodash@4.17.15",
        rule_id="CVE-2019-10744",
        detected_by=["snyk"]
    )
    
    f2 = Finding(
        category=Category.DEPENDENCIES.value,
        severity="medium",
        file="package.json",
        line=0,
        message="Command Injection in lodash@4.17.15",
        rule_id="CVE-2020-8203",
        detected_by=["dep-scan"]
    )
    
    deduped = deduplicate_findings([f1, f2])
    assert len(deduped) == 2
