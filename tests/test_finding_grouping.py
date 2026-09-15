import pytest
from src.core.models import Finding, FindingLocation, FindingGroup, GroupConfidence, ComplianceFindingType
from src.core.finding_grouping import group_findings, generate_group_id

def create_finding(fid, rule, file, category="security", severity="medium", framework=None, compliance_type=None, evidence=None):
    f = Finding(
        finding_id=fid,
        category=category,
        severity=severity,
        file=file,
        line=10,
        message="Test finding",
        rule_id=rule,
        detected_by=["tool"],
        framework=framework,
        compliance_finding_type=compliance_type,
        detected_evidence=evidence
    )
    # Give a dummy fingerprint so it looks legit
    f.fingerprint = f"{fid}_hash"
    return f

def test_identical_fingerprints():
    # If deduplication happened properly, there are no identical fingerprints.
    # But if there are, grouping groups them?
    # Grouping rule is based on file/rule, so they'd group.
    f1 = create_finding("1", "ruleA", "src/foo.py")
    f2 = create_finding("2", "ruleA", "src/foo.py")
    f2.fingerprint = f1.fingerprint # simulate identical fingerprint bypass
    
    groups, findings = group_findings([f1, f2])
    
    # Wait, the grouping implementation adds fingerprint to the list if not present:
    # "if f.fingerprint not in groups_map[g_id].fingerprints:"
    # So the group will only have ONE fingerprint! A group with 1 fingerprint is dropped!
    # Therefore, no group is formed.
    assert len(groups) == 0

def test_related_findings_grouped():
    f1 = create_finding("1", "ruleA", "src/foo.py")
    f1.fingerprint = "fp1"
    f2 = create_finding("2", "ruleA", "src/foo.py")
    f2.fingerprint = "fp2"
    
    groups, findings = group_findings([f1, f2])
    
    assert len(groups) == 1
    g = groups[0]
    assert g.confidence == GroupConfidence.HIGH
    assert g.grouping_reason == "Same rule and same source file."
    assert "fp1" in g.fingerprints
    assert "fp2" in g.fingerprints
    assert findings[0].group_id == g.group_id
    assert findings[1].group_id == g.group_id

def test_unrelated_findings_remain_separate():
    f1 = create_finding("1", "ruleA", "src/foo.py")
    f2 = create_finding("2", "ruleB", "src/bar.py")
    
    groups, findings = group_findings([f1, f2])
    
    assert len(groups) == 0
    assert findings[0].group_id is None
    assert findings[1].group_id is None

def test_same_rule_different_files():
    f1 = create_finding("1", "ruleA", "src/foo.py")
    f2 = create_finding("2", "ruleA", "src/bar.py")
    
    groups, findings = group_findings([f1, f2])
    
    assert len(groups) == 0

def test_same_category_no_group():
    f1 = create_finding("1", "ruleA", "src/foo.py", category="security")
    f2 = create_finding("2", "ruleB", "src/bar.py", category="security")
    
    groups, findings = group_findings([f1, f2])
    assert len(groups) == 0

def test_different_severity_does_not_prevent_grouping():
    f1 = create_finding("1", "ruleA", "src/foo.py", severity="medium")
    f1.fingerprint = "fp1"
    f2 = create_finding("2", "ruleA", "src/foo.py", severity="high")
    f2.fingerprint = "fp2"
    
    groups, findings = group_findings([f1, f2])
    assert len(groups) == 1

def test_deterministic_group_id():
    f1 = create_finding("1", "ruleA", "src/foo.py")
    f1.fingerprint = "fp1"
    f2 = create_finding("2", "ruleA", "src/foo.py")
    f2.fingerprint = "fp2"
    
    g1, _ = group_findings([f1, f2])
    g2, _ = group_findings([f1, f2])
    
    assert g1[0].group_id == g2[0].group_id

def test_third_party_transfers():
    f1 = create_finding("1", "third-party", None, category="privacy", compliance_type=ComplianceFindingType.THIRD_PARTY_RISK, evidence="Twilio")
    f1.fingerprint = "fp1"
    f2 = create_finding("2", "third-party", None, category="privacy", compliance_type=ComplianceFindingType.THIRD_PARTY_RISK, evidence="Twilio")
    f2.fingerprint = "fp2"
    
    f3 = create_finding("3", "third-party", None, category="privacy", compliance_type=ComplianceFindingType.THIRD_PARTY_RISK, evidence="Stripe")
    f3.fingerprint = "fp3"
    
    groups, findings = group_findings([f1, f2, f3])
    
    # Only Twilio should group
    assert len(groups) == 1
    assert "fp1" in groups[0].fingerprints
    assert "fp2" in groups[0].fingerprints
    assert "fp3" not in groups[0].fingerprints
    assert "Same third-party destination" in groups[0].grouping_reason

def test_compliance_overgrouping_protection():
    # Two GDPR checklist items without exact same evidence should NOT group
    f1 = create_finding("1", "gdpr-checklist", None, framework="GDPR", compliance_type=ComplianceFindingType.HUMAN_REVIEW)
    f1.fingerprint = "fp1"
    f2 = create_finding("2", "gdpr-checklist", None, framework="GDPR", compliance_type=ComplianceFindingType.HUMAN_REVIEW)
    f2.fingerprint = "fp2"
    
    groups, findings = group_findings([f1, f2])
    assert len(groups) == 0
