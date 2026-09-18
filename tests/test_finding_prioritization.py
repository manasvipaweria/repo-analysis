import pytest
from src.core.models import Finding, FindingGroup, ComplianceFindingType
from src.core.finding_prioritization import prioritize_finding, prioritize_findings

def create_finding(severity="medium", priority="P3", confidence=None, compliance_type=None, refs=None, group_id=None):
    f = Finding(
        finding_id="1",
        category="security",
        severity=severity,
        file="src/foo.py",
        line=10,
        message="Test",
        rule_id="ruleA",
        priority=priority,
        confidence=confidence,
        compliance_finding_type=compliance_type,
        group_id=group_id
    )
    if refs:
        f.gdpr_references = refs
    return f

def test_critical_finding():
    f = create_finding(severity="critical", priority="P0", confidence="HIGH")
    f = prioritize_finding(f)
    assert f.priority_score >= 90
    assert f.priority_level == "CRITICAL"
    assert "Existing severity is CRITICAL" in f.priority_reasons

def test_levels():
    f_high = prioritize_finding(create_finding(severity="high"))
    assert f_high.priority_level == "HIGH"
    
    f_med = prioritize_finding(create_finding(severity="medium"))
    assert f_med.priority_level == "MEDIUM"
    
    f_low = prioritize_finding(create_finding(severity="low"))
    assert f_low.priority_level == "LOW"
    
    f_info = prioritize_finding(create_finding(severity="info"))
    assert f_info.priority_level == "INFO"

def test_human_review_cap():
    f = create_finding(severity="critical", priority="P0", compliance_type=ComplianceFindingType.HUMAN_REVIEW)
    f = prioritize_finding(f)
    assert f.priority_level != "CRITICAL"
    assert f.priority_score <= 65
    assert any("HUMAN_REVIEW" in r for r in f.priority_reasons)

def test_inventory_cap():
    f = create_finding(severity="high", priority="P1", compliance_type=ComplianceFindingType.INVENTORY)
    f = prioritize_finding(f)
    assert f.priority_level in ("LOW", "INFO")
    assert f.priority_score <= 39
    assert any("INVENTORY flag" in r for r in f.priority_reasons)

def test_group_bonus():
    f1 = create_finding(severity="medium")
    f2 = create_finding(severity="medium")
    
    f1 = prioritize_finding(f1, group_size=1)
    f2 = prioritize_finding(f2, group_size=10)
    
    assert f2.priority_score > f1.priority_score
    assert any("group of 10" in r for r in f2.priority_reasons)

def test_deterministic():
    f1 = prioritize_finding(create_finding(severity="medium", priority="P2", refs=["Art 1"]))
    f2 = prioritize_finding(create_finding(severity="medium", priority="P2", refs=["Art 1"]))
    assert f1.priority_score == f2.priority_score
    assert f1.priority_reasons == f2.priority_reasons
    assert f1.priority_level == f2.priority_level

def test_prioritize_findings_list():
    f1 = create_finding(severity="high", group_id="g1")
    f2 = create_finding(severity="low")
    
    fg = FindingGroup(group_id="g1", title="test", confidence="HIGH", grouping_reason="", fingerprints=["fp1", "fp2"])
    
    findings = prioritize_findings([f1, f2], [fg])
    
    assert findings[0].priority_score > 70
    assert findings[1].priority_score < 40
