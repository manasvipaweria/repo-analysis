from typing import List, Optional
from src.core.models import Finding, FindingGroup

def prioritize_finding(finding: Finding, group_size: int = 1) -> Finding:
    score = 0
    reasons = []

    # A. Existing Severity
    sev = (finding.severity or "info").lower()
    if sev == "critical":
        score += 85
        reasons.append("Existing severity is CRITICAL")
    elif sev == "high":
        score += 70
        reasons.append("Existing severity is HIGH")
    elif sev == "medium":
        score += 45
        reasons.append("Existing severity is MEDIUM")
    elif sev == "low":
        score += 25
        reasons.append("Existing severity is LOW")
    else:
        score += 10
        reasons.append("Existing severity is INFO")

    # B. Existing Priority
    pri = (finding.priority or "").upper()
    if pri in ("P0", "P1"):
        score += 10
        reasons.append(f"Scanner marked priority {pri}")
    elif pri == "P2":
        score += 5
        reasons.append(f"Scanner marked priority {pri}")

    # C. Confidence / Evidence
    if finding.confidence and finding.confidence.upper() == "HIGH":
        score += 5
        reasons.append("Finding has deterministic scanner evidence")
    
    # D. Framework References
    refs = []
    for ref_attr in ["gdpr_references", "cra_references", "cert_in_references", "spdi_references", "tcpa_references", "trai_dlt_references", "eprivacy_references"]:
        if hasattr(finding, ref_attr) and getattr(finding, ref_attr):
            refs.extend(getattr(finding, ref_attr))
    
    if refs:
        bonus = min(5, len(refs))
        score += bonus
        reasons.append(f"Finding has {len(refs)} compliance framework reference(s)")

    # E. Group Context
    if group_size > 1:
        bonus = min(10, group_size - 1)
        score += bonus
        reasons.append(f"Finding occurs in a group of {group_size} related findings")

    # F. Human Review & Compliance Caps
    is_human_review = finding.compliance_finding_type and finding.compliance_finding_type.value == "human_review"
    is_inventory = finding.compliance_finding_type and finding.compliance_finding_type.value == "inventory"
    
    if is_human_review:
        reasons.append("Finding is marked HUMAN_REVIEW")
        reasons.append("Evidence is technical but does not establish legal non-compliance")
        score = min(score, 65)  # Cap at MEDIUM/HIGH boundary, never CRITICAL
    elif is_inventory:
        reasons.append("Finding is an INVENTORY flag")
        score = min(score, 39)  # Cap at LOW

    # Cap overall score
    score = max(0, min(100, score))

    # Map to priority_level
    if score >= 90:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    elif score >= 20:
        level = "LOW"
    else:
        level = "INFO"

    finding.priority_score = score
    finding.priority_level = level
    finding.priority_reasons = reasons

    return finding

def prioritize_findings(findings: List[Finding], finding_groups: Optional[List[FindingGroup]] = None) -> List[Finding]:
    groups = finding_groups or []
    group_size_map = {g.group_id: len(g.fingerprints) for g in groups if g.group_id}

    for f in findings:
        size = 1
        if f.group_id and f.group_id in group_size_map:
            size = group_size_map[f.group_id]
        
        prioritize_finding(f, size)
    
    return findings
