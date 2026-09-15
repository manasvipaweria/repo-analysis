import hashlib
from typing import List, Tuple, Dict
from src.core.models import Finding, FindingGroup, GroupConfidence

def generate_group_id(strategy: str, context: str, identity: str) -> str:
    components = [strategy, context, identity]
    canonical_string = "|".join(str(c).lower() for c in components if c)
    return hashlib.sha256(canonical_string.encode('utf-8')).hexdigest()

def group_findings(findings: List[Finding]) -> Tuple[List[FindingGroup], List[Finding]]:
    """
    Groups findings using deterministic safe grouping rules.
    Returns (groups, findings_with_group_ids).
    """
    groups_map: Dict[str, FindingGroup] = {}
    
    for f in findings:
        strategy = None
        context = None
        identity = None
        confidence = GroupConfidence.LOW
        reason = ""
        title = f.title or f.rule_id
        
        # 1. Technical Findings in the same file with the same rule
        if not f.compliance_finding_type and f.location and f.location.file and f.rule_id:
            strategy = "FILE_RULE"
            context = f.location.file
            identity = f.rule_id
            reason = "Same rule and same source file."
            confidence = GroupConfidence.HIGH
            title = f"Multiple {f.rule_id} findings in {f.location.file}"
            
        # 2. Third-Party Data Flows to the exact same vendor/destination
        elif f.compliance_finding_type and f.compliance_finding_type.value == "third_party_risk":
            if f.detected_evidence:
                strategy = "EXACT_THIRD_PARTY_EVIDENCE"
                context = f.detected_evidence
                identity = f.rule_id
                reason = "Same third-party destination and same data-flow context."
                confidence = GroupConfidence.HIGH
                title = f"Multiple third-party transfer findings for: {f.rule_id}"
                
        # 3. Identical compliance checklist items (should ideally be deduplicated, 
        # but if fingerprints differ due to some other field, they might group here)
        elif f.compliance_finding_type and not f.location:
            # We explicitly do NOT group these unless there's explicit evidence overlap,
            # to prevent over-grouping GDPR checklist items.
            pass
            
        if strategy and confidence == GroupConfidence.HIGH:
            g_id = generate_group_id(strategy, context, identity)
            f.group_id = g_id
            
            if g_id not in groups_map:
                groups_map[g_id] = FindingGroup(
                    group_id=g_id,
                    title=title,
                    confidence=confidence,
                    grouping_reason=reason,
                    fingerprints=[f.fingerprint],
                    category=f.category,
                    severity=f.severity,
                    rule_id=identity
                )
            else:
                if f.fingerprint not in groups_map[g_id].fingerprints:
                    groups_map[g_id].fingerprints.append(f.fingerprint)
                    
    # Only materialize groups that have more than 1 finding
    multi_groups = {g_id: g for g_id, g in groups_map.items() if len(g.fingerprints) > 1}
    
    # Strip group_id from findings that didn't end up in a multi-group
    for f in findings:
        if f.group_id and f.group_id not in multi_groups:
            f.group_id = None
            
    return list(multi_groups.values()), findings
