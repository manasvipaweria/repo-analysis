"""
EU Cyber Resilience Act (CRA - Regulation 2024/2847) Engine.
Evaluates repository evidence against CRA Annex I Part I and Part II requirements.
"""
import os
import re
import uuid
from typing import List, Dict, Any, Tuple

from src.core.models import Finding, FindingEvidence, FindingLocation, Category, ComplianceFindingType
from src.compliance.cra_mapping import CRA_REQUIREMENTS, get_cra_references_for_rule

def evaluate_cra_applicability(repo_path: str) -> Tuple[str, str]:
    """
    Evaluates repository signals for CRA product scope applicability.
    Returns (applicability_state, reason_description).
    Options: APPLICABLE, NOT_APPLICABLE, INDETERMINATE.
    """
    # Check for explicit config override
    env_app = os.environ.get("CRA_APPLICABILITY")
    if env_app in ["APPLICABLE", "NOT_APPLICABLE", "INDETERMINATE"]:
        return (env_app, f"Applicability explicitly configured via CRA_APPLICABILITY environment variable ({env_app}).")
        
    # Inspect repository signals (package.json, release workflows, dockerfiles)
    has_package = os.path.exists(os.path.join(repo_path, "package.json")) or os.path.exists(os.path.join(repo_path, "pyproject.toml"))
    has_release_wf = False
    wf_dir = os.path.join(repo_path, ".github", "workflows")
    if os.path.isdir(wf_dir):
        try:
            for f in os.listdir(wf_dir):
                if any(k in f.lower() for k in ["release", "publish", "deploy", "build"]):
                    has_release_wf = True
                    break
        except Exception:
            pass
            
    if has_package and has_release_wf:
        return ("INDETERMINATE", "Product software component and release pipeline detected. Legal/product owner must confirm EU market placement and CRA scope.")
        
    return ("INDETERMINATE", "Repository contains software artifacts. Product applicability under CRA §3 requires product owner sign-off.")

def check_security_md(repo_path: str) -> Finding:
    """
    Scans repository for SECURITY.md, .github/SECURITY.md, or security.txt.
    Evaluates vulnerability disclosure policy (CRA-II-5), contact point (CRA-II-6), and advisory process (CRA-II-4).
    """
    sec_file_candidates = [
        "SECURITY.md",
        ".github/SECURITY.md",
        "security.md",
        "docs/SECURITY.md",
        "security.txt",
        ".well-known/security.txt"
    ]
    
    found_path = None
    content = ""
    for rel_path in sec_file_candidates:
        abs_p = os.path.join(repo_path, rel_path)
        if os.path.isfile(abs_p):
            found_path = rel_path
            try:
                with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                pass
            break
            
    rule_id = "cra-security-md-disclosure"
    cra_refs = ["CRA-II-4", "CRA-II-5", "CRA-II-6"]
    
    if not found_path:
        return Finding(
            category=Category.SECURITY.value,
            severity="medium",
            file=None,
            line=None,
            message="SECURITY.md file not found in repository. Coordinated vulnerability disclosure policy, contact point, and advisory process required under CRA-II-4/5/6.",
            rule_id=rule_id,
            title="CRA Vulnerability Disclosure Policy & Contact (SECURITY.md)",
            description="No SECURITY.md file detected. CRA Annex I Part II (CRA-II-4, CRA-II-5, CRA-II-6) requires a vulnerability disclosure policy, reporting contact, and advisory process. (Shared with CERT-In security contact requirement).",
            detected_by=["cra-engine"],
            framework="CRA",
            section="Annex I, Part II (4-6)",
            effective_status="FUTURE_STATE",
            effective_from="2027-12-11",
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Create SECURITY.md with disclosure contact email/URL and policy text.",
            requirement="CRA-II-4, CRA-II-5, CRA-II-6: Manufacturers must publish vulnerability disclosure policy, reporting contact point, and fixed vulnerability advisories.",
            recommended_action="Add a SECURITY.md file containing vulnerability reporting instructions, security contact email, and advisory policy.",
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            cra_references=cra_refs
        )
        
    # Analyze content for contact point and policy text
    has_contact = bool(re.search(r"[\w\.-]+@[\w\.-]+\.\w+", content) or re.search(r"https?://", content))
    has_policy = len(content.strip()) > 50
    
    if has_contact and has_policy:
        return Finding(
            category=Category.SECURITY.value,
            severity="info",
            file=found_path,
            line=1,
            message=f"SECURITY.md detected at '{found_path}' containing vulnerability disclosure contact and policy text.",
            rule_id=rule_id,
            title="CRA Vulnerability Disclosure Policy & Contact (SECURITY.md)",
            description=f"SECURITY.md file found at '{found_path}'. Evidences coordinated vulnerability disclosure policy (CRA-II-5), contact point (CRA-II-6), and advisory process (CRA-II-4).",
            detected_by=["cra-engine"],
            framework="CRA",
            section="Annex I, Part II (4-6)",
            effective_status="FUTURE_STATE",
            effective_from="2027-12-11",
            evidence_status="DETECTED",
            human_review_required="NO — Vulnerability disclosure policy and contact point evidenced.",
            requirement="CRA-II-4, CRA-II-5, CRA-II-6: Vulnerability disclosure policy and contact point requirement.",
            recommended_action="Ensure security contact email/URL in SECURITY.md is actively monitored.",
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            cra_references=cra_refs
        )
    else:
        return Finding(
            category=Category.SECURITY.value,
            severity="low",
            file=found_path,
            line=1,
            message=f"SECURITY.md found at '{found_path}' but missing clear contact details or policy text.",
            rule_id=rule_id,
            title="CRA Vulnerability Disclosure Policy & Contact (SECURITY.md)",
            description=f"SECURITY.md exists at '{found_path}', but contact email/URL or disclosure policy text could not be verified.",
            detected_by=["cra-engine"],
            framework="CRA",
            section="Annex I, Part II (4-6)",
            effective_status="FUTURE_STATE",
            effective_from="2027-12-11",
            evidence_status="INDETERMINATE",
            human_review_required="YES — Update SECURITY.md to include explicit contact email and disclosure guidelines.",
            requirement="CRA-II-4, CRA-II-5, CRA-II-6: Vulnerability disclosure policy and contact point requirement.",
            recommended_action="Add clear vulnerability submission instructions and security contact details.",
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            cra_references=cra_refs
        )

def check_update_delivery_mechanism(repo_path: str) -> Finding:
    """
    Extracts release workflows, packaging, and update delivery evidence for CRA-I-3h.
    """
    wf_dir = os.path.join(repo_path, ".github", "workflows")
    has_release = False
    has_docker = os.path.exists(os.path.join(repo_path, "Dockerfile")) or os.path.exists(os.path.join(repo_path, "docker-compose.yml"))
    
    if os.path.isdir(wf_dir):
        try:
            for f in os.listdir(wf_dir):
                if any(k in f.lower() for k in ["release", "publish", "deploy", "npm", "pypi", "docker"]):
                    has_release = True
                    break
        except Exception:
            pass
            
    cra_refs = ["CRA-I-3h"]
    rule_id = "cra-i-3h-update-delivery"
    
    if has_release or has_docker:
        return Finding(
            category=Category.ARCHITECTURE.value,
            severity="info",
            file=None,
            line=None,
            message="Automated release/publishing workflows or container build specs detected for vulnerability update delivery under CRA-I-3h.",
            rule_id=rule_id,
            title="CRA-I-3h Vulnerability Update Delivery Mechanism",
            description="Release automation, package publishing, or container workflows identified in repository context.",
            detected_by=["cra-engine"],
            framework="CRA",
            section="Annex I, Part I (3h)",
            effective_status="FUTURE_STATE",
            effective_from="2027-12-11",
            evidence_status="DETECTED",
            human_review_required="NO — Release delivery automation evidenced.",
            requirement="CRA-I-3h: Provide a mechanism to remediate vulnerabilities via security updates.",
            recommended_action="Ensure security updates are delivered seamlessly to end users/systems.",
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            cra_references=cra_refs
        )
    else:
        return Finding(
            category=Category.ARCHITECTURE.value,
            severity="info",
            file=None,
            line=None,
            message="Security update delivery mechanism could not be technically established from repository workflow evidence alone.",
            rule_id=rule_id,
            title="CRA-I-3h Vulnerability Update Delivery Mechanism",
            description="No automated release or container publishing workflow identified in repository context.",
            detected_by=["cra-engine"],
            framework="CRA",
            section="Annex I, Part I (3h)",
            effective_status="FUTURE_STATE",
            effective_from="2027-12-11",
            evidence_status="INDETERMINATE",
            human_review_required="YES — Verify patch delivery path and software update channel.",
            requirement="CRA-I-3h: Provide a mechanism to remediate vulnerabilities via security updates.",
            recommended_action="Document patch distribution channels and update delivery mechanisms.",
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            cra_references=cra_refs
        )

def generate_attestation_checklist() -> List[Finding]:
    """
    Generates report-level Organizational Attestation Checklist items for non-code-verifiable requirements:
    - CRA-I-3e: Availability & DoS resilience testing
    - CRA-II-7: Free security update distribution policy
    - CRA-II-8: 24-hour ENISA/CSIRT early-warning notification process
    """
    checklist = []
    
    # CRA-I-3e
    checklist.append(Finding(
        category=Category.SECURITY.value,
        severity="info",
        file=None,
        line=None,
        message="[Organizational Attestation Required] CRA-I-3e: Availability & DoS resilience testing performed and documented.",
        rule_id="cra-i-3e-availability-dos-attestation",
        title="CRA-I-3e Availability & DoS Resilience Checklist",
        description="Availability & DoS resilience testing cannot be established from application source code alone. Organizational attestation and test documentation required.",
        detected_by=["cra-engine"],
        framework="CRA",
        section="Annex I, Part I (3e)",
        effective_status="FUTURE_STATE",
        effective_from="2027-12-11",
        evidence_status="INDETERMINATE",
        human_review_required="YES — Human owner must sign off availability/DoS resilience testing documentation.",
        requirement="CRA-I-3e: Protect availability of essential functions, including resilience against DoS attacks.",
        recommended_action="Perform and document DoS resilience and load availability testing.",
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        cra_references=["CRA-I-3e"]
    ))
    
    # CRA-II-7
    checklist.append(Finding(
        category=Category.SECURITY.value,
        severity="info",
        file=None,
        line=None,
        message="[Organizational Attestation Required] CRA-II-7: Policy and workflow to distribute security updates free of charge with accompanying advisories.",
        rule_id="cra-ii-7-free-patch-distribution-attestation",
        title="CRA-II-7 Free Security Patch Distribution Checklist",
        description="Organizational policy must ensure security updates are provided to end users free of charge and accompanied by advisory information.",
        detected_by=["cra-engine"],
        framework="CRA",
        section="Annex I, Part II (7)",
        effective_status="FUTURE_STATE",
        effective_from="2027-12-11",
        evidence_status="INDETERMINATE",
        human_review_required="YES — Organizational sign-off confirming security updates are free of charge.",
        requirement="CRA-II-7: Distribute security updates without delay, free of charge, with accompanying advisory information.",
        recommended_action="Establish organizational policy confirming patch availability free of charge.",
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        cra_references=["CRA-II-7"]
    ))
    
    # CRA-II-8
    checklist.append(Finding(
        category=Category.SECURITY.value,
        severity="info",
        file=None,
        line=None,
        message="[Organizational Attestation Required] CRA-II-8: 24-hour ENISA/CSIRT notification process for actively exploited vulnerabilities.",
        rule_id="cra-ii-8-enisa-csirt-early-warning-attestation",
        title="CRA-II-8 ENISA/CSIRT 24-Hour Reporting Checklist",
        description="Process and named incident owner must exist to notify ENISA and designated CSIRT within 24 hours of becoming aware of actively exploited vulnerabilities.",
        detected_by=["cra-engine"],
        framework="CRA",
        section="Annex I, Part II (8)",
        effective_status="FUTURE_STATE",
        effective_from="2026-09-11",
        evidence_status="INDETERMINATE",
        human_review_required="YES — Appoint named incident owner and document 24-hour ENISA/CSIRT reporting SLA.",
        requirement="CRA-II-8: 24-hour early-warning notification to ENISA/CSIRT for actively exploited vulnerabilities.",
        recommended_action="Document incident escalation plan to meet 24-hour ENISA reporting deadline (Effective 11 Sept 2026).",
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        cra_references=["CRA-II-8"]
    ))
    
    return checklist

def run_cra_checks(
    repo_path: str,
    shared_findings: List[Finding]
) -> List[Finding]:
    """
    Executes CRA-specific requirement checks and re-tags shared findings with matching cra_references.
    """
    cra_findings: List[Finding] = []
    
    # 1. Deterministic SECURITY.md Check (CRA-II-4, CRA-II-5, CRA-II-6)
    sec_md_finding = check_security_md(repo_path)
    cra_findings.append(sec_md_finding)
    
    # 2. Update Delivery Mechanism Check (CRA-I-3h)
    update_finding = check_update_delivery_mechanism(repo_path)
    cra_findings.append(update_finding)
    
    # 3. Organizational Attestation Checklist (CRA-I-3e, CRA-II-7, CRA-II-8)
    checklist = generate_attestation_checklist()
    cra_findings.extend(checklist)
    
    # 4. Re-tag existing findings in-place with matching cra_references
    for f in shared_findings:
        refs = get_cra_references_for_rule(f.rule_id, f.detected_by)
        if refs:
            existing = set(f.cra_references or [])
            existing.update(refs)
            f.cra_references = sorted(list(existing))
            
    return cra_findings
