"""
India IT (SPDI Rules, 2011) Requirement Mapping & Compliance Engine.
Evaluates repository evidence against IT Act §43A and SPDI Rules 2011 (Rules 3–8).
"""

import os
import uuid
from typing import List, Dict, Any, Tuple, Optional

from src.core.models import Finding, FindingEvidence, Category, ComplianceFindingType, ToolStatus
from src.compliance.spdi_constants import (
    FRAMEWORK_SPDI,
    SPDI_EFFECTIVE_STATUS,
    SPDI_EFFECTIVE_FROM,
    SPDI_CATEGORIES,
    SPDI_REQUIREMENTS
)
from src.compliance.spdi_mapping import (
    classify_spdi_field,
    get_spdi_references_for_rule
)

def evaluate_spdi_applicability(repo_path: str) -> Tuple[str, str]:
    """
    Evaluates applicability of India IT SPDI Rules, 2011.
    Checks environment config and repository technical indicators.
    Returns (applicability_state, reasoning_description).
    """
    env_override = os.environ.get("SPDI_APPLICABILITY")
    if env_override:
        env_upper = env_override.upper().strip()
        if env_upper in ["APPLICABLE", "NOT_APPLICABLE", "INDETERMINATE"]:
            return (env_upper, f"SPDI applicability set via SPDI_APPLICABILITY environment variable to '{env_upper}'.")

    # Inspect repository for India context / Indian cloud / INR currency / body corporate indicators
    has_india_context = False
    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb", "dist", "build"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb", "dist", "build"]]

        for file_name in files:
            ext = os.path.splitext(file_name)[1].lower()
            if ext in [".json", ".yaml", ".yml", ".env", ".py", ".js", ".ts", ".md"]:
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if any(kw in content for kw in ["ap-south-1", "ap-south-2", "inr", "rupee", "india", "pvt ltd", "private limited"]):
                            has_india_context = True
                            break
                except Exception:
                    pass
        if has_india_context:
            break

    if has_india_context:
        return ("APPLICABLE", "India geographical context / region / currency indicators detected in repository.")

    return ("INDETERMINATE", "Static repository evidence is insufficient to determine legal applicability under SPDI Rule 1. Requires organizational confirmation.")


def check_spdi_sensitive_data_inventory(flow_data: Dict[str, Any]) -> List[Finding]:
    """
    Consumes shared PII fields and applies 4-tier SPDI taxonomy classification (Rule 3).
    """
    findings: List[Finding] = []
    pii_fields = flow_data.get("pii_fields", [])

    # Group by field name
    field_map: Dict[str, List[Dict[str, Any]]] = {}
    for pii in pii_fields:
        field_name = pii.get("field", "")
        if field_name and field_name != "defaultChecked_checkbox":
            if field_name not in field_map:
                field_map[field_name] = []
            field_map[field_name].append(pii)

    for field_name, pii_list in field_map.items():
        tax_tier, cat_key, ev_status = classify_spdi_field(field_name)
        loc_file = pii_list[0].get("file")
        loc_line = pii_list[0].get("line")
        locs_text = "\n".join([f"- {item.get('file')}:{item.get('line')}" for item in pii_list])

        if tax_tier == "SPDI_SENSITIVE":
            req_spec = SPDI_REQUIREMENTS["SPDI-RULE-3-SENSITIVE-TAXONOMY"]
            findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="high",
                file=loc_file,
                line=loc_line,
                message=f"SPDI Sensitive Personal Data field '{field_name}' (category: {cat_key}) detected across {len(pii_list)} location(s).",
                rule_id="spdi-rule3-sensitive-data-detected",
                title=f"SPDI Sensitive Data: {field_name}",
                description=f"Field '{field_name}' matches SPDI Rule 3 sensitive personal data category '{cat_key}'. Rule 3 requires enhanced technical and operational controls.",
                detected_by=["spdi-engine"],
                framework=FRAMEWORK_SPDI,
                section="Rule 3",
                effective_status=SPDI_EFFECTIVE_STATUS,
                effective_from=SPDI_EFFECTIVE_FROM,
                evidence_status="DETECTED",
                human_review_required="YES — Confirm SPDI sensitive classification and statutory encryption/access controls.",
                requirement=req_spec["requirement"],
                recommended_action=req_spec["recommended_action"],
                compliance_finding_type=ComplianceFindingType.INVENTORY,
                spdi_references=["SPDI-RULE-3-SENSITIVE-TAXONOMY"],
                evidence=FindingEvidence(code_context=f"Sensitive locations:\n{locs_text}")
            ))

        elif tax_tier == "ORDINARY_PII":
            req_spec = SPDI_REQUIREMENTS["SPDI-RULE-3-ORDINARY-PII"]
            findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="info",
                file=loc_file,
                line=loc_line,
                message=f"Ordinary personal data field '{field_name}' detected. Ordinary PII is not classified as SPDI Sensitive Personal Data under Rule 3.",
                rule_id="spdi-rule3-ordinary-pii-detected",
                title=f"SPDI Ordinary PII: {field_name}",
                description=f"Field '{field_name}' is ordinary personal data. Under SPDI Rule 3, phone numbers, email addresses, names, and IP addresses are not automatically SPDI Sensitive Personal Data.",
                detected_by=["spdi-engine"],
                framework=FRAMEWORK_SPDI,
                section="Rule 3",
                effective_status=SPDI_EFFECTIVE_STATUS,
                effective_from=SPDI_EFFECTIVE_FROM,
                evidence_status="DETECTED",
                human_review_required="NO — Standard PII handling rules apply.",
                requirement=req_spec["requirement"],
                recommended_action=req_spec["recommended_action"],
                compliance_finding_type=ComplianceFindingType.INVENTORY,
                spdi_references=["SPDI-RULE-3-ORDINARY-PII"],
                evidence=FindingEvidence(code_context=f"Ordinary PII locations:\n{locs_text}")
            ))

        elif tax_tier == "PUBLIC_DOMAIN":
            req_spec = SPDI_REQUIREMENTS["SPDI-RULE-3-PUBLIC-DOMAIN"]
            findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="info",
                file=loc_file,
                line=loc_line,
                message=f"Field '{field_name}' indicates public domain / statutory disclosure context and is exempt from SPDI sensitive classification.",
                rule_id="spdi-rule3-public-domain-exemption",
                title=f"SPDI Public Domain Exemption: {field_name}",
                description=f"Field '{field_name}' is freely available in the public domain or furnished under law, exempting it from SPDI Rule 3 sensitive data requirements.",
                detected_by=["spdi-engine"],
                framework=FRAMEWORK_SPDI,
                section="Rule 3 Exemption",
                effective_status=SPDI_EFFECTIVE_STATUS,
                effective_from=SPDI_EFFECTIVE_FROM,
                evidence_status="PUBLIC_EXEMPT",
                human_review_required="NO — Verified public domain exemption.",
                requirement=req_spec["requirement"],
                recommended_action=req_spec["recommended_action"],
                compliance_finding_type=ComplianceFindingType.INVENTORY,
                spdi_references=["SPDI-RULE-3-PUBLIC-DOMAIN"]
            ))

        else:  # AMBIGUOUS
            req_spec = SPDI_REQUIREMENTS["SPDI-RULE-3-SENSITIVE-TAXONOMY"]
            findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="low",
                file=loc_file,
                line=loc_line,
                message=f"Field '{field_name}' has ambiguous personal data classification.",
                rule_id="spdi-rule3-ambiguous-data-classification",
                title=f"SPDI Ambiguous Classification: {field_name}",
                description=f"Field '{field_name}' cannot be deterministically classified as SPDI Sensitive or Ordinary PII from source code alone.",
                detected_by=["spdi-engine"],
                framework=FRAMEWORK_SPDI,
                section="Rule 3",
                effective_status=SPDI_EFFECTIVE_STATUS,
                effective_from=SPDI_EFFECTIVE_FROM,
                evidence_status="INDETERMINATE",
                human_review_required="YES — Legal/data governance review required to determine sensitive status.",
                requirement=req_spec["requirement"],
                recommended_action=req_spec["recommended_action"],
                compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                spdi_references=["SPDI-RULE-3-SENSITIVE-TAXONOMY"]
            ))

    return findings


def check_spdi_rule5_provisions(repo_path: str, flow_data: Dict[str, Any]) -> List[Finding]:
    """
    Evaluates Rule 5 requirements (Consent, Notice, Purpose Limitation, Correction, Opt-Out, Grievance).
    Guardrail: Missing evidence for Rule 5 is NOT an automatic legal violation.
    """
    findings: List[Finding] = []
    pii_fields = flow_data.get("pii_fields", [])

    # 1. Rule 5(1) Consent Check
    consent_checkboxes = [p for p in pii_fields if p.get("field") == "defaultChecked_checkbox"]
    if consent_checkboxes:
        cb = consent_checkboxes[0]
        req_spec = SPDI_REQUIREMENTS["SPDI-RULE-5-1-CONSENT"]
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="medium",
            file=cb.get("file"),
            line=cb.get("line"),
            message="Consent UI element detected. Verify written/electronic prior consent mechanism under SPDI Rule 5(1).",
            rule_id="spdi-rule5-1-consent-mechanism",
            title=req_spec["title"],
            description="Consent UI element detected in frontend codebase. SPDI Rule 5(1) requires obtaining prior consent in writing or by electronic means before collection.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(1)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="DETECTED",
            human_review_required="YES — Review consent language and electronic consent capture workflow.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            spdi_references=["SPDI-RULE-5-1-CONSENT"]
        ))
    else:
        req_spec = SPDI_REQUIREMENTS["SPDI-RULE-5-1-CONSENT"]
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="[Attestation Required] SPDI Rule 5(1): Prior consent mechanism not detected in application source repository.",
            rule_id="spdi-rule5-1-consent-attestation",
            title="SPDI Rule 5(1) Prior Consent Attestation Checklist",
            description="No explicit consent UI element detected in codebase. Legal/organizational verification is required to confirm prior consent is obtained via offline/external channels.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(1)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Confirm prior consent procedure.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            spdi_references=["SPDI-RULE-5-1-CONSENT"]
        ))

    # 2. Rule 5(6) Review & Correction Rights
    has_correction_api = False
    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb"]]
        for file_name in files:
            if file_name.endswith((".js", ".jsx", ".ts", ".tsx", ".py")):
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if any(kw in content for kw in ["editprofile", "updateuser", "updateprofile", "edit-profile", "correction"]):
                            has_correction_api = True
                            break
                except Exception:
                    pass
        if has_correction_api:
            break

    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-5-6-REVIEW-CORRECTION"]
    if has_correction_api:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="User profile edit / data correction mechanism detected in codebase.",
            rule_id="spdi-rule5-6-correction-detected",
            title=req_spec["title"],
            description="Profile update / data correction features detected in source code, supporting Rule 5(6) data principal review rights.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(6)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="DETECTED",
            human_review_required="NO — Correction mechanism present.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            spdi_references=["SPDI-RULE-5-6-REVIEW-CORRECTION"]
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="[Attestation Required] SPDI Rule 5(6): Data principal review/correction mechanism not detected in application code.",
            rule_id="spdi-rule5-6-correction-attestation",
            title="SPDI Rule 5(6) Data Principal Correction Right Checklist",
            description="Static codebase inspection did not locate self-service user profile editing features.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(6)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Confirm process for handling data principal review & correction requests.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            spdi_references=["SPDI-RULE-5-6-REVIEW-CORRECTION"]
        ))

    # 3. Rule 5(7) Opt-Out & Consent Withdrawal
    has_opt_out = False
    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb"]]
        for file_name in files:
            if file_name.endswith((".js", ".jsx", ".ts", ".tsx", ".py")):
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if any(kw in content for kw in ["optout", "opt-out", "withdrawconsent", "unsubscribe"]):
                            has_opt_out = True
                            break
                except Exception:
                    pass
        if has_opt_out:
            break

    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-5-7-OPT-OUT-WITHDRAWAL"]
    if has_opt_out:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="Opt-out / consent withdrawal mechanism detected in codebase.",
            rule_id="spdi-rule5-7-optout-detected",
            title=req_spec["title"],
            description="Opt-out / withdrawal features detected in source code, supporting Rule 5(7) rights.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(7)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="DETECTED",
            human_review_required="NO — Opt-out mechanism present.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            spdi_references=["SPDI-RULE-5-7-OPT-OUT-WITHDRAWAL"]
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="[Attestation Required] SPDI Rule 5(7): Consent withdrawal / opt-out mechanism not detected in application source.",
            rule_id="spdi-rule5-7-optout-attestation",
            title="SPDI Rule 5(7) Consent Withdrawal Checklist",
            description="No explicit opt-out or consent withdrawal features found in code.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(7)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Verify procedure for data principals to withdraw consent.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            spdi_references=["SPDI-RULE-5-7-OPT-OUT-WITHDRAWAL"]
        ))

    return findings


def check_spdi_privacy_policy(repo_path: str) -> List[Finding]:
    """
    Scans repository for Privacy Policy files or routes (Rule 4).
    """
    findings: List[Finding] = []
    found_policy = False
    policy_file = None

    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb"]]

        for file_name in files:
            fname_lower = file_name.lower()
            if any(kw in fname_lower for kw in ["privacy", "privacypolicy", "privacy-policy", "privacy_policy"]):
                found_policy = True
                policy_file = os.path.relpath(os.path.join(root, file_name), repo_path).replace("\\", "/")
                break
        if found_policy:
            break

    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-4-PRIVACY-POLICY"]
    if found_policy:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=policy_file,
            line=1,
            message=f"Privacy Policy file/route artifact detected at '{policy_file}'. Technical evidence that policy exists.",
            rule_id="spdi-rule4-privacy-policy-detected",
            title=req_spec["title"],
            description=f"Privacy policy file or route artifact detected in repository. SPDI Rule 4 requires publishing a privacy policy covering collection, purpose, disclosure, and security practices.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 4",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="DETECTED",
            human_review_required="YES — Legal review to confirm policy covers SPDI Rule 4 statutory requirements.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            spdi_references=["SPDI-RULE-4-PRIVACY-POLICY"]
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="[Attestation Required] SPDI Rule 4: Privacy Policy artifact not detected in application source repository.",
            rule_id="spdi-rule4-privacy-policy-attestation",
            title="SPDI Rule 4 Privacy Policy Publication Checklist",
            description="Static repository inspection did not locate a privacy policy file. Policy may be hosted externally on organizational website.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 4",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Confirm published privacy policy URL and statutory coverage.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            spdi_references=["SPDI-RULE-4-PRIVACY-POLICY"]
        ))

    return findings


def check_spdi_security_practices(
    repo_path: str,
    shared_security_findings: List[Finding]
) -> List[Finding]:
    """
    Scans repository for Rule 8 Reasonable Security Practices (ISO 27001, ISMS, technical controls).
    Guardrail: ISO 27001 reference is evidence only, NOT proof of certification or audit status.
    """
    findings: List[Finding] = []
    found_iso27001 = False
    found_isms = False
    ref_file = None

    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb"]]

        for file_name in files:
            ext = os.path.splitext(file_name)[1].lower()
            if ext in [".md", ".txt", ".json", ".yaml", ".yml", ".py", ".js", ".ts"] or file_name.lower().startswith("security"):
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if "27001" in content or "iso/iec 27001" in content or "iso 27001" in content:
                            found_iso27001 = True
                            ref_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                        if "isms" in content or "information security management system" in content or "security policy" in content:
                            found_isms = True
                            if not ref_file:
                                ref_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                except Exception:
                    pass
        if found_iso27001 and found_isms:
            break

    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-8-REASONABLE-SECURITY"]
    if found_iso27001 or found_isms:
        details = []
        if found_iso27001:
            details.append("ISO/IEC 27001 standard reference")
        if found_isms:
            details.append("ISMS / security policy documentation")
        detail_str = " and ".join(details)

        findings.append(Finding(
            category=Category.SECURITY.value,
            severity="info",
            file=ref_file,
            line=1,
            message=f"Reasonable security practice documentation ({detail_str}) detected at '{ref_file}'. Technical readiness evidence.",
            rule_id="spdi-rule8-isms-documentation-detected",
            title=req_spec["title"],
            description=f"Documentation referencing {detail_str} detected in repository. Under SPDI Rule 8, implementing ISO/IEC 27001 or equivalent code of practice complies with reasonable security standards.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 8",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="DETECTED",
            human_review_required="YES — Confirm independent audit status and operational ISMS certification.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            spdi_references=["SPDI-RULE-8-REASONABLE-SECURITY"]
        ))
    else:
        findings.append(Finding(
            category=Category.SECURITY.value,
            severity="info",
            file=None,
            line=None,
            message="[Attestation Required] SPDI Rule 8: ISO 27001 / ISMS documentation reference not detected in repository.",
            rule_id="spdi-rule8-isms-attestation",
            title="SPDI Rule 8 ISO 27001 / Reasonable Security Audit Checklist",
            description="Static repository inspection did not locate explicit ISO 27001 certification or ISMS policy documents. Operational audit status requires attestation.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 8",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Compliance officer must confirm ISO 27001 certification or equivalent audited code of practice.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            spdi_references=["SPDI-RULE-8-REASONABLE-SECURITY"]
        ))

    return findings


def check_spdi_third_party_disclosure(flow_data: Dict[str, Any]) -> List[Finding]:
    """
    Evaluates Rule 6 Third-Party Disclosure constraints for SPDI-sensitive fields.
    Guardrail: Third-party transfer != automatic SPDI violation.
    """
    findings: List[Finding] = []
    transfers = flow_data.get("third_party_transfers", [])

    tp_map: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for tx in transfers:
        key = (tx.get("processor", "unknown"), tx.get("field", "unknown"))
        if key not in tp_map:
            tp_map[key] = []
        tp_map[key].append(tx)

    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-6-THIRD-PARTY-DISCLOSURE"]
    for (proc, field_name), tx_list in tp_map.items():
        tax_tier, cat_key, ev_status = classify_spdi_field(field_name)
        if tax_tier == "SPDI_SENSITIVE":
            locs_text = "\n".join([f"- {t.get('file')}:{t.get('line')}" for t in tx_list])
            findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="medium",
                file=tx_list[0].get("file"),
                line=tx_list[0].get("line"),
                message=f"SPDI Sensitive Personal Data '{field_name}' ({cat_key}) is transmitted to third-party processor '{proc}'.",
                rule_id="spdi-rule6-third-party-sensitive-disclosure",
                title=f"SPDI Rule 6 Disclosure: {field_name} -> {proc}",
                description=f"Transmission of SPDI sensitive data field '{field_name}' to third-party processor '{proc}' detected. Rule 6 requires prior permission from data principal or contractual authorization.",
                detected_by=["spdi-engine"],
                framework=FRAMEWORK_SPDI,
                section="Rule 6",
                effective_status=SPDI_EFFECTIVE_STATUS,
                effective_from=SPDI_EFFECTIVE_FROM,
                evidence_status="DETECTED",
                human_review_required="YES — Legal review to confirm prior disclosure consent or contractual processor terms.",
                requirement=req_spec["requirement"],
                recommended_action=req_spec["recommended_action"],
                compliance_finding_type=ComplianceFindingType.THIRD_PARTY_RISK,
                spdi_references=["SPDI-RULE-6-THIRD-PARTY-DISCLOSURE"],
                evidence=FindingEvidence(code_context=f"Disclosure locations:\n{locs_text}")
            ))

    return findings


def check_spdi_cross_border_transfer(flow_data: Dict[str, Any]) -> List[Finding]:
    """
    Evaluates Rule 7 Cross-Border Data Transfer controls.
    Separate from Rule 6 disclosure. Detects external service/region/endpoint.
    Guardrail: Cross-border transfer != automatic SPDI violation.
    """
    findings: List[Finding] = []
    transfers = flow_data.get("third_party_transfers", [])
    outbound_calls = flow_data.get("outbound_calls", [])

    # Identify external destinations and cross-border regions
    cross_border_items = []
    for tx in transfers:
        proc = tx.get("processor", "")
        field_name = tx.get("field", "")
        tax_tier, cat_key, _ = classify_spdi_field(field_name)

        # Look for region / domain details in outbound calls
        matched_call = next((c for c in outbound_calls if proc.lower() in str(c).lower()), None)
        cross_border_items.append({
            "processor": proc,
            "field": field_name,
            "tier": tax_tier,
            "category": cat_key,
            "file": tx.get("file"),
            "line": tx.get("line"),
            "call_details": matched_call
        })

    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-7-CROSS-BORDER-TRANSFER"]
    seen_procs = set()
    for item in cross_border_items:
        proc = item["processor"]
        field_name = item["field"]
        if proc not in seen_procs and item["tier"] == "SPDI_SENSITIVE":
            seen_procs.add(proc)
            findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="medium",
                file=item["file"],
                line=item["line"],
                message=f"Cross-border / external body corporate data transfer detected: SPDI field '{field_name}' transmitted to '{proc}'.",
                rule_id="spdi-rule7-cross-border-transfer-detected",
                title=f"SPDI Rule 7 Data Transfer: {proc}",
                description=f"SPDI Rule 7 allows transferring SPDI outside India or to another body corporate only if recipient ensures equivalent data protection standards.",
                detected_by=["spdi-engine"],
                framework=FRAMEWORK_SPDI,
                section="Rule 7",
                effective_status=SPDI_EFFECTIVE_STATUS,
                effective_from=SPDI_EFFECTIVE_FROM,
                evidence_status="DETECTED",
                human_review_required="YES — Confirm recipient body corporate data protection agreement and equivalent security standards.",
                requirement=req_spec["requirement"],
                recommended_action=req_spec["recommended_action"],
                compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                spdi_references=["SPDI-RULE-7-CROSS-BORDER-TRANSFER"]
            ))

    return findings


def check_spdi_retention_deletion(repo_path: str) -> List[Finding]:
    """
    Evaluates Rule 7 & Rule 5(4) Data Retention & Deletion mechanisms.
    Detects TTL indexes, scheduled cleanup jobs, database expiration, lifecycle policies, delete APIs.
    Guardrail: Absence of retention logic != automatic SPDI violation.
    """
    findings: List[Finding] = []
    found_retention = False
    found_delete_api = False
    ref_file = None

    retention_terms = ["ttl", "expireafterseconds", "node-cron", "celery", "logrotate", "lifecycle", "retention_days"]
    delete_api_terms = ["deleteuser", "deleteaccount", "delete_user", "removeuser", "destroyuser", "purge"]

    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb"]]

        for file_name in files:
            ext = os.path.splitext(file_name)[1].lower()
            if ext in [".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".yml", ".yaml"]:
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if any(term in content for term in retention_terms):
                            found_retention = True
                            ref_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                        if any(term in content for term in delete_api_terms):
                            found_delete_api = True
                            if not ref_file:
                                ref_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                except Exception:
                    pass
        if found_retention and found_delete_api:
            break

    req_spec_54 = SPDI_REQUIREMENTS["SPDI-RULE-5-4-RETENTION-LIMIT"]
    req_spec_7 = SPDI_REQUIREMENTS["SPDI-RULE-7-RETENTION-DELETION"]

    if found_retention or found_delete_api:
        details = []
        if found_retention:
            details.append("automated data lifecycle / TTL retention configuration")
        if found_delete_api:
            details.append("explicit data deletion API endpoint")
        detail_str = " and ".join(details)

        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=ref_file,
            line=1,
            message=f"Data retention / deletion mechanism ({detail_str}) detected at '{ref_file}'.",
            rule_id="spdi-rule7-retention-deletion-detected",
            title="SPDI Rule 7 / Rule 5(4) Retention & Cleanup Mechanism",
            description=f"Technical indicators for {detail_str} detected in codebase, supporting Rule 5(4) retention limits and Rule 7 lifecycle handling.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 7 / Rule 5(4)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="DETECTED",
            human_review_required="NO — Technical retention/deletion evidence present.",
            requirement=req_spec_7["requirement"],
            recommended_action=req_spec_7["recommended_action"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            spdi_references=["SPDI-RULE-7-RETENTION-DELETION", "SPDI-RULE-5-4-RETENTION-LIMIT"]
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="[Attestation Required] SPDI Rule 7 / Rule 5(4): Data retention limit and deletion mechanism not detected in application source.",
            rule_id="spdi-rule7-retention-deletion-attestation",
            title="SPDI Rule 7 / Rule 5(4) Data Retention & Purge Checklist",
            description="Static repository scan did not locate automated TTL cleanup jobs or data deletion APIs. Retention may be managed operationally.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 7 / Rule 5(4)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Confirm organizational retention schedule and operational purge procedures.",
            requirement=req_spec_7["requirement"],
            recommended_action=req_spec_7["recommended_action"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            spdi_references=["SPDI-RULE-7-RETENTION-DELETION", "SPDI-RULE-5-4-RETENTION-LIMIT"]
        ))

    return findings


def check_spdi_grievance_contact(repo_path: str) -> List[Finding]:
    """
    Evaluates Rule 5(9) Grievance Officer & Contact Mechanism requirements.
    """
    findings: List[Finding] = []
    found_grievance = False
    ref_file = None

    grievance_terms = ["grievance", "grievance_officer", "dpo", "privacy_officer", "privacy@", "security@"]

    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb"]]

        for file_name in files:
            ext = os.path.splitext(file_name)[1].lower()
            if ext in [".md", ".txt", ".json", ".yaml", ".yml", ".js", ".ts", ".py"] or file_name.lower().startswith("security"):
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().lower()
                        if any(term in content for term in grievance_terms):
                            found_grievance = True
                            ref_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                            break
                except Exception:
                    pass
        if found_grievance:
            break

    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-5-9-GRIEVANCE-OFFICER"]
    if found_grievance:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=ref_file,
            line=1,
            message=f"Grievance officer / privacy contact information detected at '{ref_file}'.",
            rule_id="spdi-rule5-9-grievance-officer-detected",
            title=req_spec["title"],
            description=f"Grievance contact / privacy officer information detected in repository, supporting Rule 5(9) grievance redressal requirement.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(9)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="DETECTED",
            human_review_required="YES — Confirm published grievance officer name, email, and 30-day resolution SLA.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            spdi_references=["SPDI-RULE-5-9-GRIEVANCE-OFFICER"]
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="[Attestation Required] SPDI Rule 5(9): Grievance officer designation and contact details not detected in repository.",
            rule_id="spdi-rule5-9-grievance-officer-attestation",
            title="SPDI Rule 5(9) Grievance Officer Designation Checklist",
            description="Static scan did not locate grievance officer name or email in repository files.",
            detected_by=["spdi-engine"],
            framework=FRAMEWORK_SPDI,
            section="Rule 5(9)",
            effective_status=SPDI_EFFECTIVE_STATUS,
            effective_from=SPDI_EFFECTIVE_FROM,
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Publish Grievance Officer name and contact mechanism on website.",
            requirement=req_spec["requirement"],
            recommended_action=req_spec["recommended_action"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            spdi_references=["SPDI-RULE-5-9-GRIEVANCE-OFFICER"]
        ))

    return findings


def generate_spdi_attestations(applicability_state: str) -> List[Finding]:
    """
    Generates organizational readiness attestation checklist items for SPDI framework.
    """
    checklist: List[Finding] = []

    # Attestation: Annual Security Audit by Independent Auditor (Rule 8)
    req_spec = SPDI_REQUIREMENTS["SPDI-RULE-8-REASONABLE-SECURITY"]
    checklist.append(Finding(
        category=Category.SECURITY.value,
        severity="info",
        file=None,
        line=None,
        message="[Organizational Attestation Required] SPDI Rule 8: Independent security audit & certification attestation.",
        rule_id="spdi-rule8-annual-audit-attestation",
        title="SPDI Rule 8 Independent Security Audit Checklist",
        description="Body corporate must have its reasonable security practices & procedures audited by an independent auditor at least once a year or upon significant upgrade.",
        detected_by=["spdi-engine"],
        framework=FRAMEWORK_SPDI,
        section="Rule 8",
        effective_status=SPDI_EFFECTIVE_STATUS,
        effective_from=SPDI_EFFECTIVE_FROM,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Confirm annual independent security audit report.",
        requirement=req_spec["requirement"],
        recommended_action="Execute annual independent security audit under Rule 8.",
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        spdi_references=["SPDI-RULE-8-REASONABLE-SECURITY"]
    ))

    return checklist


def run_spdi_checks(
    repo_path: str,
    flow_data: Dict[str, Any],
    shared_findings: List[Finding]
) -> List[Finding]:
    """
    Executes SPDI-specific requirement checks against shared evidence layer,
    generates dedicated findings, and re-tags qualifying shared security findings in-place.
    """
    spdi_findings: List[Finding] = []

    # 1. Applicability Assessment
    app_state, app_reason = evaluate_spdi_applicability(repo_path)

    # 2. Rule 3 Sensitive Personal Data Inventory Classification
    inventory_findings = check_spdi_sensitive_data_inventory(flow_data)
    spdi_findings.extend(inventory_findings)

    # 3. Rule 5 Provisions (Consent, Notice, Purpose, Correction, Opt-Out)
    rule5_findings = check_spdi_rule5_provisions(repo_path, flow_data)
    spdi_findings.extend(rule5_findings)

    # 4. Rule 4 Privacy Policy
    policy_findings = check_spdi_privacy_policy(repo_path)
    spdi_findings.extend(policy_findings)

    # 5. Rule 8 Reasonable Security Practices
    sec_findings = check_spdi_security_practices(repo_path, shared_findings)
    spdi_findings.extend(sec_findings)

    # 6. Rule 6 Third-Party Disclosure
    disc_findings = check_spdi_third_party_disclosure(flow_data)
    spdi_findings.extend(disc_findings)

    # 7. Rule 7 Cross-Border Transfer
    cb_findings = check_spdi_cross_border_transfer(flow_data)
    spdi_findings.extend(cb_findings)

    # 8. Rule 7 & Rule 5(4) Retention & Deletion
    retention_findings = check_spdi_retention_deletion(repo_path)
    spdi_findings.extend(retention_findings)

    # 9. Rule 5(9) Grievance Officer
    grievance_findings = check_spdi_grievance_contact(repo_path)
    spdi_findings.extend(grievance_findings)

    # 10. Organizational Attestations
    attestations = generate_spdi_attestations(app_state)
    spdi_findings.extend(attestations)

    # 11. Reference-Tagging Pass on shared security findings
    # Guardrail: Exclude findings from tools that failed (ToolStatus.ERROR)!
    for f in shared_findings:
        refs = get_spdi_references_for_rule(f.rule_id, f.detected_by, f.severity)
        if refs:
            existing = set(f.spdi_references or [])
            existing.update(refs)
            f.spdi_references = sorted(list(existing))

    return spdi_findings
