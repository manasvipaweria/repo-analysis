"""
India TRAI / TCCCPR 2018 / DLT Technical Readiness Framework Engine.

Reference:
- Telecom Commercial Communications Customer Preference Regulations, 2018 (TCCCPR 2018)
- DLT (Distributed Ledger Technology) Entity, Header, and Template Registration Mandates.
"""

import os
from typing import List, Dict, Any, Optional, Tuple
from src.core.models import Finding, FindingLocation, FindingEvidence, Severity, Category, ComplianceFindingType
from src.compliance.trai_dlt_constants import (
    FRAMEWORK_TRAI_DLT,
    TRAI_EFFECTIVE_STATUS,
    TRAI_EFFECTIVE_FROM,
    TRAI_COMMUNICATION_TYPES,
    TRAI_DLT_REQUIREMENTS
)
from src.compliance.trai_dlt_mapping import (
    classify_trai_communication_type,
    detect_dlt_parameters_in_text,
    get_trai_dlt_references_for_rule
)
from src.compliance.communication_classifier import CommunicationChannelClassifier, CommunicationFlowEvidence

def _get_flow_file_line(flow: CommunicationFlowEvidence) -> Tuple[Optional[str], Optional[int]]:
    if getattr(flow, 'file_path', None):
        return flow.file_path, getattr(flow, 'line_number', None)
    if flow.source_locations:
        loc = flow.source_locations[0]
        return loc.get("file"), loc.get("line")
    return None, None

def _get_flow_text_context(flow: CommunicationFlowEvidence) -> str:
    ctx = [flow.channel, flow.provider or "", flow.purpose or ""]
    if getattr(flow, 'code_snippet', None):
        ctx.append(flow.code_snippet)
    if getattr(flow, 'file_path', None):
        ctx.append(flow.file_path)
    for loc in flow.source_locations:
        if loc.get("file"):
            ctx.append(str(loc.get("file")))
    return " ".join(ctx)

def evaluate_trai_dlt_applicability(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> Dict[str, Any]:
    """
    Evaluates statutory applicability of India TRAI / TCCCPR 2018 / DLT mandates for the repository.
    Supports TRAI_APPLICABILITY environment variable override.
    """
    env_override = os.getenv("TRAI_APPLICABILITY")
    if env_override:
        val = env_override.strip().upper()
        if val in ("APPLICABLE", "NOT_APPLICABLE", "INDETERMINATE"):
            return {
                "status": val,
                "reason": f"Applicability overridden by TRAI_APPLICABILITY environment variable to '{val}'.",
                "evaluation_method": "ENVIRONMENT_OVERRIDE"
            }
        else:
            raise ValueError(
                f"Invalid TRAI_APPLICABILITY environment variable value: '{env_override}'. "
                "Must be one of APPLICABLE, NOT_APPLICABLE, INDETERMINATE."
            )

    if comm_evidence is None:
        classifier = CommunicationChannelClassifier()
        comm_evidence = classifier.classify_repository_communications(repo_path, flow_data)

    sms_flows = [flow for flow in comm_evidence if flow.channel == "SMS" or flow.provider]

    if not sms_flows:
        return {
            "status": "NOT_APPLICABLE",
            "reason": "No SMS, telephony, or DLT communication flows detected in repository.",
            "evaluation_method": "AUTOMATIC_EVIDENCE"
        }

    # Check for explicit India targeting indicators (+91, IN, .in domain, INR)
    has_india_jurisdiction = False
    india_indicators = []

    for flow in sms_flows:
        text_context = _get_flow_text_context(flow)
        if "+91" in text_context:
            has_india_jurisdiction = True
            india_indicators.append("+91 country code")
        if re_search_india_domain(text_context):
            has_india_jurisdiction = True
            india_indicators.append("India domain/locale")

    if flow_data:
        str_flow = str(flow_data)
        if "+91" in str_flow or "inr" in str_flow.lower() or ".in/" in str_flow.lower():
            has_india_jurisdiction = True
            india_indicators.append("India flow data metadata")

    if has_india_jurisdiction:
        return {
            "status": "APPLICABLE",
            "reason": f"SMS / Telephony flows detected with India jurisdiction indicators: {', '.join(set(india_indicators))}.",
            "evaluation_method": "AUTOMATIC_EVIDENCE"
        }

    return {
        "status": "INDETERMINATE",
        "reason": "SMS / Telephony communication detected, but target jurisdiction (India / +91) cannot be conclusively established from code alone. Configuration or legal attestation required.",
        "evaluation_method": "AUTOMATIC_EVIDENCE"
    }

def re_search_india_domain(text: str) -> bool:
    import re
    pattern = re.compile(r'(\.in/|\.co\.in|country\s*[:=]\s*["\']in["\']|locale\s*[:=]\s*["\']en[-_]in["\'])', re.IGNORECASE)
    return bool(pattern.search(text))


def check_trai_dlt_entity_registration(
    repo_path: str,
    comm_evidence: List[CommunicationFlowEvidence]
) -> List[Finding]:
    """
    Checks whether DLT Principal Entity (PE) ID parameters or configurations are present in SMS flows.
    """
    findings = []
    sms_flows = [flow for flow in comm_evidence if flow.channel == "SMS" or flow.provider]
    if not sms_flows:
        return findings

    dlt_pe_found = False
    sample_flow = sms_flows[0]
    sample_file, sample_line = _get_flow_file_line(sample_flow)

    for flow in sms_flows:
        text = _get_flow_text_context(flow)
        dlt_info = detect_dlt_parameters_in_text(text)
        if dlt_info["has_pe_id"]:
            dlt_pe_found = True
            break

    req = TRAI_DLT_REQUIREMENTS["TRAI-TCCCPR-REG-PE-ID"]

    if not dlt_pe_found:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.MEDIUM,
            file=sample_file,
            line=sample_line,
            message=f"{req['title']}: No Principal Entity (PE) ID parameter or configuration detected for SMS flows.",
            rule_id="TRAI-TCCCPR-REG-PE-ID",
            detected_by=["repo-orchestrator-trai-dlt-engine"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            requirement=req["requirement"],
            detected_evidence=f"SMS communication flow detected in {sample_file or 'repository'} without DLT Principal Entity (PE) ID binding in code.",
            recommended_action=req["recommended_action"],
            human_review_required="Verify DLT Principal Entity registration and configure 19-digit PE ID in messaging payload or provider portal.",
            framework=FRAMEWORK_TRAI_DLT,
            section="TCCCPR 2018 Reg 3",
            effective_status=TRAI_EFFECTIVE_STATUS,
            effective_from=TRAI_EFFECTIVE_FROM,
            evidence_status="ATTESTATION_REQUIRED",
            trai_dlt_references=["TRAI-TCCCPR-REG-PE-ID"]
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=sample_file,
            line=sample_line,
            message=f"{req['title']}: DLT Principal Entity (PE) ID configuration parameter detected.",
            rule_id="TRAI-TCCCPR-REG-PE-ID",
            detected_by=["repo-orchestrator-trai-dlt-engine"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence=f"DLT PE ID parameter detected in SMS communication flow ({sample_file or 'repository'}).",
            recommended_action="Ensure PE ID is registered and active on licensed Indian Access Provider DLT ledger.",
            human_review_required="Confirm DLT PE ID matches active corporate registration.",
            framework=FRAMEWORK_TRAI_DLT,
            section="TCCCPR 2018 Reg 3",
            effective_status=TRAI_EFFECTIVE_STATUS,
            effective_from=TRAI_EFFECTIVE_FROM,
            evidence_status="VERIFIED",
            trai_dlt_references=["TRAI-TCCCPR-REG-PE-ID"]
        ))

    return findings


def check_trai_dlt_header_sender_id(
    repo_path: str,
    comm_evidence: List[CommunicationFlowEvidence]
) -> List[Finding]:
    """
    Checks whether DLT Header / Sender ID parameters are registered/configured for SMS flows.
    """
    findings = []
    sms_flows = [flow for flow in comm_evidence if flow.channel == "SMS" or flow.provider]
    if not sms_flows:
        return findings

    dlt_hdr_found = False
    sample_flow = sms_flows[0]
    sample_file, sample_line = _get_flow_file_line(sample_flow)

    for flow in sms_flows:
        text = _get_flow_text_context(flow)
        dlt_info = detect_dlt_parameters_in_text(text)
        if dlt_info["has_header"]:
            dlt_hdr_found = True
            break

    req = TRAI_DLT_REQUIREMENTS["TRAI-TCCCPR-REG-HEADER-ID"]

    if not dlt_hdr_found:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.LOW,
            file=sample_file,
            line=sample_line,
            message=f"{req['title']}: DLT SMS Header / Sender ID binding not explicitly verified in source code.",
            rule_id="TRAI-TCCCPR-REG-HEADER-ID",
            detected_by=["repo-orchestrator-trai-dlt-engine"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            requirement=req["requirement"],
            detected_evidence=f"SMS communication flow detected in {sample_file or 'repository'} without explicit DLT Header / Sender ID parameter.",
            recommended_action=req["recommended_action"],
            human_review_required="Verify that SMS Sender ID / Header (e.g. 6-character alphanumeric or 6-digit numeric) is registered on DLT portal.",
            framework=FRAMEWORK_TRAI_DLT,
            section="TCCCPR 2018 Reg 8",
            effective_status=TRAI_EFFECTIVE_STATUS,
            effective_from=TRAI_EFFECTIVE_FROM,
            evidence_status="HUMAN_REVIEW",
            trai_dlt_references=["TRAI-TCCCPR-REG-HEADER-ID"]
        ))

    return findings


def check_trai_dlt_template_registration(
    repo_path: str,
    comm_evidence: List[CommunicationFlowEvidence]
) -> List[Finding]:
    """
    Checks whether DLT Content / Template ID parameters are passed alongside SMS message payloads.
    """
    findings = []
    sms_flows = [flow for flow in comm_evidence if flow.channel == "SMS" or flow.provider]
    if not sms_flows:
        return findings

    dlt_tpl_found = False
    sample_flow = sms_flows[0]
    sample_file, sample_line = _get_flow_file_line(sample_flow)

    for flow in sms_flows:
        text = _get_flow_text_context(flow)
        dlt_info = detect_dlt_parameters_in_text(text)
        if dlt_info["has_template_id"]:
            dlt_tpl_found = True
            break

    req = TRAI_DLT_REQUIREMENTS["TRAI-TCCCPR-REG-TEMPLATE-ID"]

    if not dlt_tpl_found:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.MEDIUM,
            file=sample_file,
            line=sample_line,
            message=f"{req['title']}: DLT Content Template ID parameter missing from SMS payload dispatch.",
            rule_id="TRAI-TCCCPR-REG-TEMPLATE-ID",
            detected_by=["repo-orchestrator-trai-dlt-engine"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            requirement=req["requirement"],
            detected_evidence=f"SMS dispatch in {sample_file or 'repository'} does not include a registered DLT Template ID parameter.",
            recommended_action=req["recommended_action"],
            human_review_required="Ensure every SMS message payload passes the approved DLT Content Template ID matching registered text patterns.",
            framework=FRAMEWORK_TRAI_DLT,
            section="TCCCPR 2018 Reg 9",
            effective_status=TRAI_EFFECTIVE_STATUS,
            effective_from=TRAI_EFFECTIVE_FROM,
            evidence_status="ATTESTATION_REQUIRED",
            trai_dlt_references=["TRAI-TCCCPR-REG-TEMPLATE-ID"]
        ))

    return findings


def check_trai_dlt_promotional_controls(
    repo_path: str,
    comm_evidence: List[CommunicationFlowEvidence]
) -> List[Finding]:
    """
    Checks statutory promotional / commercial SMS controls (09:00 to 21:00 time restriction & NCPR/DND scrubbing).
    """
    findings = []
    promo_flows = []

    for flow in comm_evidence:
        if flow.channel == "SMS" or flow.provider:
            text_context = _get_flow_text_context(flow)
            trai_type = classify_trai_communication_type(flow.purpose, text_context)
            if trai_type == TRAI_COMMUNICATION_TYPES["PROMOTIONAL_COMMERCIAL"]:
                promo_flows.append(flow)

    if not promo_flows:
        return findings

    sample_flow = promo_flows[0]
    sample_file, sample_line = _get_flow_file_line(sample_flow)

    # Timing check
    timing_req = TRAI_DLT_REQUIREMENTS["TRAI-TCCCPR-PROMOTIONAL-TIMING"]
    findings.append(Finding(
        category=Category.PRIVACY,
        severity=Severity.MEDIUM,
        file=sample_file,
        line=sample_line,
        message=f"{timing_req['title']}: Promotional communication flow detected requiring 09:00 to 21:00 dispatch window enforcement.",
        rule_id="TRAI-TCCCPR-PROMOTIONAL-TIMING",
        detected_by=["repo-orchestrator-trai-dlt-engine"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
        requirement=timing_req["requirement"],
        detected_evidence=f"Promotional / commercial SMS flow detected in {sample_file or 'repository'}.",
        recommended_action=timing_req["recommended_action"],
        human_review_required="Verify that background message dispatch queues enforce 09:00 AM to 09:00 PM local time restrictions for promotional SMS.",
        framework=FRAMEWORK_TRAI_DLT,
        section="TCCCPR 2018 Schedule II",
        effective_status=TRAI_EFFECTIVE_STATUS,
        effective_from=TRAI_EFFECTIVE_FROM,
        evidence_status="HUMAN_REVIEW",
        trai_dlt_references=["TRAI-TCCCPR-PROMOTIONAL-TIMING"]
    ))

    # Preference/DND check
    dnd_req = TRAI_DLT_REQUIREMENTS["TRAI-TCCCPR-PREFERENCE-DND"]
    findings.append(Finding(
        category=Category.PRIVACY,
        severity=Severity.MEDIUM,
        file=sample_file,
        line=sample_line,
        message=f"{dnd_req['title']}: Promotional communication flow requires National Customer Preference Register (NCPR / DND) scrubbing.",
        rule_id="TRAI-TCCCPR-PREFERENCE-DND",
        detected_by=["repo-orchestrator-trai-dlt-engine"],
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        requirement=dnd_req["requirement"],
        detected_evidence=f"Promotional communication flow in {sample_file or 'repository'} requires NCPR/DND scrubbing prior to dispatch.",
        recommended_action=dnd_req["recommended_action"],
        human_review_required="Verify DLT telecom carrier preference scrubbing or internal NCPR DND list integration.",
        framework=FRAMEWORK_TRAI_DLT,
        section="TCCCPR 2018 Reg 4",
        effective_status=TRAI_EFFECTIVE_STATUS,
        effective_from=TRAI_EFFECTIVE_FROM,
        evidence_status="ATTESTATION_REQUIRED",
        trai_dlt_references=["TRAI-TCCCPR-PREFERENCE-DND"]
    ))

    return findings


def generate_trai_dlt_attestations(applicability_state: Dict[str, Any]) -> List[Finding]:
    """
    Generates organizational attestation findings for non-code-verifiable TRAI/DLT legal & operational requirements.
    """
    findings = []
    if applicability_state.get("status") not in ("APPLICABLE", "INDETERMINATE"):
        return findings

    req = TRAI_DLT_REQUIREMENTS["TRAI-TCCCPR-CONSENT-TELECOM-SCRUB"]
    findings.append(Finding(
        category=Category.PRIVACY,
        severity=Severity.LOW,
        file=None,
        line=None,
        message=f"{req['title']}: DLT Consent Ledger & Opt-in Verification Attestation Required.",
        rule_id="TRAI-TCCCPR-CONSENT-TELECOM-SCRUB",
        detected_by=["repo-orchestrator-trai-dlt-engine"],
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        requirement=req["requirement"],
        detected_evidence=f"Applicability state: {applicability_state.get('status')}. Legal/operational attestation required for DLT consent ledger alignment.",
        recommended_action=req["recommended_action"],
        human_review_required="Provide organizational attestation confirming customer consent recording on DLT consent scrubbers.",
        framework=FRAMEWORK_TRAI_DLT,
        section="TCCCPR 2018 Reg 10-12",
        effective_status=TRAI_EFFECTIVE_STATUS,
        effective_from=TRAI_EFFECTIVE_FROM,
        evidence_status="ATTESTATION_REQUIRED",
        trai_dlt_references=["TRAI-TCCCPR-CONSENT-TELECOM-SCRUB"]
    ))

    return findings


def run_trai_dlt_checks(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    shared_findings: Optional[List[Finding]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Main entry point for India TRAI / TCCCPR 2018 / DLT technical readiness compliance evaluation.
    Consumes shared CommunicationFlowEvidence from src/compliance/communication_classifier.py.
    """
    if comm_evidence is None:
        classifier = CommunicationChannelClassifier()
        comm_evidence = classifier.classify_repository_communications(repo_path, flow_data)

    applicability = evaluate_trai_dlt_applicability(repo_path, flow_data, comm_evidence)

    if applicability["status"] == "NOT_APPLICABLE":
        return []

    findings: List[Finding] = []

    # Run DLT specific checks
    findings.extend(check_trai_dlt_entity_registration(repo_path, comm_evidence))
    findings.extend(check_trai_dlt_header_sender_id(repo_path, comm_evidence))
    findings.extend(check_trai_dlt_template_registration(repo_path, comm_evidence))
    findings.extend(check_trai_dlt_promotional_controls(repo_path, comm_evidence))
    findings.extend(generate_trai_dlt_attestations(applicability))

    # Annotate shared security findings with TRAI/DLT references where applicable
    if shared_findings:
        for f in shared_findings:
            refs = get_trai_dlt_references_for_rule(f.rule_id, f.detected_by)
            if refs:
                if f.trai_dlt_references is None:
                    f.trai_dlt_references = []
                for r in refs:
                    if r not in f.trai_dlt_references:
                        f.trai_dlt_references.append(r)

    return findings
