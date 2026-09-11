"""
Compliance Rule Engine for US TCPA (Telephone Consumer Protection Act - 47 U.S.C. § 227 & 47 C.F.R. § 64.1200).
Consumes framework-neutral CommunicationFlowEvidence from shared Communication Channel Classifier.
"""

import os
from typing import List, Dict, Any, Optional, Tuple

from src.core.models import Finding, Category, Severity, ComplianceFindingType, ToolStatus
from src.compliance.tcpa_constants import (
    FRAMEWORK_TCPA,
    TCPA_EFFECTIVE_STATUS,
    TCPA_EFFECTIVE_FROM,
    TCPA_REQUIREMENTS
)
from src.compliance.tcpa_mapping import get_tcpa_references_for_rule
from src.compliance.communication_models import CommunicationFlowEvidence, CommunicationChannel
from src.compliance.communication_classifier import classify_communications

def evaluate_tcpa_applicability(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> Tuple[str, List[str], str]:
    """
    Evaluates TCPA applicability:
    1. Checks TCPA_APPLICABILITY env var override:
       - 'APPLICABLE' -> ('APPLICABLE', [...], 'ENVIRONMENT_OVERRIDE')
       - 'NOT_APPLICABLE' -> ('NOT_APPLICABLE', [...], 'ENVIRONMENT_OVERRIDE')
       - 'INDETERMINATE' -> ('INDETERMINATE', [...], 'ENVIRONMENT_OVERRIDE')
       - Any invalid string -> raises ValueError
    2. Inspects shared CommunicationFlowEvidence for telephony providers / phone channels:
       - If found -> ('APPLICABLE', [...], 'TECHNICAL_EVIDENCE')
       - If not found -> ('INDETERMINATE', [...], 'HUMAN_REVIEW')
    """
    env_override = os.environ.get("TCPA_APPLICABILITY")
    if env_override:
        override_clean = env_override.strip().upper()
        if override_clean == "APPLICABLE":
            return ("APPLICABLE", ["TCPA applicability explicitly set via environment variable override (APPLICABLE)."], "ENVIRONMENT_OVERRIDE")
        elif override_clean == "NOT_APPLICABLE":
            return ("NOT_APPLICABLE", ["TCPA applicability explicitly disabled via environment variable override (NOT_APPLICABLE)."], "ENVIRONMENT_OVERRIDE")
        elif override_clean == "INDETERMINATE":
            return ("INDETERMINATE", ["TCPA applicability explicitly set to INDETERMINATE via environment variable."], "ENVIRONMENT_OVERRIDE")
        else:
            raise ValueError(f"Invalid TCPA_APPLICABILITY override value: '{env_override}'. Expected APPLICABLE, NOT_APPLICABLE, or INDETERMINATE.")

    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, flow_data)

    reasons = []
    has_telephony = False

    for ev in comm_evidence:
        if ev.channel in (CommunicationChannel.SMS.value, CommunicationChannel.VOICE_CALL.value) or ev.provider:
            has_telephony = True
            prov_str = f" to '{ev.provider}'" if ev.provider else ""
            if ev.recipient_field:
                reasons.append(f"Phone number personal data field detected in inventory: {ev.recipient_field}")
            reasons.append(f"Telephony communications provider detected in third-party transfers{prov_str}")

    if has_telephony:
        # Deduplicate reasons while preserving order
        unique_reasons = list(dict.fromkeys(reasons))
        return ("APPLICABLE", unique_reasons, "TECHNICAL_EVIDENCE")

    return (
        "INDETERMINATE",
        ["No direct technical evidence of telephony service APIs or phone number processing detected in repository source code.",
         "TCPA applicability depends on whether the organization engages in telephone calls or SMS messaging targeted to US subscribers."],
        "HUMAN_REVIEW"
    )

def check_tcpa_communication_channels(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Evaluates telephone & SMS communication channels from shared CommunicationFlowEvidence.
    Note: Phone numbers and Twilio presence are technical evidence, NEVER automatic violations.
    """
    findings = []
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, flow_data)

    telephony_evidence = []
    for ev in comm_evidence:
        if ev.channel in (CommunicationChannel.SMS.value, CommunicationChannel.VOICE_CALL.value):
            if ev.recipient_field:
                loc_file = ev.source_locations[0].get("file", "codebase") if ev.source_locations else "codebase"
                telephony_evidence.append(f"Phone PII field '{ev.recipient_field}' in {loc_file}")
            if ev.provider:
                telephony_evidence.append(f"Telephony service transfer to '{ev.provider}'")

    if telephony_evidence:
        ev_str = "; ".join(dict.fromkeys(telephony_evidence))
        req = TCPA_REQUIREMENTS["TCPA-227-B-1-A-CALLS-CONSENT"]
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Telephone / SMS communication channel evidence detected.",
            rule_id="TCPA-227-B-1-A-CALLS-CONSENT",
            title=req["title"],
            description="Technical evidence of telephony APIs or phone number data structures detected in repository.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-227-B-1-A-CALLS-CONSENT"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence=ev_str,
            recommended_action=req["recommended_action"],
            human_review_required="Verify express consent records and opt-in mechanisms prior to initiating automated phone calls or SMS messages."
        ))

    return findings

def check_tcpa_consent_evidence(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Evaluates consent UI / consent flags from shared CommunicationFlowEvidence.
    """
    findings = []
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, flow_data)

    consent_items = []
    for ev in comm_evidence:
        consent_items.extend(ev.consent_evidence)

    req = TCPA_REQUIREMENTS["TCPA-227-B-1-A-CALLS-CONSENT"]
    if consent_items:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="TCPA consent mechanism detected in codebase.",
            rule_id="TCPA-227-B-1-A-CALLS-CONSENT",
            title=req["title"],
            description="Codebase contains references to phone or SMS consent flags.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-227-B-1-A-CALLS-CONSENT"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence="; ".join(list(dict.fromkeys(consent_items))[:5]),
            recommended_action="Maintain documented audit trail of consent timestamps and opt-in text disclosures presented to users.",
            human_review_required="Verify that written consent language clearly states consent to receive marketing calls/SMS via autodialer if applicable."
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.MEDIUM,
            file=None,
            line=None,
            message="No explicit TCPA prior express consent UI mechanism detected for phone/SMS communications.",
            rule_id="TCPA-227-B-1-A-CALLS-CONSENT",
            title=req["title"],
            description="Technical consent indicators for telephone/SMS communications were not found in repository source files.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-227-B-1-A-CALLS-CONSENT"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            requirement=req["requirement"],
            detected_evidence="NOT_DETECTED — No explicit phone/SMS opt-in consent UI checkbox or consent flag found in repository.",
            recommended_action=req["recommended_action"],
            human_review_required="Attest that prior express consent (or prior express written consent for telemarketing) is obtained out-of-band or via un-indexed web forms."
        ))

    return findings

def check_tcpa_opt_out_stop(
    repo_path: str,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Evaluates SMS opt-out mechanism from shared CommunicationFlowEvidence.
    """
    findings = []
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, None)

    opt_out_items = []
    for ev in comm_evidence:
        opt_out_items.extend(ev.opt_out_evidence)

    req = TCPA_REQUIREMENTS["TCPA-64-1200-SMS-OPT-OUT"]
    if opt_out_items:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="SMS opt-out keyword processing / webhook handler detected.",
            rule_id="TCPA-64-1200-SMS-OPT-OUT",
            title=req["title"],
            description="Codebase includes keyword inspection logic or webhook handling for SMS opt-out requests.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-64-1200-SMS-OPT-OUT"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence="; ".join(list(dict.fromkeys(opt_out_items))[:5]),
            recommended_action="Ensure opt-out processing immediately updates internal suppression lists and halts further outgoing messages to the subscriber.",
            human_review_required="Confirm that STOP, UNSUBSCRIBE, CANCEL, QUIT, and HELP replies are automatically processed and confirmed."
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.MEDIUM,
            file=None,
            line=None,
            message="No explicit SMS opt-out (STOP keyword) webhook or handler detected in repository.",
            rule_id="TCPA-64-1200-SMS-OPT-OUT",
            title=req["title"],
            description="SMS opt-out handling code (STOP/UNSUBSCRIBE processing) was not identified in local repository files.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-64-1200-SMS-OPT-OUT"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            requirement=req["requirement"],
            detected_evidence="NOT_DETECTED — No explicit SMS STOP keyword handler found in source code.",
            recommended_action=req["recommended_action"],
            human_review_required="Verify whether SMS opt-out handling is managed automatically by the telephony provider platform (e.g. Twilio Advanced Opt-Out) or external service."
        ))

    return findings

def check_tcpa_suppression(
    repo_path: str,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Evaluates internal suppression list from shared CommunicationFlowEvidence.
    """
    findings = []
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, None)

    supp_items = []
    for ev in comm_evidence:
        supp_items.extend(ev.suppression_evidence)

    req_dnc = TCPA_REQUIREMENTS["TCPA-227-C-DO-NOT-CALL"]
    req_supp = TCPA_REQUIREMENTS["TCPA-SUPPRESSION-LIST"]

    if supp_items:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Internal suppression list / Do-Not-Contact mechanism detected.",
            rule_id="TCPA-SUPPRESSION-LIST",
            title=req_supp["title"],
            description="Codebase contains data structures or models for maintaining contact suppression lists.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-227-C-DO-NOT-CALL", "TCPA-SUPPRESSION-LIST"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req_supp["requirement"],
            detected_evidence="; ".join(list(dict.fromkeys(supp_items))[:5]),
            recommended_action="Ensure suppression list is consulted in real time prior to executing outbound communication dispatch.",
            human_review_required="Verify compliance with internal DNC recordkeeping requirements under 47 C.F.R. § 64.1200(d)."
        ))
    else:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.LOW,
            file=None,
            line=None,
            message="No explicit internal DNC / contact suppression table detected in repository.",
            rule_id="TCPA-227-C-DO-NOT-CALL",
            title=req_dnc["title"],
            description="Internal suppression list implementation was not detected in repository code.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-227-C-DO-NOT-CALL", "TCPA-SUPPRESSION-LIST"],
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            requirement=req_dnc["requirement"],
            detected_evidence="NOT_DETECTED — No internal DNC/suppression model or table found in repository.",
            recommended_action=req_dnc["recommended_action"],
            human_review_required="Attest that internal Do-Not-Call requests are tracked and honored through CRM, backend database, or vendor platforms."
        ))

    return findings

def check_tcpa_automation_autodialer(
    repo_path: str,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Evaluates automated dispatch / autodialer indicators from shared CommunicationFlowEvidence.
    """
    findings = []
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, None)

    auto_evidence = []
    for ev in comm_evidence:
        if ev.automated or ev.bulk:
            loc = ev.source_locations[0].get("file", "codebase") if ev.source_locations else "codebase"
            auto_evidence.append(f"Automated queue/cron dispatch in {loc}")

    req = TCPA_REQUIREMENTS["TCPA-AUTODIALER-ATDS-MONITOR"]
    if auto_evidence:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Automated communication dispatch / queue processing detected.",
            rule_id="TCPA-AUTODIALER-ATDS-MONITOR",
            title=req["title"],
            description="Technical evidence of batch or automated queue-based communication dispatch detected.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-AUTODIALER-ATDS-MONITOR"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence="; ".join(list(dict.fromkeys(auto_evidence))[:5]),
            recommended_action="Ensure all automated telephone/SMS dispatch pipelines enforce consent verification and suppression list filtering before API invocation.",
            human_review_required="Review whether automated dispatch equipment satisfies ATDS criteria under Facebook v. Duguid (141 S. Ct. 1163) and applicable FCC rulings."
        ))

    return findings

def check_tcpa_voice_calling(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Evaluates voice calling controls from shared CommunicationFlowEvidence.
    """
    findings = []
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, flow_data)

    voice_evidence = []
    for ev in comm_evidence:
        if ev.channel == CommunicationChannel.VOICE_CALL.value:
            loc = ev.source_locations[0].get("file", "codebase") if ev.source_locations else "codebase"
            voice_evidence.append(f"Voice call / TwiML evidence in {loc}")

    if voice_evidence:
        req = TCPA_REQUIREMENTS["TCPA-227-B-1-B-PRERECORDED-VOICE"]
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Voice call / Prerecorded audio indicators detected in repository.",
            rule_id="TCPA-227-B-1-B-PRERECORDED-VOICE",
            title=req["title"],
            description="Codebase contains references to voice calling APIs, interactive voice response (IVR), or speech synthesis.",
            framework=FRAMEWORK_TCPA,
            effective_status=TCPA_EFFECTIVE_STATUS,
            effective_from=TCPA_EFFECTIVE_FROM,
            tcpa_references=["TCPA-227-B-1-B-PRERECORDED-VOICE", "TCPA-64-1200-IDENTIFICATION"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence="; ".join(list(dict.fromkeys(voice_evidence))[:5]),
            recommended_action="Ensure voice scripts include mandatory caller identification disclosures at the beginning of each call.",
            human_review_required="Verify prior express consent for artificial or prerecorded voice communications under 47 C.F.R. § 64.1200(a)(3)."
        ))

    return findings

def generate_tcpa_attestations(applicability_state: str) -> List[Finding]:
    """
    Generates organizational readiness attestations for TCPA compliance.
    """
    attestations = []

    req_dnc = TCPA_REQUIREMENTS["TCPA-227-C-DO-NOT-CALL"]
    attestations.append(Finding(
        category=Category.PRIVACY,
        severity=Severity.LOW,
        file=None,
        line=None,
        message="Organizational Attestation: National Do Not Call Registry Subscription & Policy",
        rule_id="TCPA-227-C-DO-NOT-CALL",
        title=req_dnc["title"],
        description="TCPA compliance requires subscribing to the National Do Not Call Registry and maintaining written DNC procedures.",
        framework=FRAMEWORK_TCPA,
        effective_status=TCPA_EFFECTIVE_STATUS,
        effective_from=TCPA_EFFECTIVE_FROM,
        tcpa_references=["TCPA-227-C-DO-NOT-CALL"],
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        requirement=req_dnc["requirement"],
        detected_evidence="ATTESTATION_REQUIRED — Organizational policy & registry subscription requirement.",
        recommended_action="Subscribe to National DNC Registry (if making telephone solicitations) and maintain documented internal DNC procedures.",
        human_review_required="Confirm organizational DNC policy is documented and operationalized across sales and marketing teams."
    ))

    req_id = TCPA_REQUIREMENTS["TCPA-64-1200-IDENTIFICATION"]
    attestations.append(Finding(
        category=Category.PRIVACY,
        severity=Severity.LOW,
        file=None,
        line=None,
        message="Organizational Attestation: Sender Identification & Disclosure Compliance",
        rule_id="TCPA-64-1200-IDENTIFICATION",
        title=req_id["title"],
        description="47 C.F.R. § 64.1200(b) mandates caller identification disclosures in telephone solicitations and promotional SMS.",
        framework=FRAMEWORK_TCPA,
        effective_status=TCPA_EFFECTIVE_STATUS,
        effective_from=TCPA_EFFECTIVE_FROM,
        tcpa_references=["TCPA-64-1200-IDENTIFICATION"],
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        requirement=req_id["requirement"],
        detected_evidence="ATTESTATION_REQUIRED — Message template identification disclosure requirement.",
        recommended_action="Verify all promotional text messages and voice scripts clearly identify the sending business name and contact information.",
        human_review_required="Review communication templates to ensure mandatory sender disclosures are present."
    ))

    return attestations

def run_tcpa_checks(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    shared_findings: Optional[List[Finding]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> Tuple[Dict[str, Any], List[Finding]]:
    """
    Main entry point for running TCPA compliance checks.
    Consumes framework-neutral CommunicationFlowEvidence from shared classifier.
    """
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, flow_data)

    state, reasons, source = evaluate_tcpa_applicability(repo_path, flow_data, comm_evidence)

    if state == "NOT_APPLICABLE":
        summary = {
            "status": ToolStatus.NOT_APPLICABLE.value,
            "applicability": "NOT_APPLICABLE",
            "applicability_source": source,
            "reasons": reasons,
            "findings_count": 0
        }
        return summary, []

    tcpa_findings: List[Finding] = []

    # Run technical checks consuming shared communication evidence
    tcpa_findings.extend(check_tcpa_communication_channels(repo_path, flow_data, comm_evidence))
    tcpa_findings.extend(check_tcpa_consent_evidence(repo_path, flow_data, comm_evidence))
    tcpa_findings.extend(check_tcpa_opt_out_stop(repo_path, comm_evidence))
    tcpa_findings.extend(check_tcpa_suppression(repo_path, comm_evidence))
    tcpa_findings.extend(check_tcpa_automation_autodialer(repo_path, comm_evidence))
    tcpa_findings.extend(check_tcpa_voice_calling(repo_path, flow_data, comm_evidence))

    # Add organizational attestations
    tcpa_findings.extend(generate_tcpa_attestations(state))

    # Re-tag qualifying shared security findings (ToolStatus.COMPLETED or OPEN)
    if shared_findings:
        for f in shared_findings:
            if getattr(f, "status", None) == ToolStatus.COMPLETED.value or getattr(f, "status", None) == "OPEN":
                refs = get_tcpa_references_for_rule(f.rule_id, f.detected_by, f.severity)
                if refs:
                    if not f.tcpa_references:
                        f.tcpa_references = []
                    for r in refs:
                        if r not in f.tcpa_references:
                            f.tcpa_references.append(r)

    summary = {
        "status": ToolStatus.COMPLETED.value,
        "applicability": state,
        "applicability_source": source,
        "reasons": reasons,
        "findings_count": len(tcpa_findings)
    }

    return summary, tcpa_findings
