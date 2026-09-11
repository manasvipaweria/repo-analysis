"""
Compliance Rule Engine for US TCPA (Telephone Consumer Protection Act - 47 U.S.C. § 227 & 47 C.F.R. § 64.1200).
Operates as a compliance evaluation layer on top of shared technical evidence graph and scanner findings.
"""

import os
import re

from typing import List, Dict, Any, Optional, Tuple
from src.core.models import Finding, Category, Severity, ComplianceFindingType, ToolStatus
from src.compliance.tcpa_constants import (
    FRAMEWORK_TCPA,
    TCPA_EFFECTIVE_STATUS,
    TCPA_EFFECTIVE_FROM,
    TCPA_CHANNELS,
    TCPA_PURPOSES,
    TCPA_REQUIREMENTS
)
from src.compliance.tcpa_mapping import (
    classify_communication_channel,
    classify_communication_purpose,
    get_tcpa_references_for_rule,
    TELEPHONY_PROVIDERS,
    VOICE_SPECIFIC_KEYWORDS,
    SMS_SPECIFIC_KEYWORDS
)

EXCLUDE_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", ".pytest_cache", "dist", "build"}
OPT_OUT_KEYWORDS = ["stop", "unsubscribe", "cancel", "quit", "optout", "opt_out", "do_not_contact", "dnc"]
SUPPRESSION_KEYWORDS = ["suppression", "blacklist", "do_not_call", "dnc_list", "opt_out_list", "blocked_numbers"]
AUTOMATION_KEYWORDS = ["celery", "bull", "sidekiq", "cron", "batch_sms", "bulk_sms", "broadcast", "queue", "autodial"]

def evaluate_tcpa_applicability(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None
) -> Tuple[str, List[str], str]:
    """
    Evaluates TCPA applicability:
    1. Checks TCPA_APPLICABILITY env var override:
       - 'APPLICABLE' -> ('APPLICABLE', [...], 'ENVIRONMENT_OVERRIDE')
       - 'NOT_APPLICABLE' -> ('NOT_APPLICABLE', [...], 'ENVIRONMENT_OVERRIDE')
       - 'INDETERMINATE' -> ('INDETERMINATE', [...], 'ENVIRONMENT_OVERRIDE')
       - Any invalid string -> raises ValueError
    2. Scans repo for technical evidence of telephony providers or phone PII:
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

    reasons = []
    has_telephony = False

    # Check shared flow data for telephony providers or phone PII
    if flow_data:
        transfers = flow_data.get("third_party_transfers", [])
        for tr in transfers:
            svc = str(tr.get("service", "")).lower()
            if any(p in svc for p in TELEPHONY_PROVIDERS):
                has_telephony = True
                reasons.append(f"Telephony communications provider detected in third-party transfers: {tr.get('service')}")

        inventory = flow_data.get("personal_data_inventory", [])
        for item in inventory:
            field = str(item.get("field_name", "")).lower()
            if any(k in field for k in ["phone", "mobile", "telephone", "cell"]):
                has_telephony = True
                reasons.append(f"Phone number personal data field detected in inventory: {item.get('field_name')}")

    # Codebase scan fallback
    if not has_telephony and os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".json", ".env", ".yml", ".yaml")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            if any(p in content for p in TELEPHONY_PROVIDERS):
                                has_telephony = True
                                rel_p = os.path.relpath(filepath, repo_path)
                                reasons.append(f"Telephony provider reference detected in {rel_p}")
                                break
                    except Exception:
                        pass
            if has_telephony:
                break

    if has_telephony:
        return ("APPLICABLE", reasons, "TECHNICAL_EVIDENCE")

    return (
        "INDETERMINATE",
        ["No direct technical evidence of telephony service APIs or phone number processing detected in repository source code.",
         "TCPA applicability depends on whether the organization engages in telephone calls or SMS messaging targeted to US subscribers."],
        "HUMAN_REVIEW"
    )

def check_tcpa_communication_channels(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None
) -> List[Finding]:
    """
    Evaluates telephone & SMS communication channels.
    Note: Phone numbers and Twilio presence are technical evidence, NEVER automatic violations.
    """
    findings = []
    telephony_evidence = []

    if flow_data:
        inventory = flow_data.get("personal_data_inventory", [])
        for item in inventory:
            field = str(item.get("field_name", "")).lower()
            if any(k in field for k in ["phone", "mobile", "telephone", "cell"]):
                telephony_evidence.append(f"Phone PII field '{item.get('field_name')}' in {item.get('location', {}).get('file', 'codebase')}")

        transfers = flow_data.get("third_party_transfers", [])
        for tr in transfers:
            svc = str(tr.get("service", "")).lower()
            if any(p in svc for p in TELEPHONY_PROVIDERS):
                telephony_evidence.append(f"Telephony service transfer to '{tr.get('service')}'")

    if telephony_evidence:
        ev_str = "; ".join(telephony_evidence[:5])
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
    flow_data: Optional[Dict[str, Any]] = None
) -> List[Finding]:
    """
    Evaluates consent UI / consent flags for telephone and SMS communications.
    """
    findings = []
    consent_found = False
    consent_evidence = []

    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".vue")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            content_lower = content.lower()
                            if any(k in content_lower for k in ["sms_consent", "phone_consent", "consent_to_text", "tcpa_consent", "agree_sms", "opt_in_sms"]):
                                consent_found = True
                                rel_p = os.path.relpath(filepath, repo_path)
                                consent_evidence.append(f"Consent mechanism reference in {rel_p}")
                    except Exception:
                        pass

    req = TCPA_REQUIREMENTS["TCPA-227-B-1-A-CALLS-CONSENT"]
    if consent_found:
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
            detected_evidence="; ".join(consent_evidence[:5]),
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
    repo_path: str
) -> List[Finding]:
    """
    Evaluates SMS opt-out mechanism (STOP, UNSUBSCRIBE, CANCEL, QUIT, HELP).
    """
    findings = []
    opt_out_found = False
    opt_out_evidence = []

    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            content_lower = content.lower()
                            if any(k in content_lower for k in ["stop", "unsubscribe", "optout", "opt_out"]):
                                if any(kw in content_lower for kw in ["sms", "twilio", "webhook", "message", "incoming"]):
                                    opt_out_found = True
                                    rel_p = os.path.relpath(filepath, repo_path)
                                    opt_out_evidence.append(f"SMS opt-out handler in {rel_p}")
                    except Exception:
                        pass

    req = TCPA_REQUIREMENTS["TCPA-64-1200-SMS-OPT-OUT"]
    if opt_out_found:
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
            detected_evidence="; ".join(opt_out_evidence[:5]),
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
    repo_path: str
) -> List[Finding]:
    """
    Evaluates internal suppression list / do-not-contact / DNC database tables or services.
    """
    findings = []
    suppression_found = False
    suppression_evidence = []

    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".sql", ".prisma")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            if any(k in content for k in SUPPRESSION_KEYWORDS):
                                suppression_found = True
                                rel_p = os.path.relpath(filepath, repo_path)
                                suppression_evidence.append(f"Suppression list reference in {rel_p}")
                    except Exception:
                        pass

    req_dnc = TCPA_REQUIREMENTS["TCPA-227-C-DO-NOT-CALL"]
    req_supp = TCPA_REQUIREMENTS["TCPA-SUPPRESSION-LIST"]

    if suppression_found:
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
            detected_evidence="; ".join(suppression_evidence[:5]),
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
    repo_path: str
) -> List[Finding]:
    """
    Evaluates automated dispatch / autodialer / queue dispatch indicators.
    Note: Automated/bulk messaging is technical evidence of automation, NOT automatic proof of an illegal autodialer under statutory definitions.
    """
    findings = []
    auto_found = False
    auto_evidence = []

    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".yml", ".yaml")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            if any(p in content for p in TELEPHONY_PROVIDERS) or "sms" in content or "phone" in content:
                                if any(k in content for k in AUTOMATION_KEYWORDS):
                                    auto_found = True
                                    rel_p = os.path.relpath(filepath, repo_path)
                                    auto_evidence.append(f"Automated queue/cron dispatch in {rel_p}")
                    except Exception:
                        pass

    req = TCPA_REQUIREMENTS["TCPA-AUTODIALER-ATDS-MONITOR"]
    if auto_found:
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
            detected_evidence="; ".join(auto_evidence[:5]),
            recommended_action="Ensure all automated telephone/SMS dispatch pipelines enforce consent verification and suppression list filtering before API invocation.",
            human_review_required="Review whether automated dispatch equipment satisfies ATDS criteria under Facebook v. Duguid (141 S. Ct. 1163) and applicable FCC rulings."
        ))

    return findings

def check_tcpa_voice_calling(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None
) -> List[Finding]:
    """
    Evaluates voice calling and artificial / prerecorded voice controls.
    """
    findings = []
    voice_found = False
    voice_evidence = []

    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".xml", ".twiml")):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            if any(k in content for k in VOICE_SPECIFIC_KEYWORDS) or "<say>" in content or "<play>" in content:
                                voice_found = True
                                rel_p = os.path.relpath(filepath, repo_path)
                                voice_evidence.append(f"Voice call / TwiML evidence in {rel_p}")
                    except Exception:
                        pass

    if voice_found:
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
            detected_evidence="; ".join(voice_evidence[:5]),
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
    shared_findings: Optional[List[Finding]] = None
) -> Tuple[Dict[str, Any], List[Finding]]:
    """
    Main entry point for running TCPA compliance checks.
    Integrates technical checks, attestation generation, and shared finding re-tagging.
    """
    state, reasons, source = evaluate_tcpa_applicability(repo_path, flow_data)

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

    # Run technical checks
    tcpa_findings.extend(check_tcpa_communication_channels(repo_path, flow_data))
    tcpa_findings.extend(check_tcpa_consent_evidence(repo_path, flow_data))
    tcpa_findings.extend(check_tcpa_opt_out_stop(repo_path))
    tcpa_findings.extend(check_tcpa_suppression(repo_path))
    tcpa_findings.extend(check_tcpa_automation_autodialer(repo_path))
    tcpa_findings.extend(check_tcpa_voice_calling(repo_path, flow_data))

    # Add organizational attestations
    tcpa_findings.extend(generate_tcpa_attestations(state))

    # Re-tag qualifying shared security findings (ToolStatus.COMPLETED only)
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
