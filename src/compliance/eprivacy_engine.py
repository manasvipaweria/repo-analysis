"""
Compliance Rule Engine for EU ePrivacy Directive (2002/58/EC).
Consumes framework-neutral CommunicationFlowEvidence and shared Data Flow evidence.
"""

import os
from typing import List, Dict, Any, Optional, Tuple

from src.core.models import Finding, Category, Severity, ComplianceFindingType, ToolStatus
from src.compliance.eprivacy_constants import (
    FRAMEWORK_EPRIVACY,
    EPRIVACY_EFFECTIVE_STATUS,
    EPRIVACY_BASELINE_EFFECTIVE_FROM,
    EPRIVACY_AMENDMENT_EFFECTIVE_FROM,
    EPRIVACY_REQUIREMENTS
)
from src.compliance.eprivacy_mapping import get_eprivacy_references_for_rule
from src.compliance.communication_models import CommunicationFlowEvidence, CommunicationChannel, CommunicationPurpose
from src.compliance.communication_classifier import classify_communications


def evaluate_eprivacy_applicability(repo_path: str) -> Tuple[str, List[str], str]:
    """
    Evaluates ePrivacy applicability.
    Rules:
    - APPLICABLE / NOT_APPLICABLE / INDETERMINATE from env var.
    - Invalid config -> explicit error.
    - Does not silently fall back to APPLICABLE.
    - Does not infer EU applicability just from words like "EU" or "GDPR".
    - Uses HUMAN_REVIEW otherwise.
    """
    env_override = os.environ.get("EPRIVACY_APPLICABILITY")
    if env_override:
        override_clean = env_override.strip().upper()
        if override_clean == "APPLICABLE":
            return ("APPLICABLE", ["ePrivacy applicability explicitly set via environment variable override (APPLICABLE)."], "ENVIRONMENT_OVERRIDE")
        elif override_clean == "NOT_APPLICABLE":
            return ("NOT_APPLICABLE", ["ePrivacy applicability explicitly disabled via environment variable override (NOT_APPLICABLE)."], "ENVIRONMENT_OVERRIDE")
        elif override_clean == "INDETERMINATE":
            return ("INDETERMINATE", ["ePrivacy applicability explicitly set to INDETERMINATE via environment variable."], "ENVIRONMENT_OVERRIDE")
        else:
            raise ValueError(f"Invalid EPRIVACY_APPLICABILITY override value: '{env_override}'. Expected APPLICABLE, NOT_APPLICABLE, or INDETERMINATE.")

    return (
        "INDETERMINATE",
        ["No explicit configuration found. ePrivacy Directive applicability depends on target market, users, service location, and Member State transposition, which require legal assessment.",
         "Technical repository indicators can support applicability assessment but cannot prove legal applicability."],
        "HUMAN_REVIEW"
    )

def check_eprivacy_art5_confidentiality(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    shared_findings: Optional[List[Finding]] = None
) -> List[Finding]:
    """
    Article 5: Confidentiality of Communications.
    Looks at shared security findings for insecure HTTP, plaintext, etc.
    Does NOT flag provider (e.g., Twilio) as a violation.
    """
    findings = []
    has_confidentiality_evidence = False

    if shared_findings:
        for f in shared_findings:
            refs = get_eprivacy_references_for_rule(f.rule_id, f.detected_by)
            if "EPRIVACY-ART5-CONFIDENTIALITY" in refs:
                has_confidentiality_evidence = True
                break

    req = EPRIVACY_REQUIREMENTS["EPRIVACY-ART5-CONFIDENTIALITY"]
    
    # We rely on the orchestrator to tag shared findings, so we only emit an attestation/inventory finding here
    # if we didn't find deterministic technical violations, or as a general human review note.
    
    findings.append(Finding(
        category=Category.PRIVACY,
        severity=Severity.INFO,
        file=None,
        line=None,
        message="ePrivacy Article 5 Confidentiality of Communications Review.",
        rule_id="EPRIVACY-ART5-CONFIDENTIALITY-ATTESTATION",
        title=req["title"],
        description="Ensure all electronic communications and traffic data are protected from unauthorized access or interception.",
        framework=FRAMEWORK_EPRIVACY,
        effective_status=EPRIVACY_EFFECTIVE_STATUS,
        effective_from=req["baseline_date"],
        eprivacy_references=["EPRIVACY-ART5-CONFIDENTIALITY"],
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        requirement=req["requirement"],
        detected_evidence="ATTESTATION_REQUIRED — Technical security architecture review required.",
        recommended_action=req["recommended_action"],
        human_review_required="Confirm that communication contents and traffic data cannot be intercepted or exposed inappropriately (e.g., insecure transport, proxy exposure). Note: E-Privacy is implemented through national transposition which may vary by Member State."
    ))

    return findings

def check_eprivacy_art5_3_terminal_equipment(repo_path: str, flow_data: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """
    Article 5(3): Terminal Equipment (Cookie Law).
    Detects cookies, localStorage, sessionStorage, tracking pixels, fingerprinting.
    """
    findings = []
    terminal_evidence = []
    consent_evidence = []

    # Using the shared AST extractor via flow_data if possible.
    # We will also do a light file scan for specific keywords if not fully captured by flow_data.
    
    keywords_terminal = ["cookie", "localstorage", "sessionstorage", "indexeddb", "tracking_pixel", "beacon", "navigator.useragent", "fingerprint"]
    keywords_analytics = ["google-analytics", "segment", "mixpanel", "analytics", "tracking", "facebook-pixel", "gtag", "fbp"]
    
    # We also check the flow_data for consent UI which is extracted centrally.
    consent_checkboxes = []
    if flow_data:
        for pii in flow_data.get("pii_fields", []):
            if pii.get("field") == "defaultChecked_checkbox":
                consent_checkboxes.append(pii)
                
    has_analytics = False
    has_unknown = False
    
    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            if any(skip in root for skip in ["node_modules", ".git", "dist", "build"]):
                continue
            for file in files:
                if file.endswith((".js", ".jsx", ".ts", ".tsx", ".html", ".vue")):
                    filepath = os.path.join(root, file)
                    rel_p = os.path.relpath(filepath, repo_path)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            if any(k in content for k in keywords_terminal):
                                terminal_evidence.append(f"Terminal equipment access/storage API detected in {rel_p}")
                                if any(a in content for a in keywords_analytics):
                                    has_analytics = True
                                else:
                                    has_unknown = True
                            if "cookie_consent" in content or "cookiebot" in content or "onetrust" in content or "consent" in content:
                                consent_evidence.append(f"Consent mechanism reference in {rel_p}")
                    except Exception:
                        pass
                        
    req = EPRIVACY_REQUIREMENTS["EPRIVACY-ART5-3-TERMINAL-EQUIPMENT"]
    
    if not terminal_evidence:
        return []

    ev_str = "; ".join(list(dict.fromkeys(terminal_evidence))[:5])
    
    if consent_evidence or consent_checkboxes:
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Terminal equipment storage (e.g., cookies/localStorage) with consent mechanism detected.",
            rule_id="EPRIVACY-ART5-3-TERMINAL-EQUIPMENT",
            title=req["title"],
            description="Codebase contains references to terminal equipment storage and a potential consent mechanism.",
            framework=FRAMEWORK_EPRIVACY,
            effective_status=EPRIVACY_EFFECTIVE_STATUS,
            effective_from=req["baseline_date"],
            eprivacy_references=["EPRIVACY-ART5-3-TERMINAL-EQUIPMENT"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence=f"Storage APIs: {ev_str}. Consent indicators: {'; '.join(list(dict.fromkeys(consent_evidence))[:2])}",
            recommended_action=req["recommended_action"],
            human_review_required="Verify that the consent mechanism meets the 'clear and comprehensive information' requirement and correctly blocks non-essential storage prior to consent."
        ))
    else:
        # No consent mechanism detected
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.MEDIUM if has_analytics else Severity.INFO,
            file=None,
            line=None,
            message=f"Terminal equipment storage (e.g., cookies/localStorage) detected without clear technical consent mechanism.",
            rule_id="EPRIVACY-ART5-3-TERMINAL-EQUIPMENT",
            title=req["title"],
            description="Terminal equipment storage APIs were detected, but no explicit consent mechanism (e.g., cookie banner integration) was identified in the source code.",
            framework=FRAMEWORK_EPRIVACY,
            effective_status=EPRIVACY_EFFECTIVE_STATUS,
            effective_from=req["baseline_date"],
            eprivacy_references=["EPRIVACY-ART5-3-TERMINAL-EQUIPMENT"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            requirement=req["requirement"],
            detected_evidence=f"Storage APIs: {ev_str}. NOT_DETECTED — No consent mechanism found.",
            recommended_action=req["recommended_action"],
            human_review_required="Review whether the stored information is strictly necessary (exempt from consent) or requires consent (e.g., analytics/tracking). Note: E-Privacy is implemented through national transposition."
        ))

    return findings

def check_eprivacy_art6_traffic_data(repo_path: str, flow_data: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """
    Article 6: Traffic Data Processing.
    Reuses PII fields from shared flow_data (IP addresses, timestamps).
    DO NOT CREATE DUPLICATE TRAFFIC METADATA DETECTOR.
    """
    findings = []
    traffic_evidence = []
    
    if flow_data:
        for pii in flow_data.get("pii_fields", []):
            field = str(pii.get("field", "")).lower()
            if any(k in field for k in ["ip", "ip_address", "timestamp", "mac", "mac_address"]):
                loc = f"{pii.get('file', 'unknown')}:{pii.get('line', '?')}"
                traffic_evidence.append(f"Traffic metadata field '{pii.get('field')}' detected at {loc}")
                
    req = EPRIVACY_REQUIREMENTS["EPRIVACY-ART6-TRAFFIC-DATA"]
    
    if traffic_evidence:
        ev_str = "; ".join(list(dict.fromkeys(traffic_evidence))[:5])
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Traffic data processing (IP addresses, timestamps) detected.",
            rule_id="EPRIVACY-ART6-TRAFFIC-DATA",
            title=req["title"],
            description="Codebase collects traffic data which is subject to erasure or anonymization when no longer needed for transmission, under Article 6.",
            framework=FRAMEWORK_EPRIVACY,
            effective_status=EPRIVACY_EFFECTIVE_STATUS,
            effective_from=req["baseline_date"],
            eprivacy_references=["EPRIVACY-ART6-TRAFFIC-DATA"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence=ev_str,
            recommended_action=req["recommended_action"],
            human_review_required="Verify retention policies and legal basis (e.g., billing, consent) for processing traffic metadata. Note: E-Privacy is implemented through national transposition."
        ))
        
        # We also need a human review for retention evidence
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Traffic data retention and erasure policies require review.",
            rule_id="EPRIVACY-ART6-TRAFFIC-RETENTION",
            title=req["title"],
            description="Repository code does not explicitly prove compliance with Article 6 erasure/anonymization mandates.",
            framework=FRAMEWORK_EPRIVACY,
            effective_status=EPRIVACY_EFFECTIVE_STATUS,
            effective_from=req["baseline_date"],
            eprivacy_references=["EPRIVACY-ART6-TRAFFIC-DATA"],
            compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
            requirement=req["requirement"],
            detected_evidence="INDETERMINATE — Missing retention/use/purpose/legal-context evidence for traffic data.",
            recommended_action=req["recommended_action"],
            human_review_required="Confirm traffic data is erased or made anonymous when no longer needed for the transmission of a communication, unless retained for billing or with consent."
        ))

    return findings

def check_eprivacy_art9_location_data(repo_path: str, flow_data: Optional[Dict[str, Any]] = None) -> List[Finding]:
    """
    Article 9: Location Data.
    Reuses PII fields for location/GPS.
    """
    findings = []
    location_evidence = []
    
    if flow_data:
        for pii in flow_data.get("pii_fields", []):
            field = str(pii.get("field", "")).lower()
            if any(k in field for k in ["location", "gps", "lat", "lng", "latitude", "longitude", "geolocation"]):
                loc = f"{pii.get('file', 'unknown')}:{pii.get('line', '?')}"
                location_evidence.append(f"Location data field '{pii.get('field')}' detected at {loc}")
                
    # Also check generic source code for geolocation API
    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            if any(skip in root for skip in ["node_modules", ".git", "dist", "build"]):
                continue
            for file in files:
                if file.endswith((".js", ".jsx", ".ts", ".tsx", ".html")):
                    filepath = os.path.join(root, file)
                    rel_p = os.path.relpath(filepath, repo_path)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            if "navigator.geolocation" in content:
                                location_evidence.append(f"Browser geolocation API used in {rel_p}")
                    except Exception:
                        pass

    req = EPRIVACY_REQUIREMENTS["EPRIVACY-ART9-LOCATION-DATA"]
    
    if location_evidence:
        ev_str = "; ".join(list(dict.fromkeys(location_evidence))[:5])
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Location data processing detected.",
            rule_id="EPRIVACY-ART9-LOCATION-DATA",
            title=req["title"],
            description="Evidence of precise location data collection found. Location data other than traffic data requires consent or anonymization.",
            framework=FRAMEWORK_EPRIVACY,
            effective_status=EPRIVACY_EFFECTIVE_STATUS,
            effective_from=req["baseline_date"],
            eprivacy_references=["EPRIVACY-ART9-LOCATION-DATA"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence=ev_str,
            recommended_action=req["recommended_action"],
            human_review_required="Review the purpose, consent evidence, transmission, third-party transfer, and retention/use of location data. Note: E-Privacy is implemented through national transposition."
        ))

    return findings

def check_eprivacy_art12_public_directories(repo_path: str) -> List[Finding]:
    """
    Article 12: Public Directories.
    Checks for public user directories.
    """
    findings = []
    dir_evidence = []
    
    if os.path.exists(repo_path):
        for root, dirs, files in os.walk(repo_path):
            if any(skip in root for skip in ["node_modules", ".git", "dist", "build"]):
                continue
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".java", ".go", ".php")):
                    filepath = os.path.join(root, file)
                    rel_p = os.path.relpath(filepath, repo_path)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read().lower()
                            if "public" in content and any(k in content for k in ["user_directory", "subscriber_directory", "users/list", "subscribers/list"]):
                                dir_evidence.append(f"Potential public directory endpoint in {rel_p}")
                    except Exception:
                        pass
                        
    req = EPRIVACY_REQUIREMENTS["EPRIVACY-ART12-PUBLIC-DIRECTORIES"]
    
    if dir_evidence:
        ev_str = "; ".join(list(dict.fromkeys(dir_evidence))[:5])
        findings.append(Finding(
            category=Category.PRIVACY,
            severity=Severity.INFO,
            file=None,
            line=None,
            message="Potential public subscriber/user directory endpoint detected.",
            rule_id="EPRIVACY-ART12-PUBLIC-DIRECTORIES",
            title=req["title"],
            description="Codebase contains references to user directories which may be publicly accessible.",
            framework=FRAMEWORK_EPRIVACY,
            effective_status=EPRIVACY_EFFECTIVE_STATUS,
            effective_from=req["baseline_date"],
            eprivacy_references=["EPRIVACY-ART12-PUBLIC-DIRECTORIES"],
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            requirement=req["requirement"],
            detected_evidence=ev_str,
            recommended_action=req["recommended_action"],
            human_review_required="Verify if the directory is authenticated/private or public. If public, ensure subscribers are informed and give consent prior to inclusion."
        ))
        
    return findings

def check_eprivacy_art13_direct_marketing(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> List[Finding]:
    """
    Article 13: Direct Marketing.
    Must consume existing CommunicationFlowEvidence. No duplicate SMS/email detectors.
    """
    findings = []
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, flow_data)
        
    req = EPRIVACY_REQUIREMENTS["EPRIVACY-ART13-DIRECT-MARKETING"]
    
    for ev in comm_evidence:
        # ePrivacy applies to automated calling systems, fax, and electronic mail (which includes SMS).
        if ev.channel in (CommunicationChannel.EMAIL.value, CommunicationChannel.SMS.value, CommunicationChannel.VOICE_CALL.value):
            loc_str = ev.source_locations[0].get("file", "unknown") if ev.source_locations else "unknown"
            
            if ev.purpose == CommunicationPurpose.TRANSACTIONAL.value:
                # Transactional flows are not automatically direct marketing
                findings.append(Finding(
                    category=Category.PRIVACY,
                    severity=Severity.INFO,
                    file=loc_str,
                    line=None,
                    message=f"Transactional {ev.channel} communication flow detected.",
                    rule_id="EPRIVACY-ART13-TRANSACTIONAL",
                    title=req["title"],
                    description=f"Transactional {ev.channel} communication detected. ePrivacy Article 13 direct marketing rules generally do not apply to strictly transactional messages.",
                    framework=FRAMEWORK_EPRIVACY,
                    effective_status=EPRIVACY_EFFECTIVE_STATUS,
                    effective_from=req["baseline_date"],
                    eprivacy_references=["EPRIVACY-ART13-DIRECT-MARKETING"],
                    compliance_finding_type=ComplianceFindingType.INVENTORY,
                    requirement=req["requirement"],
                    detected_evidence=f"Channel: {ev.channel}, Purpose: {ev.purpose} ({ev.purpose_confidence} confidence). Provider: {ev.provider}.",
                    recommended_action=req["recommended_action"],
                    human_review_required="Confirm that the communication does not contain mixed marketing content which would subject it to Article 13 consent requirements."
                ))
            elif ev.purpose == CommunicationPurpose.MARKETING.value:
                # Marketing flows require consent or soft opt-in
                if ev.consent_evidence:
                    findings.append(Finding(
                        category=Category.PRIVACY,
                        severity=Severity.INFO,
                        file=loc_str,
                        line=None,
                        message=f"Marketing {ev.channel} communication flow with consent evidence detected.",
                        rule_id="EPRIVACY-ART13-MARKETING-CONSENT",
                        title=req["title"],
                        description=f"Marketing {ev.channel} communication detected alongside consent mechanism references.",
                        framework=FRAMEWORK_EPRIVACY,
                        effective_status=EPRIVACY_EFFECTIVE_STATUS,
                        effective_from=req["baseline_date"],
                        eprivacy_references=["EPRIVACY-ART13-DIRECT-MARKETING"],
                        compliance_finding_type=ComplianceFindingType.INVENTORY,
                        requirement=req["requirement"],
                        detected_evidence=f"Channel: {ev.channel}, Purpose: {ev.purpose}. Consent Evidence: {'; '.join(ev.consent_evidence[:2])}",
                        recommended_action=req["recommended_action"],
                        human_review_required="Verify that the consent mechanism satisfies GDPR/ePrivacy standards (prior, informed, freely given opt-in)."
                    ))
                else:
                    findings.append(Finding(
                        category=Category.PRIVACY,
                        severity=Severity.MEDIUM,
                        file=loc_str,
                        line=None,
                        message=f"Marketing {ev.channel} communication flow detected without clear technical consent mechanism.",
                        rule_id="EPRIVACY-ART13-MARKETING-NOCONSENT",
                        title=req["title"],
                        description=f"Marketing {ev.channel} communication detected, but no explicit consent or opt-in evidence was found in the source code.",
                        framework=FRAMEWORK_EPRIVACY,
                        effective_status=EPRIVACY_EFFECTIVE_STATUS,
                        effective_from=req["baseline_date"],
                        eprivacy_references=["EPRIVACY-ART13-DIRECT-MARKETING"],
                        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                        requirement=req["requirement"],
                        detected_evidence=f"Channel: {ev.channel}, Purpose: {ev.purpose}. NOT_DETECTED — No consent mechanism found.",
                        recommended_action=req["recommended_action"],
                        human_review_required="Verify whether prior opt-in consent is obtained, or if the 'soft opt-in' exception for existing customers applies (requires opt-out option). Note: E-Privacy is implemented through national transposition."
                    ))
            elif ev.purpose in (CommunicationPurpose.MIXED.value, CommunicationPurpose.UNKNOWN.value):
                findings.append(Finding(
                    category=Category.PRIVACY,
                    severity=Severity.INFO,
                    file=loc_str,
                    line=None,
                    message=f"{ev.channel} communication flow with {ev.purpose} purpose detected.",
                    rule_id="EPRIVACY-ART13-MIXED-UNKNOWN",
                    title=req["title"],
                    description=f"{ev.channel} communication detected with {ev.purpose} purpose. Unresolved legal question regarding Article 13 applicability.",
                    framework=FRAMEWORK_EPRIVACY,
                    effective_status=EPRIVACY_EFFECTIVE_STATUS,
                    effective_from=req["baseline_date"],
                    eprivacy_references=["EPRIVACY-ART13-DIRECT-MARKETING"],
                    compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW,
                    requirement=req["requirement"],
                    detected_evidence=f"Channel: {ev.channel}, Purpose: {ev.purpose}. Provider: {ev.provider}.",
                    recommended_action=req["recommended_action"],
                    human_review_required="Review communication templates to determine if they contain direct marketing, which triggers Article 13 consent and opt-out requirements."
                ))
                
            # Check unsubscribe/suppression for all non-transactional or mixed
            if ev.purpose != CommunicationPurpose.TRANSACTIONAL.value:
                if ev.opt_out_evidence or ev.suppression_evidence:
                    findings.append(Finding(
                        category=Category.PRIVACY,
                        severity=Severity.INFO,
                        file=loc_str,
                        line=None,
                        message=f"Opt-out or suppression mechanism detected for {ev.channel} communication.",
                        rule_id="EPRIVACY-ART13-OPTOUT",
                        title=req["title"],
                        description=f"Evidence of unsubscribe or suppression lists found for {ev.channel} communications.",
                        framework=FRAMEWORK_EPRIVACY,
                        effective_status=EPRIVACY_EFFECTIVE_STATUS,
                        effective_from=req["baseline_date"],
                        eprivacy_references=["EPRIVACY-ART13-DIRECT-MARKETING"],
                        compliance_finding_type=ComplianceFindingType.INVENTORY,
                        requirement=req["requirement"],
                        detected_evidence=f"Opt-out/Suppression Evidence: {'; '.join((ev.opt_out_evidence + ev.suppression_evidence)[:3])}",
                        recommended_action=req["recommended_action"],
                        human_review_required="Ensure the opt-out mechanism is easy to use and free of charge."
                    ))

    return findings

def run_eprivacy_checks(
    repo_path: str,
    flow_data: Optional[Dict[str, Any]] = None,
    shared_findings: Optional[List[Finding]] = None,
    comm_evidence: Optional[List[CommunicationFlowEvidence]] = None
) -> Tuple[Dict[str, Any], List[Finding]]:
    """
    Main entry point for running EU ePrivacy Directive compliance checks.
    Consumes framework-neutral CommunicationFlowEvidence and Data Flow Graph.
    """
    if comm_evidence is None:
        comm_evidence = classify_communications(repo_path, flow_data)

    state, reasons, source = evaluate_eprivacy_applicability(repo_path)

    if state == "NOT_APPLICABLE":
        summary = {
            "status": ToolStatus.NOT_APPLICABLE.value,
            "applicability": "NOT_APPLICABLE",
            "applicability_source": source,
            "reasons": reasons,
            "findings_count": 0
        }
        return summary, []

    eprivacy_findings: List[Finding] = []

    # Run technical checks
    eprivacy_findings.extend(check_eprivacy_art5_confidentiality(repo_path, flow_data, shared_findings))
    eprivacy_findings.extend(check_eprivacy_art5_3_terminal_equipment(repo_path, flow_data))
    eprivacy_findings.extend(check_eprivacy_art6_traffic_data(repo_path, flow_data))
    eprivacy_findings.extend(check_eprivacy_art9_location_data(repo_path, flow_data))
    eprivacy_findings.extend(check_eprivacy_art12_public_directories(repo_path))
    eprivacy_findings.extend(check_eprivacy_art13_direct_marketing(repo_path, flow_data, comm_evidence))

    # Re-tag qualifying shared security findings
    if shared_findings:
        for f in shared_findings:
            if getattr(f, "status", None) == ToolStatus.COMPLETED.value or getattr(f, "status", None) == "OPEN":
                refs = get_eprivacy_references_for_rule(f.rule_id, f.detected_by)
                if refs:
                    if not hasattr(f, 'eprivacy_references') or f.eprivacy_references is None:
                        f.eprivacy_references = []
                    for r in refs:
                        if r not in f.eprivacy_references:
                            f.eprivacy_references.append(r)

    summary = {
        "status": ToolStatus.COMPLETED.value,
        "applicability": state,
        "applicability_source": source,
        "reasons": reasons,
        "findings_count": len(eprivacy_findings)
    }

    return summary, eprivacy_findings
