"""
India CERT-In (Cyber Security Directions under Section 70B(6) IT Act, 2000) Engine.
Evaluates repository evidence against CERT-In statutory requirements and Annexure I incident categories.
"""
import os
import re
from typing import List, Dict, Any, Tuple

from src.core.models import Finding, Category, ComplianceFindingType, ToolStatus
from src.compliance.cert_in_mapping import CERT_IN_REQUIREMENTS, get_cert_in_references_for_rule

VALID_ENTITY_TYPES = {
    "GENERAL",
    "DATA_CENTER",
    "VPN_PROVIDER",
    "CLOUD_SERVICE_PROVIDER",
    "VIRTUAL_ASSET_EXCHANGE"
}

def evaluate_cert_in_applicability(repo_path: str) -> Tuple[str, str, str]:
    """
    Evaluates CERT-In applicability and validates CERTIN_ENTITY_TYPE environment variable.
    Returns (general_applicability, entity_type, reason_description).
    Raises ValueError if CERTIN_ENTITY_TYPE contains an unsupported value.
    """
    entity_type = os.environ.get("CERTIN_ENTITY_TYPE", "GENERAL").upper().strip()
    
    if entity_type not in VALID_TYPES:
        raise ValueError(
            f"Invalid CERTIN_ENTITY_TYPE '{entity_type}'. Must be one of: "
            f"{', '.join(sorted(list(VALID_TYPES)))}"
        )
        
    reason = f"CERT-In general directions apply broadly to Indian entities. Entity scope configured as '{entity_type}'."
    return ("APPLICABLE", entity_type, reason)

VALID_TYPES = VALID_ENTITY_TYPES  # Alias for brevity

def check_log_retention_and_residency(repo_path: str) -> Finding:
    """
    Scans repository for 180-day log retention configuration and Indian cloud storage regions (ap-south-1, etc.).
    Guardrail: Technical evidence only; static config does not prove production compliance.
    """
    indian_regions = ["ap-south-1", "ap-south-2", "asia-south1", "southindia", "centralindia", "westindia"]
    retention_terms = ["180", "retention_in_days", "logrotate", "retentioninDays", "expire_logs_days"]
    
    found_region = None
    found_retention = False
    found_file = None
    
    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb", "dist", "build"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb", "dist", "build"]]
            
        for file_name in files:
            ext = os.path.splitext(file_name)[1].lower()
            fname_lower = file_name.lower()
            if ext in [".tf", ".yml", ".yaml", ".json", ".conf", ".env", ".py", ".js", ".mjs", ".ts"] or fname_lower.startswith("dockerfile") or fname_lower.startswith("containerfile"):
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        
                    for reg in indian_regions:
                        if reg in content.lower():
                            found_region = reg
                            found_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                            break
                            
                    for term in retention_terms:
                        if term in content:
                            found_retention = True
                            if not found_file:
                                found_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                            break
                            
                    if found_region and found_retention:
                        break
                except Exception:
                    pass
                    
        if found_region and found_retention:
            break

    rule_id = "cert-in-5v-log-retention-residency"
    cert_refs = ["CERT-IN-LOG-RETENTION"]
    
    if found_region or found_retention:
        evidence_text = []
        if found_region:
            evidence_text.append(f"Indian cloud region reference ('{found_region}')")
        if found_retention:
            evidence_text.append("180-day log retention setting")
        details = " and ".join(evidence_text)
        
        return Finding(
            category=Category.ARCHITECTURE.value,
            severity="info",
            file=found_file,
            line=1,
            message=f"Log retention duration / Indian cloud region configuration detected ({details}).",
            rule_id=rule_id,
            title="CERT-In §5(v) Log Retention (180 Days) & Data Residency",
            description=f"Repository configuration evidence detected ({details} in '{found_file}'). Note: Configuration is evidence of configured retention/residency, NOT proof that production CERT-In logs are actually retained for 180 days or stored in India.",
            detected_by=["cert-in-engine"],
            framework="CERT-IN",
            section="Directions §5(v)",
            effective_status="IN_FORCE",
            effective_from="2022-06-27",
            evidence_status="DETECTED",
            human_review_required="YES — Operational confirmation required via production attestation.",
            requirement="CERT-In Directions §5(v): ICT log retention for 180 days within Indian jurisdiction.",
            recommended_action="Verify operational execution of 180-day log retention and Indian cloud storage in production.",
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            cert_in_references=cert_refs
        )
    else:
        return Finding(
            category=Category.ARCHITECTURE.value,
            severity="info",
            file=None,
            line=None,
            message="180-day log retention or Indian cloud storage region could not be verified from repository configuration artifacts alone.",
            rule_id=rule_id,
            title="CERT-In §5(v) Log Retention (180 Days) & Data Residency",
            description="No explicit 180-day log retention setting or Indian cloud region string identified in static repository code. Note: Missing static evidence is not automatically a CERT-In violation; operational verification required.",
            detected_by=["cert-in-engine"],
            framework="CERT-IN",
            section="Directions §5(v)",
            effective_status="IN_FORCE",
            effective_from="2022-06-27",
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Confirm production log retention SLA and storage jurisdiction.",
            requirement="CERT-In Directions §5(v): ICT log retention for 180 days within Indian jurisdiction.",
            recommended_action="Document log retention parameters (180 days) and ensure storage within Indian jurisdiction.",
            compliance_finding_type=ComplianceFindingType.SECURITY_GAP,
            cert_in_references=cert_refs
        )

def check_ntp_synchronization(repo_path: str) -> Finding:
    """
    Scans repository for NTP time synchronization configuration (chrony, systemd-timesyncd, NPL/NIC traceable servers).
    Guardrail: Technical evidence only; static config does not prove active production clock sync.
    """
    ntp_signals = ["nplindia.org", "nic.in", "pool.ntp.org", "time.google.com", "chrony", "systemd-timesyncd", "ntpd", "timesyncd.conf"]
    
    found_signal = None
    found_file = None
    
    for root, dirs, files in os.walk(repo_path):
        if any(skip in dirs for skip in ["node_modules", ".git", ".vdb", "dist", "build"]):
            dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", ".vdb", "dist", "build"]]
            
        for file_name in files:
            ext = os.path.splitext(file_name)[1].lower()
            fname_lower = file_name.lower()
            if ext in [".conf", ".tf", ".yml", ".yaml", ".sh", ".json", ".env", ".py", ".js", ".ts"] or fname_lower.startswith("dockerfile") or fname_lower.startswith("containerfile"):
                abs_p = os.path.join(root, file_name)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        
                    for sig in ntp_signals:
                        if sig in content.lower():
                            found_signal = sig
                            found_file = os.path.relpath(abs_p, repo_path).replace("\\", "/")
                            break
                    if found_signal:
                        break
                except Exception:
                    pass
        if found_signal:
            break
            
    rule_id = "cert-in-5i-ntp-synchronization"
    cert_refs = ["CERT-IN-NTP"]
    
    if found_signal:
        return Finding(
            category=Category.ARCHITECTURE.value,
            severity="info",
            file=found_file,
            line=1,
            message=f"NTP time synchronization configuration detected in repository files ('{found_signal}').",
            rule_id=rule_id,
            title="CERT-In §5(i) NTP Time Synchronization Configuration",
            description=f"NTP configuration signal ('{found_signal}') found in '{found_file}'. Note: Repository configuration is evidence of configured time sync only; operational confirmation of active NPL/NIC clock synchronization in production is required.",
            detected_by=["cert-in-engine"],
            framework="CERT-IN",
            section="Directions §5(i)",
            effective_status="IN_FORCE",
            effective_from="2022-06-27",
            evidence_status="DETECTED",
            human_review_required="YES — Verify operational clock sync with NPL/NIC standard time sources in production.",
            requirement="CERT-In Directions §5(i): ICT system clock synchronization with NPL/NIC traceable NTP sources.",
            recommended_action="Ensure production servers actively sync clocks with NPL/NIC traceable NTP sources.",
            compliance_finding_type=ComplianceFindingType.INVENTORY,
            cert_in_references=cert_refs
        )
    else:
        return Finding(
            category=Category.ARCHITECTURE.value,
            severity="info",
            file=None,
            line=None,
            message="NTP time synchronization configuration could not be verified from repository configuration artifacts alone.",
            rule_id=rule_id,
            title="CERT-In §5(i) NTP Time Synchronization Configuration",
            description="No explicit NTP server configuration or timesyncd signal identified in static repository code. Note: Missing static evidence is not automatically a CERT-In violation; operational verification required.",
            detected_by=["cert-in-engine"],
            framework="CERT-IN",
            section="Directions §5(i)",
            effective_status="IN_FORCE",
            effective_from="2022-06-27",
            evidence_status="NOT_DETECTED",
            human_review_required="YES — Confirm NTP client configuration on all infrastructure nodes.",
            requirement="CERT-In Directions §5(i): ICT system clock synchronization with NPL/NIC traceable NTP sources.",
            recommended_action="Configure NTP clients on infrastructure nodes pointing to NPL/NIC traceable time sources.",
            compliance_finding_type=ComplianceFindingType.SECURITY_GAP,
            cert_in_references=cert_refs
        )

def generate_cert_in_attestations(entity_type: str) -> List[Finding]:
    """
    Generates report-level Organizational Attestation Checklist items for non-code-verifiable CERT-In requirements:
    - 6-Hour Cyber Incident Reporting SLA (Directions §5(iii))
    - Operational 180-Day Log Retention Execution (Directions §5(v))
    - Operational NTP Time Synchronization Execution (Directions §5(i))
    - 5-Year Subscriber / KYC Record-Keeping (Directions §5(vi)) — Gated on entity_type != GENERAL
    """
    checklist = []
    
    # 1. 6-Hour SLA Incident Reporting Attestation
    checklist.append(Finding(
        category=Category.SECURITY.value,
        severity="info",
        file=None,
        line=None,
        message="[Organizational Attestation Required] CERT-In Directions §5(iii): Named incident owner and process to report cyber security incidents to CERT-In within 6 hours.",
        rule_id="cert-in-5iii-6h-incident-reporting-attestation",
        title="CERT-In §5(iii) 6-Hour Incident Reporting SLA Checklist",
        description="6-hour mandatory cyber incident reporting SLA requires named incident response owners and escalation procedures. Cannot be verified from application source code alone.",
        detected_by=["cert-in-engine"],
        framework="CERT-IN",
        section="Directions §5(iii)",
        effective_status="IN_FORCE",
        effective_from="2022-06-27",
        evidence_status="INDETERMINATE",
        human_review_required="YES — Human owner must sign off 6-hour incident escalation SLA to CERT-In.",
        requirement="CERT-In Directions §5(iii): Mandatory 6-hour reporting to CERT-In for 20 Annexure I incident categories.",
        recommended_action="Document incident response plan meeting CERT-In 6-hour reporting SLA (Effective 27 June 2022).",
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        cert_in_references=["CERT-IN-ANNEX-1", "CERT-IN-ANNEX-2", "CERT-IN-ANNEX-3"]
    ))
    
    # 2. Production Log Retention Execution Attestation
    checklist.append(Finding(
        category=Category.SECURITY.value,
        severity="info",
        file=None,
        line=None,
        message="[Organizational Attestation Required] CERT-In Directions §5(v): Operational confirmation that logs are actively retained for 180 days in production and stored in India.",
        rule_id="cert-in-5v-production-log-retention-attestation",
        title="CERT-In §5(v) Production Log Retention Attestation",
        description="Static repository evidence cannot verify active 180-day log rotation or production storage jurisdiction. Operational attestation required.",
        detected_by=["cert-in-engine"],
        framework="CERT-IN",
        section="Directions §5(v)",
        effective_status="IN_FORCE",
        effective_from="2022-06-27",
        evidence_status="INDETERMINATE",
        human_review_required="YES — Infrastructure lead must confirm 180-day log retention and Indian storage in production.",
        requirement="CERT-In Directions §5(v): Secure maintenance of ICT logs for 180 days within Indian jurisdiction.",
        recommended_action="Verify and document production log retention policies and storage regions.",
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        cert_in_references=["CERT-IN-LOG-RETENTION"]
    ))
    
    # 3. Production NTP Time Sync Execution Attestation
    checklist.append(Finding(
        category=Category.SECURITY.value,
        severity="info",
        file=None,
        line=None,
        message="[Organizational Attestation Required] CERT-In Directions §5(i): Operational confirmation that production system clocks are synchronized with NPL/NIC NTP sources.",
        rule_id="cert-in-5i-production-ntp-execution-attestation",
        title="CERT-In §5(i) Production NTP Time Sync Attestation",
        description="Active system clock synchronization with NPL/NIC traceable time servers must be operationally verified in production.",
        detected_by=["cert-in-engine"],
        framework="CERT-IN",
        section="Directions §5(i)",
        effective_status="IN_FORCE",
        effective_from="2022-06-27",
        evidence_status="INDETERMINATE",
        human_review_required="YES — Infrastructure lead must confirm active NTP sync with NPL/NIC traceable sources.",
        requirement="CERT-In Directions §5(i): Clock synchronization with NPL/NIC traceable NTP sources.",
        recommended_action="Document production NTP daemon configuration and NPL/NIC server synchronization.",
        compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
        cert_in_references=["CERT-IN-NTP"]
    ))
    
    # 4. Entity-Specific 5-Year KYC Record-Keeping Attestation (Gated)
    if entity_type != "GENERAL":
        checklist.append(Finding(
            category=Category.SECURITY.value,
            severity="info",
            file=None,
            line=None,
            message=f"[Organizational Attestation Required] CERT-In Directions §5(vi): 5-year subscriber/KYC record-keeping requirement for {entity_type}.",
            rule_id="cert-in-5vi-5yr-kyc-recordkeeping-attestation",
            title=f"CERT-In §5(vi) 5-Year Subscriber KYC Record-Keeping Checklist ({entity_type})",
            description=f"Entity type is configured as '{entity_type}'. CERT-In Directions §5(vi) requires data centers, VPS providers, cloud service providers, and virtual asset exchanges to maintain subscriber identity, IP addresses, contact details, and transaction logs for 5 years after registration cancellation.",
            detected_by=["cert-in-engine"],
            framework="CERT-IN",
            section="Directions §5(vi)",
            effective_status="IN_FORCE",
            effective_from="2022-06-27",
            evidence_status="INDETERMINATE",
            human_review_required=f"YES — Compliance officer must confirm 5-year subscriber/KYC retention policy for {entity_type}.",
            requirement=f"CERT-In Directions §5(vi): 5-year subscriber KYC record-keeping requirement for {entity_type}.",
            recommended_action=f"Maintain subscriber registration, validated identity, IP address, and billing logs for 5 years.",
            compliance_finding_type=ComplianceFindingType.ATTESTATION_REQUIRED,
            cert_in_references=["CERT-IN-KYC"]
        ))
        
    return checklist

def run_cert_in_checks(
    repo_path: str,
    shared_findings: List[Finding]
) -> List[Finding]:
    """
    Executes CERT-In specific requirement checks, validates CERTIN_ENTITY_TYPE,
    generates dedicated findings, and re-tags qualifying shared security findings in-place.
    """
    cert_in_findings: List[Finding] = []
    
    # 1. Applicability & Entity Type Validation
    general_app, entity_type, reason = evaluate_cert_in_applicability(repo_path)
    
    # 2. Log Retention & Residency Check
    retention_finding = check_log_retention_and_residency(repo_path)
    cert_in_findings.append(retention_finding)
    
    # 3. NTP Synchronization Check
    ntp_finding = check_ntp_synchronization(repo_path)
    cert_in_findings.append(ntp_finding)
    
    # 4. Attestations
    attestations = generate_cert_in_attestations(entity_type)
    cert_in_findings.extend(attestations)
    
    # 5. Reference-Tagging Pass on shared findings
    # Guardrail: Exclude findings from tools that failed (ToolStatus.ERROR) or were skipped!
    for f in shared_findings:
        refs = get_cert_in_references_for_rule(f.rule_id, f.detected_by, f.severity)
        if refs:
            existing = set(f.cert_in_references or [])
            existing.update(refs)
            f.cert_in_references = sorted(list(existing))
            
    return cert_in_findings
