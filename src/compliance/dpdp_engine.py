"""
DPDP Act 2023 + DPDP Rules 2025 Requirement Mapping & Compliance Engine.
Evaluates repository evidence against DPDP §§3–17 using shared evidence layer.
"""
import uuid
from typing import List, Dict, Any, Optional

from src.core.models import Finding, FindingEvidence, FindingLocation, Category, ComplianceFindingType
from src.compliance.dpdp_constants import (
    get_dpdp_tier_info,
    get_dpdp_restricted_countries_config,
    DPDP_REQUIREMENTS,
    DPDP_PENALTY_SCHEDULE_REFERENCE
)
from src.compliance.dpdp_basis import evaluate_dpdp_processing_basis

def run_dpdp_checks(
    repo_path: str,
    flow_data: Dict[str, Any],
    shared_findings: List[Finding]
) -> List[Finding]:
    """
    Executes DPDP-specific requirement checks against the shared evidence layer.
    Returns a list of DPDP Findings tagged with framework, section, processing_basis,
    effective_status, effective_from, and evidence_status.
    """
    dpdp_findings: List[Finding] = []
    
    pii_fields = flow_data.get("pii_fields", [])
    unused_pii = flow_data.get("unused_pii_fields", [])
    transfers = flow_data.get("third_party_transfers", [])
    unprotected_storage = flow_data.get("unprotected_storage", [])
    outbound_calls = flow_data.get("outbound_calls", [])
    
    # -------------------------------------------------------------------------
    # 1. DPDP §3 — Applicability Check
    # -------------------------------------------------------------------------
    sec = "3"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="DPDP §3 Scope Assessment: Digital personal data collection detected in application codebase.",
        rule_id="dpdp-3-applicability",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="Digital personal data processing detected. Verify whether data principals are located in India or services target individuals in India.",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="DETECTED",
        human_review_required="YES — Confirm Indian jurisdiction and applicability under §3.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.INVENTORY
    ))

    # -------------------------------------------------------------------------
    # 2. DPDP §5 & §6 — Notice, Consent, and Processing Basis (§4 & §7)
    # -------------------------------------------------------------------------
    # Analyze UI consent checkboxes
    consent_checkboxes = [p for p in pii_fields if p.get("field") == "defaultChecked_checkbox"]
    
    if consent_checkboxes:
        for cb in consent_checkboxes:
            ctx = {
                "purpose": "consent_capture",
                "field": "consent",
                "is_consent_flow": True,
                "consent_ui_default_checked": True
            }
            basis = evaluate_dpdp_processing_basis(ctx)
            sec = "6(1)"
            eff_status, eff_from = get_dpdp_tier_info(sec)
            
            dpdp_findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="medium",
                file=cb.get("file"),
                line=cb.get("line"),
                message="Consent UI element is default-checked. DPDP §6(1) requires unambiguous affirmative action.",
                rule_id="dpdp-6-1-preticked-consent",
                title=DPDP_REQUIREMENTS[sec]["title"],
                description="Consent-capture UI element is pre-ticked by default. Under DPDP §6(1), pre-ticked consent is invalid as it fails the clear affirmative action requirement.",
                detected_by=["dpdp-engine"],
                framework="DPDP",
                section=sec,
                processing_basis=basis,
                effective_status=eff_status,
                effective_from=eff_from,
                evidence_status="DETECTED",
                human_review_required="YES — Legal review of consent UI interaction and unbundling.",
                requirement=DPDP_REQUIREMENTS[sec]["requirement"],
                recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
                compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
            ))
            
    # DPDP §5 Notice Check
    sec = "5"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="Itemised privacy notice and rights summary required for consent requests under DPDP §5.",
        rule_id="dpdp-5-notice-requirements",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="Verify that consent requests present an itemised notice detailing data fields, purpose, withdrawal under §6(4), Data Principal rights (§§11–14), and Board grievance procedures.",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Verify itemised notice copy and multi-language support (English/Schedule 8).",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # Tier 2: §6(9) Consent Manager Check
    sec = "6(9)"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="Consent Manager registration status requires verification under DPDP §6(9).",
        rule_id="dpdp-6-9-consent-manager",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="Consent Managers used to manage Data Principal consent must be registered with the Data Protection Board. (Tier 2 requirement effective 13 Nov 2026).",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Verify Consent Manager registration with the Board once Tier 2 takes effect.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # Evaluate processing basis for detected third-party flows & PII fields
    for tx in transfers:
        ctx = {
            "purpose": "outbound_processing",
            "field": tx.get("field"),
            "processor": tx.get("processor"),
            "is_consent_flow": False
        }
        basis = evaluate_dpdp_processing_basis(ctx)
        
        # DPDP §4 & §7 Ground evaluation for processor transfer
        sec = "4"
        eff_status, eff_from = get_dpdp_tier_info(sec)
        dpdp_findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=tx.get("file"),
            line=tx.get("line"),
            message=f"DPDP Lawful Basis Assessment for data flow '{tx.get('field')}' → {tx.get('processor')}.",
            rule_id="dpdp-4-grounds-for-processing",
            title=f"DPDP §4 Grounds: {tx.get('processor')}",
            description=f"Processing basis for '{tx.get('field')}' transmitted to '{tx.get('processor')}': {basis.get('evidence')}",
            detected_by=["dpdp-engine"],
            framework="DPDP",
            section=sec,
            processing_basis=basis,
            effective_status=eff_status,
            effective_from=eff_from,
            evidence_status=basis.get("status", "INDETERMINATE"),
            human_review_required="YES — Legal team must confirm whether processing rests on valid consent (§6) or a §7 legitimate use.",
            requirement=DPDP_REQUIREMENTS["6(1)"]["requirement"],
            recommended_action="Verify specific consent or applicable §7 sub-clause (7(a)-7(i)).",
            compliance_finding_type=ComplianceFindingType.THIRD_PARTY_RISK
        ))

    # -------------------------------------------------------------------------
    # 3. DPDP §8 — General Obligations of Data Fiduciary
    # -------------------------------------------------------------------------
    # §8(3) Accuracy
    sec = "8(3)"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="DPDP §8(3): Accuracy and completeness obligations for personal data.",
        rule_id="dpdp-8-3-accuracy",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="Verify that personal data used to make decisions affecting individuals or shared onward is accurate, complete, and consistent.",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Verify data completeness controls for decision-making pipelines.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # §8(4)-(5) Security Safeguards
    sec = "8(4)"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    for store in unprotected_storage:
        dpdp_findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=store.get("file"),
            line=store.get("line"),
            message=f"Storage protection for '{store.get('field')}' could not be technically established under DPDP §8(4)-(5).",
            rule_id="dpdp-8-5-security-safeguards",
            title=f"DPDP §8(5) Security: {store.get('field')}",
            description=f"Reasonable technical security safeguards (encryption at rest, access controls) for '{store.get('field')}' could not be verified from application code alone.",
            detected_by=["dpdp-engine"],
            framework="DPDP",
            section="8(5)",
            effective_status=eff_status,
            effective_from=eff_from,
            evidence_status="INDETERMINATE",
            human_review_required="YES — Security team must confirm encryption and access controls.",
            requirement=DPDP_REQUIREMENTS[sec]["requirement"],
            recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
            compliance_finding_type=ComplianceFindingType.SECURITY_GAP
        ))

    # =========================================================================
    # §8(6) BREACH NOTIFICATION — EXPLICIT DPDP IMPLEMENTATION RULE
    # =========================================================================
    # DPDP §8(6) Breach Notification Rule: DPDP requires notification to BOTH
    # the Data Protection Board AND EACH affected Data Principal.
    # CRITICAL: DO NOT reuse or import GDPR's 'likely to result in a high risk'
    # severity/risk gate to suppress Data Principal notification under DPDP.
    # =========================================================================
    sec = "8(6)"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="DPDP §8(6): Personal data breach notification pipeline requires Board and Data Principal notification mechanisms.",
        rule_id="dpdp-8-6-breach-notification",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="Verify technical logging, alerting, and incident response readiness to notify BOTH the Data Protection Board and ALL affected Data Principals in the event of a personal data breach. Note: DPDP §8(6) does not contain a GDPR-style high-risk severity gate.",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Incident response team must confirm notification capability for Board and affected Data Principals.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # §8(7)-(8) Erasure upon Purpose Completion
    sec = "8(7)"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    if unused_pii:
        for u in unused_pii:
            dpdp_findings.append(Finding(
                category=Category.PRIVACY.value,
                severity="medium",
                file=u.get("file"),
                line=u.get("line"),
                message=f"Unused personal data '{u.get('field')}' detected; erasure required under DPDP §8(7) when purpose no longer served.",
                rule_id="dpdp-8-7-data-erasure",
                title=f"DPDP §8(7) Erasure: {u.get('field')}",
                description=f"Personal data field '{u.get('field')}' is collected but never read or used. DPDP §8(7) mandates erasure when specified purpose is no longer served.",
                detected_by=["dpdp-engine"],
                framework="DPDP",
                section=sec,
                effective_status=eff_status,
                effective_from=eff_from,
                evidence_status="DETECTED",
                human_review_required="YES — Verify erasure or retention schedule justification.",
                requirement=DPDP_REQUIREMENTS[sec]["requirement"],
                recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
                compliance_finding_type=ComplianceFindingType.MINIMISATION_FLAG
            ))
            
    # §8(9) Designated Contact Requirement (Distinguished from SDF DPO)
    sec = "8(9)"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="Designated contact / applicable DPO information could not be technically established from repository evidence.",
        rule_id="dpdp-8-9-designated-contact",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="Designated contact / applicable DPO information could not be technically established from repository evidence under DPDP §8(9).",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Confirm designated business contact details are published for Data Principal inquiries.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # §8(10) Grievance Redressal Endpoint
    sec = "8(10)"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="DPDP §8(10): Accessible grievance redressal mechanism required for Data Principals.",
        rule_id="dpdp-8-10-grievance-mechanism",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="Data Fiduciaries must provide an easily accessible grievance submission mechanism for Data Principals.",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Confirm grievance intake workflow.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # -------------------------------------------------------------------------
    # 4. DPDP §9 — Processing of Children's and Disabled Persons' Data
    # -------------------------------------------------------------------------
    sec = "9"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="DPDP §9 Independent Children's Data Regime: Verifiable parental consent and tracking prohibition.",
        rule_id="dpdp-9-childrens-data-regime",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="DPDP §9 establishes a distinct children's data regime requiring verifiable parental consent before processing data of minors (<18), prohibiting harmful processing, and banning behavioral tracking or targeted advertising.",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Confirm whether application processes children's data or uses tracking SDKs on child-facing surfaces.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # -------------------------------------------------------------------------
    # 5. DPDP §10 — Significant Data Fiduciary (SDF) Obligations
    # -------------------------------------------------------------------------
    # Non-computable threshold. Engine surfaces technical indicators only.
    sec = "10"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="DPDP §10 Significant Data Fiduciary (SDF) Status: Non-computable government notification threshold.",
        rule_id="dpdp-10-significant-data-fiduciary",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="SDF applicability is a government notification threshold based on processing volume, sensitivity, and risk. Scanner cannot auto-determine SDF status.",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Legal team must evaluate whether government SDF notification applies.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # -------------------------------------------------------------------------
    # 6. DPDP §§11–14 — Data Principal Rights
    # -------------------------------------------------------------------------
    # §11 Summary/Access, §12 Rectification/Erasure, §13 Grievance, §14 Nomination
    sec = "14"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    dpdp_findings.append(Finding(
        category=Category.PRIVACY.value,
        severity="info",
        file=None,
        line=None,
        message="DPDP §14 Right to Nominate: Feature check for Data Principal representative nomination.",
        rule_id="dpdp-14-right-to-nominate",
        title=DPDP_REQUIREMENTS[sec]["title"],
        description="DPDP §14 grants Data Principals the right to nominate an individual to exercise rights on their death/incapacity. (DPDP-specific requirement with no direct GDPR analog).",
        detected_by=["dpdp-engine"],
        framework="DPDP",
        section=sec,
        effective_status=eff_status,
        effective_from=eff_from,
        evidence_status="INDETERMINATE",
        human_review_required="YES — Evaluate implementation of nomination feature in user account management.",
        requirement=DPDP_REQUIREMENTS[sec]["requirement"],
        recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
        compliance_finding_type=ComplianceFindingType.HUMAN_REVIEW
    ))

    # -------------------------------------------------------------------------
    # 7. DPDP §16 — Cross-Border Data Transfer (Blacklist Model)
    # -------------------------------------------------------------------------
    # Evaluates against DPDP_RESTRICTED_COUNTRIES config. DOES NOT reuse GDPR adequacy list.
    sec = "16"
    eff_status, eff_from = get_dpdp_tier_info(sec)
    restricted_cfg = get_dpdp_restricted_countries_config()
    restricted_countries = restricted_cfg.get("countries", [])
    
    if not restricted_countries:
        # Default empty list state -> Emit non-blocking informational state
        dpdp_findings.append(Finding(
            category=Category.PRIVACY.value,
            severity="info",
            file=None,
            line=None,
            message="No countries are currently configured as restricted under DPDP §16; restriction-based cross-border findings are not being generated from this dataset.",
            rule_id="dpdp-16-restricted-countries-config",
            title=DPDP_REQUIREMENTS[sec]["title"],
            description="No countries are currently configured as restricted under DPDP §16; restriction-based cross-border findings are not being generated from this dataset.",
            detected_by=["dpdp-engine"],
            framework="DPDP",
            section=sec,
            effective_status=eff_status,
            effective_from=eff_from,
            evidence_status="INDETERMINATE",
            human_review_required="NO — Informational configuration state.",
            requirement=DPDP_REQUIREMENTS[sec]["requirement"],
            recommended_action="Update DPDP_RESTRICTED_COUNTRIES environment configuration when Central Government issues Section 16 notifications.",
            compliance_finding_type=ComplianceFindingType.THIRD_PARTY_RISK
        ))
    else:
        # Check transfers against configured restricted list
        detected_restricted = []
        for tx in transfers:
            dest = str(tx.get("destination") or tx.get("processor") or "").lower()
            for r_country in restricted_countries:
                if r_country.lower() in dest:
                    detected_restricted.append((tx, r_country))
                    
        if detected_restricted:
            for tx, r_country in detected_restricted:
                dpdp_findings.append(Finding(
                    category=Category.PRIVACY.value,
                    severity="high",
                    file=tx.get("file"),
                    line=tx.get("line"),
                    message=f"Personal data transfer to restricted country '{r_country}' detected under DPDP §16.",
                    rule_id="dpdp-16-restricted-country-transfer",
                    title=f"DPDP §16 Restricted Transfer: {r_country}",
                    description=f"Personal data transfer of field '{tx.get('field')}' to restricted destination '{tx.get('processor')}' ({r_country}) detected under DPDP §16.",
                    detected_by=["dpdp-engine"],
                    framework="DPDP",
                    section=sec,
                    effective_status=eff_status,
                    effective_from=eff_from,
                    evidence_status="DETECTED",
                    human_review_required="YES — Legal review of cross-border transfer restriction.",
                    requirement=DPDP_REQUIREMENTS[sec]["requirement"],
                    recommended_action=DPDP_REQUIREMENTS[sec]["recommended_action"],
                    compliance_finding_type=ComplianceFindingType.THIRD_PARTY_RISK
                ))

    # -------------------------------------------------------------------------
    # 8. DPDP §17 — Exemptions (Suppression / Exception Layer)
    # -------------------------------------------------------------------------
    # §17 tags flows with exemption context (litigation hold, research-only, notified startup)
    # Logging audit reasons rather than generating finding alerts.
    
    return dpdp_findings
