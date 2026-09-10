"""
DPDP Act 2023 + DPDP Rules 2025 Constants and Tier Mappings.
"""
import os
import json
from typing import Dict, Tuple, List, Any

# Section Effective Dates and Tier Schedules (Verified against Gazette Notification G.S.R. 843(E))
# Tier 1 (13 Nov 2025) - IN_FORCE
TIER_1_SECTIONS = {
    "1(2)", "2", "18", "19", "20", "21", "22", "23", "24", "25", "26",
    "35", "38", "39", "40", "41", "42", "43", "44(1)", "44(3)"
}

# Tier 2 (13 Nov 2026) - FUTURE_STATE
TIER_2_SECTIONS = {
    "6(9)", "27(1)(d)"
}

# Tier 3 (13 May 2027) - FUTURE_STATE (Substantive obligations)
# §§3–5, §6(1)–(8)&(10), §§7–10, §§11–17, §27 (except 1(d)), §§28–34, §36, §37, §44(2)

def get_dpdp_tier_info(section: str) -> Tuple[str, str]:
    """Returns (effective_status, effective_from) for a given section."""
    clean_sec = section.strip()
    if clean_sec in TIER_1_SECTIONS:
        return ("IN_FORCE", "2025-11-13")
    elif clean_sec in TIER_2_SECTIONS:
        return ("FUTURE_STATE", "2026-11-13")
    else:
        # Default Tier 3 for substantive obligations §§3-17 etc.
        return ("FUTURE_STATE", "2027-05-13")

# Section 16 Restricted Countries Specification
# Default list MUST be [] per technical specification. Do not hardcode/seed fake countries.
DEFAULT_DPDP_RESTRICTED_COUNTRIES: Dict[str, Any] = {
    "countries": [],
    "source": "MeitY Gazette notifications under Section 16",
    "source_reference": "https://www.meity.gov.in/static/uploads/2024/02/Digital-Personal-Data-Protection-Act-2023.pdf",
    "last_verified": "2026-09-10"
}

def get_dpdp_restricted_countries_config() -> Dict[str, Any]:
    """Retrieves current DPDP restricted countries configuration with provenance metadata."""
    env_countries = os.environ.get("DPDP_RESTRICTED_COUNTRIES")
    config = dict(DEFAULT_DPDP_RESTRICTED_COUNTRIES)
    if env_countries:
        try:
            # Can be JSON array or comma-separated string
            if env_countries.startswith("["):
                config["countries"] = json.loads(env_countries)
            else:
                config["countries"] = [c.strip() for c in env_countries.split(",") if c.strip()]
        except Exception:
            config["countries"] = [env_countries.strip()]
    return config

# Section 7 Legitimate Uses Closed Enumeration
LEGITIMATE_USE_CATEGORIES = {
    "7(a)": "voluntary_disclosure_specified_purpose",
    "7(b)": "state_subsidy_benefit_service",
    "7(c)": "state_function_sovereignty_security",
    "7(d)": "legal_disclosure_obligation",
    "7(e)": "judgment_or_court_order_compliance",
    "7(f)": "medical_emergency",
    "7(g)": "public_health_epidemic_measures",
    "7(h)": "disaster_safety_measures",
    "7(i)": "employment_related"
}

# Static Penalty Reference Text (§33 & Schedule) - Excluded from findings, included as reference context only
DPDP_PENALTY_SCHEDULE_REFERENCE = (
    "DPDP §33 Penalty Schedule Reference Context (Non-computable reference only):\n"
    "- Failure to take reasonable security safeguards to prevent personal data breach (§8(5)): Up to ₹250 Crore\n"
    "- Failure to notify Board or affected Data Principals of a personal data breach (§8(6)): Up to ₹200 Crore\n"
    "- Non-fulfilment of additional obligations in relation to children (§9): Up to ₹200 Crore\n"
    "- Non-fulfilment of additional obligations of Significant Data Fiduciary (§10): Up to ₹150 Crore\n"
    "- Breach of any other provision or rules: Up to ₹50 Crore"
)

# DPDP Requirement Descriptions & Details
DPDP_REQUIREMENTS = {
    "3": {
        "title": "DPDP §3 — Applicability",
        "requirement": "DPDP Act applies to digital personal data collected within India, or outside India if connected to offering goods/services to Data Principals in India.",
        "recommended_action": "Verify if application services/users are located in or target individuals in India."
    },
    "5": {
        "title": "DPDP §5 — Notice Requirements",
        "requirement": "DPDP §5 requires that every consent request be accompanied or preceded by an itemised notice stating: personal data collected, purpose of processing, withdrawal rights under §6(4), Data Principal rights under §§11–14, and how to lodge complaints with the Board.",
        "recommended_action": "Ensure consent UI/collection forms present itemised notice with purpose, withdrawal instructions, rights summary, and Board grievance redress details."
    },
    "6(1)": {
        "title": "DPDP §6(1) — Valid Consent",
        "requirement": "Consent must be free, specific, informed, unconditional, unambiguous, given via clear affirmative action, and limited to necessary data. Bundled or default-on consent is invalid.",
        "recommended_action": "Ensure consent checkboxes are not pre-checked by default and consent is unbundled from unrelated terms."
    },
    "6(4)": {
        "title": "DPDP §6(4) — Right to Withdraw Consent",
        "requirement": "Data Principal has the right to withdraw consent at any time. Withdrawal of consent must be as easy as giving consent.",
        "recommended_action": "Provide a self-service consent revocation mechanism or API endpoint (e.g. /api/user/consent or /unsubscribe) that halts processing."
    },
    "6(9)": {
        "title": "DPDP §6(9) — Consent Manager Registration",
        "requirement": "Consent Managers must be registered with the Data Protection Board and satisfy technical/interoperability standards.",
        "recommended_action": "Verify if third-party Consent Manager integrations are registered with the Board (Tier 2 obligation effective 13 Nov 2026)."
    },
    "8(3)": {
        "title": "DPDP §8(3) — Accuracy and Completeness",
        "requirement": "Data Fiduciary must ensure accuracy, completeness, and consistency of personal data where it is used to make decisions affecting the Data Principal or disclosed onward.",
        "recommended_action": "Implement data validation and update mechanisms where personal data feeds decision-making or external sharing."
    },
    "8(4)": {
        "title": "DPDP §8(4)-(5) — Security Safeguards",
        "requirement": "DPDP §8(4)-(5) obligates Data Fiduciaries to implement reasonable technical and organizational security safeguards against personal data breaches.",
        "recommended_action": "Ensure encryption at rest, transport security (TLS), strict access controls, and vulnerability management across data stores."
    },
    "8(6)": {
        "title": "DPDP §8(6) — Personal Data Breach Notification",
        "requirement": "In the event of a personal data breach, the Data Fiduciary must notify the Data Protection Board and EACH affected Data Principal. (Note: DPDP §8(6) does not contain a GDPR-style 'high risk' severity gate).",
        "recommended_action": "Establish technical logging, alerting, and breach response workflow capable of notifying both the Board and affected individuals."
    },
    "8(7)": {
        "title": "DPDP §8(7)-(8) — Erasure upon Purpose Completion / Withdrawal",
        "requirement": "Data Fiduciary must erase personal data as soon as consent is withdrawn or the specified purpose is no longer served, unless retention is legally mandated.",
        "recommended_action": "Implement automated data retention schedules, cleanup background jobs, or deletion routines."
    },
    "8(9)": {
        "title": "DPDP §8(9) — Designated Contact / Privacy Information",
        "requirement": "Data Fiduciary must publish business contact details of a designated person or DPO capable of answering Data Principal queries.",
        "recommended_action": "Publish designated privacy contact details (e.g. dpo@, privacy@, or contact form) in accessibility notices."
    },
    "8(10)": {
        "title": "DPDP §8(10) — Grievance Redressal Mechanism",
        "requirement": "Data Fiduciary must provide an effective grievance redressal mechanism for Data Principals.",
        "recommended_action": "Expose a dedicated grievance submission route or support endpoint for privacy complaints."
    },
    "9": {
        "title": "DPDP §9 — Processing of Children's & Disabled Persons' Data",
        "requirement": "Verifiable parental/guardian consent is required prior to processing data of a child (<18) or person with disability. No processing likely to cause harm, and no behavioral tracking or targeted advertising directed at children.",
        "recommended_action": "Verify age-gating, parental consent verification, and absence of tracking/advertising SDKs on child-facing surfaces."
    },
    "10": {
        "title": "DPDP §10 — Significant Data Fiduciary (SDF) Obligations",
        "requirement": "Government-notified SDFs must appoint an India-based DPO reporting to the board, appoint an independent data auditor, and conduct periodic DPIAs and audits.",
        "recommended_action": "Legal team must determine SDF notification status based on processing volume, sensitivity, and societal impact. (Non-computable threshold)."
    },
    "11": {
        "title": "DPDP §11 — Right to Access Information",
        "requirement": "Data Principal has the right to obtain a summary of personal data being processed, processing activities, and identities of all Data Fiduciaries/Processors shared with.",
        "recommended_action": "Provide self-service data export / profile summary endpoints."
    },
    "12": {
        "title": "DPDP §12 — Right to Correction and Erasure",
        "requirement": "Data Principal has the right to correction, completion, updating, and erasure of personal data.",
        "recommended_action": "Implement self-service update/edit and deletion capabilities."
    },
    "13": {
        "title": "DPDP §13 — Right to Grievance Redressal",
        "requirement": "Data Principal has the right to readily available grievance redressal provided by the Data Fiduciary.",
        "recommended_action": "Provide accessible grievance submission form/endpoint."
    },
    "14": {
        "title": "DPDP §14 — Right to Nominate",
        "requirement": "Data Principal has the right to nominate an individual to exercise their rights in the event of death or incapacity. (DPDP-only feature with no GDPR direct analog).",
        "recommended_action": "Implement a user nomination feature allowing Data Principals to designate a legal representative."
    },
    "16": {
        "title": "DPDP §16 — Cross-Border Data Transfer",
        "requirement": "Data Fiduciary may transfer personal data outside India, except to countries/territories explicitly restricted by the Central Government via Gazette notification. (Blacklist model).",
        "recommended_action": "Verify third-party service destinations against Central Government restricted list."
    }
}
