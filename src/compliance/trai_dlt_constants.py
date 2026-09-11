"""
Centralized metadata and constants for India TRAI / TCCCPR 2018 / DLT Technical Readiness.
Reference: Telecom Commercial Communications Customer Preference Regulations, 2018 (TCCCPR 2018)
and DLT (Distributed Ledger Technology) Blockchain Ecosystem Mandates.
"""

FRAMEWORK_TRAI_DLT = "TRAI_DLT"
TRAI_EFFECTIVE_STATUS = "IN_FORCE"
TRAI_EFFECTIVE_FROM = "2018-07-19"

# Statutory TRAI / DLT Communication Categories
TRAI_COMMUNICATION_TYPES = {
    "SERVICE_TRANSACTIONAL": "SERVICE_TRANSACTIONAL",
    "PROMOTIONAL_COMMERCIAL": "PROMOTIONAL_COMMERCIAL",
    "UNKNOWN": "UNKNOWN"
}

# Statutory Requirements Mapping Table
TRAI_DLT_REQUIREMENTS = {
    "TRAI-TCCCPR-REG-PE-ID": {
        "rule": "TCCCPR 2018 Reg 3 & DLT Entity Mandate",
        "title": "TCCCPR 2018 — Principal Entity (PE) Registration on DLT Platform",
        "requirement": "Any enterprise sending commercial, service, or transactional SMS/voice calls to Indian phone numbers must register as a Principal Entity (PE) with a licensed Access Provider's DLT platform and obtain a unique 19-digit PE ID.",
        "recommended_action": "Verify Principal Entity registration on an authorized DLT portal (e.g. Jio, Airtel, VI, BSNL DLT) and configure entity parameters in application credentials or environment settings."
    },
    "TRAI-TCCCPR-REG-HEADER-ID": {
        "rule": "TCCCPR 2018 Reg 8 & Header Registration Guidelines",
        "title": "TCCCPR 2018 — Header / Sender ID Registration & Binding",
        "requirement": "All SMS headers (6-character alphanumeric headers for Service/Transactional or 6-digit numeric headers for Promotional) must be registered on the DLT portal and bound to the verified Principal Entity.",
        "recommended_action": "Ensure outbound messaging headers are explicitly specified and registered in the DLT portal for the intended communication type."
    },
    "TRAI-TCCCPR-REG-TEMPLATE-ID": {
        "rule": "TCCCPR 2018 Reg 9 & Content Template Registration",
        "title": "TCCCPR 2018 — Content & Consent Template Registration on DLT",
        "requirement": "Every SMS message structure (content template) must be pre-registered and approved on the DLT platform with fixed headers, dynamic variables ({#var#}), and registered Template IDs passed during provider API calls.",
        "recommended_action": "Configure DLT template IDs alongside outbound SMS payload dispatches and link templates with verified headers."
    },
    "TRAI-TCCCPR-CONSENT-TELECOM-SCRUB": {
        "rule": "TCCCPR 2018 Reg 10-12 & Consent Ledger Scrubbing",
        "title": "TCCCPR 2018 — Customer Consent Template & DLT Consent Scrubbing",
        "requirement": "Commercial communications require customer consent recorded on the DLT consent ledger or verified explicit opt-in prior to dispatch.",
        "recommended_action": "Maintain explicit opt-in UI evidence and ensure provider-level consent scrubbing is active on the DLT network."
    },
    "TRAI-TCCCPR-PROMOTIONAL-TIMING": {
        "rule": "TCCCPR 2018 Schedule II & Time Restrictions",
        "title": "TCCCPR 2018 — Promotional Communication Time Restrictions (09:00 to 21:00)",
        "requirement": "Promotional / commercial communications to consumers are strictly prohibited outside the statutory window of 09:00 AM to 09:00 PM local time.",
        "recommended_action": "Enforce time-window scheduling guards on marketing and promotional message dispatch queues."
    },
    "TRAI-TCCCPR-PREFERENCE-DND": {
        "rule": "TCCCPR 2018 Reg 4 & NCPR / DND Scrubbing",
        "title": "TCCCPR 2018 — National Customer Preference Register (NCPR / DND) Compliance",
        "requirement": "Promotional messages must be scrubbed against the National Customer Preference Register (NCPR/DND) preferences (Category 1 to 7) prior to delivery.",
        "recommended_action": "Verify DLT telecom carrier preference scrubbing or implement pre-dispatch DND registry checks."
    }
}
