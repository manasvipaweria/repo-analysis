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

# Statutory Requirements Mapping Table with Verified Authoritative References
TRAI_DLT_REQUIREMENTS = {
    "TRAI-TCCCPR-REG-PE-ID": {
        "rule": "TCCCPR 2018 Reg 3(1) & CoP-PE Guidelines",
        "title": "TCCCPR 2018 — Principal Entity (PE) DLT Registration Evidence",
        "authoritative_reference": "TRAI TCCCPR 2018, Regulation 3(1) & Regulation 8(1) (Code of Practice for Principal Entity Registration - CoP-PE)",
        "classification": "STATUTORY_REQUIREMENT_EXTERNAL_ATTESTATION",
        "requirement": "Any enterprise initiating commercial or service communications must register as a Principal Entity (PE) on an authorized Access Provider DLT portal and obtain a unique 19-digit PE ID under TCCCPR 2018 Reg 3(1). Presence of a PE ID parameter in code serves as technical readiness evidence; active DLT portal registration is an external fact requiring organizational attestation.",
        "recommended_action": "Verify Principal Entity registration on an authorized Access Provider DLT portal (e.g., Jio, Airtel, VI, BSNL DLT) and configure 19-digit PE ID parameters in messaging dispatch settings."
    },
    "TRAI-TCCCPR-REG-HEADER-ID": {
        "rule": "TCCCPR 2018 Reg 8(1)-(3) & CoP-Header Guidelines",
        "title": "TCCCPR 2018 — Sender Header / Header ID DLT Binding Evidence",
        "authoritative_reference": "TRAI TCCCPR 2018, Regulation 8(1), 8(2) & 8(3) (Code of Practice for Header Registration - CoP-Header)",
        "classification": "STATUTORY_REQUIREMENT_EXTERNAL_ATTESTATION",
        "requirement": "All messaging headers (6-character alphanumeric for Service/Transactional or 6-digit numeric for Promotional) must be registered on the DLT ledger and bound to the verified Principal Entity under TCCCPR 2018 Reg 8. Parameter detection in code proves technical evidence of header configuration; live DLT header approval requires human review.",
        "recommended_action": "Ensure outbound messaging headers are explicitly specified in application payload dispatches and registered under the verified PE ID in the Access Provider DLT portal."
    },
    "TRAI-TCCCPR-REG-TEMPLATE-ID": {
        "rule": "TCCCPR 2018 Reg 9(1)-(2) & CoP-CT Guidelines",
        "title": "TCCCPR 2018 — Content Template ID DLT Registration Evidence",
        "authoritative_reference": "TRAI TCCCPR 2018, Regulation 9(1) & Regulation 9(2) (Code of Practice for Content Template - CoP-CT)",
        "classification": "STATUTORY_REQUIREMENT_TECHNICAL_INDICATOR",
        "requirement": "Every SMS message structure (content template) must be pre-registered and approved on the DLT platform with fixed headers and dynamic variables ({#var#}), passing the registered Content Template ID during provider API calls under TCCCPR 2018 Reg 9.",
        "recommended_action": "Configure DLT Content Template ID parameters alongside outbound SMS payload dispatches matching registered template structures."
    },
    "TRAI-TCCCPR-CONSENT-TELECOM-SCRUB": {
        "rule": "TCCCPR 2018 Reg 10(1) & Reg 12(1)-(2) & CoP-Consent",
        "title": "TCCCPR 2018 — Customer Consent Acquisition & DLT Consent Ledger Attestation",
        "authoritative_reference": "TRAI TCCCPR 2018, Regulation 10(1) & Regulation 12(1)-(2) (Code of Practice for Consent - CoP-Consent)",
        "classification": "STATUTORY_REQUIREMENT_EXTERNAL_ATTESTATION",
        "requirement": "Commercial communications require customer consent acquired via registered consent templates and recorded on the Access Provider DLT Consent Ledger under TCCCPR 2018 Reg 10 & 12. Repository code UI elements demonstrate technical consent handling evidence, but legal validity of consent and actual DLT consent ledger scrubbing require organizational attestation.",
        "recommended_action": "Maintain explicit opt-in UI consent capture evidence and provide organizational attestation confirming DLT consent ledger registration with telecom Access Providers."
    },
    "TRAI-TCCCPR-PROMOTIONAL-TIMING": {
        "rule": "TCCCPR 2018 Reg 14(1) & Schedule II, Clause 2(b)",
        "title": "TCCCPR 2018 — Promotional Communication Time Restrictions (09:00 to 21:00)",
        "authoritative_reference": "TRAI TCCCPR 2018, Regulation 14(1) read with Schedule II, Clause 2(b) & TRAI Direction dated Jan 20, 2020",
        "classification": "STATUTORY_REQUIREMENT_OPERATIONAL_CHECK",
        "requirement": "Promotional / commercial communications to consumers are strictly prohibited outside the statutory window of 09:00 hrs to 21:00 hrs (9:00 AM to 9:00 PM local time) under TCCCPR 2018 Reg 14(1) & Schedule II. Code check evaluates technical time-window scheduling guards on message queues.",
        "recommended_action": "Enforce time-window scheduling guards on marketing and promotional message dispatch queues to ensure delivery solely between 09:00 AM and 09:00 PM."
    },
    "TRAI-TCCCPR-PREFERENCE-DND": {
        "rule": "TCCCPR 2018 Reg 4(1) & Reg 11(1)-(3) & CoP-Preference",
        "title": "TCCCPR 2018 — National Customer Preference Register (NCPR / DND) Scrubbing Evidence",
        "authoritative_reference": "TRAI TCCCPR 2018, Regulation 4(1) & Regulation 11(1)-(3) (Code of Practice for Preference Management - CoP-Preference)",
        "classification": "STATUTORY_REQUIREMENT_EXTERNAL_ATTESTATION",
        "requirement": "Promotional communications must be scrubbed against customer preferences (Categories 1 to 7 / DND) on the NCPR/DLT preference ledger prior to delivery under TCCCPR 2018 Reg 4 & 11. Technical evidence verifies pre-dispatch suppression checks; actual telecom carrier preference scrubbing requires external attestation.",
        "recommended_action": "Verify Access Provider DLT carrier preference scrubbing or implement pre-dispatch DND registry suppression checks."
    }
}
