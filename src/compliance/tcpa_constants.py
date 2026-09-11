"""
Centralized metadata and constants for US TCPA (Telephone Consumer Protection Act) Technical Readiness.
Reference: 47 U.S.C. § 227 and 47 C.F.R. § 64.1200 (FCC Regulations).
"""

FRAMEWORK_TCPA = "TCPA"
TCPA_EFFECTIVE_STATUS = "IN_FORCE"
TCPA_EFFECTIVE_FROM = "1991-12-20"

# Communication Channels
TCPA_CHANNELS = {
    "SMS": "SMS",
    "VOICE_CALL": "VOICE_CALL",
    "EMAIL": "EMAIL",
    "UNKNOWN": "UNKNOWN"
}

# Purpose Signals
TCPA_PURPOSES = {
    "TRANSACTIONAL": "TRANSACTIONAL",
    "MARKETING": "MARKETING",
    "MIXED": "MIXED",
    "UNKNOWN": "UNKNOWN"
}

TCPA_REQUIREMENTS = {
    "TCPA-227-B-1-A-CALLS-CONSENT": {
        "rule": "47 U.S.C. § 227(b)(1)(A) / 47 C.F.R. § 64.1200(a)(1)-(2)",
        "title": "TCPA § 227(b)(1)(A) — Prior Express / Written Consent",
        "requirement": "Unlawful to make calls or send SMS messages using an automatic telephone dialing system (ATDS) or artificial/prerecorded voice to wireless telephone numbers without prior express consent (or prior express written consent for telemarketing/advertising).",
        "recommended_action": "Implement clear consent capture mechanisms (opt-in UI checkboxes, written consent forms) before initiating automated calls or SMS messages."
    },
    "TCPA-227-B-1-B-PRERECORDED-VOICE": {
        "rule": "47 U.S.C. § 227(b)(1)(B) / 47 C.F.R. § 64.1200(a)(3)",
        "title": "TCPA § 227(b)(1)(B) — Prerecorded / Artificial Voice Controls",
        "requirement": "Unlawful to initiate telephone calls to residential lines using artificial or prerecorded voice without prior express consent unless statutory exemptions apply.",
        "recommended_action": "Verify express consent before dispatching artificial or prerecorded voice calls and implement clear prompt identification at call start."
    },
    "TCPA-227-C-DO-NOT-CALL": {
        "rule": "47 U.S.C. § 227(c) / 47 C.F.R. § 64.1200(c)-(d)",
        "title": "TCPA § 227(c) — Do-Not-Call (DNC) Registry & Internal DNC Policy",
        "requirement": "Entities initiating telephone solicitations must maintain a written policy for honoring do-not-call requests, maintain an internal DNC list, and consult the National Do Not Call Registry.",
        "recommended_action": "Maintain an internal suppression / DNC database table or service integration and scrub target lists against DNC registries prior to solicitations."
    },
    "TCPA-64-1200-SMS-OPT-OUT": {
        "rule": "47 C.F.R. § 64.1200(a)(9) / FCC Opt-Out Mandates",
        "title": "47 C.F.R. § 64.1200 — SMS Opt-Out & Keywords Handling (STOP)",
        "requirement": "SMS sender must provide recipients a simple, standard mechanism to opt out (e.g., replying STOP, UNSUBSCRIBE, CANCEL, QUIT, HELP) and promptly honor opt-out requests.",
        "recommended_action": "Implement automated keyword processing (STOP, UNSUBSCRIBE) and webhooks to update contact suppression lists immediately."
    },
    "TCPA-64-1200-IDENTIFICATION": {
        "rule": "47 C.F.R. § 64.1200(b)",
        "title": "47 C.F.R. § 64.1200(b) — Identification & Disclosure Requirements",
        "requirement": "All artificial/prerecorded voice calls and promotional text messages must state clearly at the beginning the identity of the business, individual, or entity initiating the call/message.",
        "recommended_action": "Ensure outbound message templates and voice scripts include sender identity and contact details."
    },
    "TCPA-AUTODIALER-ATDS-MONITOR": {
        "rule": "47 U.S.C. § 227(a)(1) / (b)(1)",
        "title": "TCPA § 227(a)(1) — Autodialer / Automated Dispatch Control",
        "requirement": "Equipment with capacity to store or produce telephone numbers using a random or sequential number generator and dial them (ATDS) is subject to strict prior express consent rules.",
        "recommended_action": "Maintain human intervention controls, queue reviews, or consent-linked dispatch workflows for automated batch messaging."
    },
    "TCPA-SUPPRESSION-LIST": {
        "rule": "47 C.F.R. § 64.1200(d)(3)",
        "title": "47 C.F.R. § 64.1200(d) — Internal Contact Suppression & Exclusion Lists",
        "requirement": "Entities making calls/SMS must record opt-out requests and place the subscriber's name and telephone number on the suppression list within a reasonable time frame.",
        "recommended_action": "Implement strict suppression database checks in the outbound dispatch path prior to API execution."
    }
}
