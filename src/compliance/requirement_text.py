"""
Static, deterministic compliance requirement text for every GDPR finding type.

Each entry answers the manager's five questions:
  1. WHAT was detected?       -> 'detected_evidence' is populated per-finding in orchestrator.py
  2. WHAT regulation applies? -> 'requirement'
  3. WHY it matters?          -> embedded in 'requirement'
  4. WHAT action is needed?   -> 'recommended_action'
  5. Automatable or human?    -> 'human_review_required'
"""

REQUIREMENTS = {
    "Art. 5(1)(c)": "Personal data should be limited to what is necessary for the stated purpose. Verify whether this field is still required.",
    "Art. 28": "Personal data appears to be transmitted to an external processor. Ensure a valid Data Processing Agreement (DPA) is in place.",
    "Art. 44-49": "Personal data appears to be transmitted to a non-EU processor. Review applicable transfer safeguards (e.g. SCCs) and processor agreement.",
    "Art. 32": "Personal data must be processed in a manner that ensures appropriate security, including protection against unauthorised or unlawful processing. Verify appropriate encryption/access controls.",
    "HR_THIRD_PARTY": "Lawful basis, transparency, and processor-agreement adequacy require legal review.",
    "HR_MESSAGING": "Cannot determine from source code whether this message is service-related or promotional; classification affects applicable consent requirements.",
    "HR_CONSENT": "Verify whether the consent language and user flow are legally adequate for informed consent."
}

# ── Per-rule static definitions ────────────────────────────────────────────────
#
# Keys match rule_id values emitted by orchestrator.py.
# Every entry MUST have: requirement, recommended_action, human_review_required.

FINDING_SPECS = {

    # ── Personal Data Inventory ──────────────────────────────────────────────
    "personal-data-field-detected": {
        "requirement": (
            "GDPR Art. 5(1)(b)-(c) — Purpose limitation and data minimisation.\n"
            "Personal data may only be collected for specified, explicit, and legitimate purposes "
            "and must be limited to what is necessary in relation to those purposes. "
            "Detection of a personal-data field (phone, email, etc.) in source code is an "
            "INVENTORY item — it confirms that the data is present in the system. "
            "It does not, by itself, indicate a violation."
        ),
        "recommended_action": (
            "1. Confirm that a documented lawful basis exists for collecting and processing this field "
            "(e.g. contract performance, legitimate interest, consent). "
            "2. Verify the field is necessary for the declared purpose — if it is never read or used "
            "downstream, consider removal (see also minimisation flags). "
            "3. Ensure the field is described in your Records of Processing Activities (RoPA) under Art. 30."
        ),
        "human_review_required": (
            "YES — legal team must confirm: (a) lawful basis, (b) purpose documented in privacy notice, "
            "(c) field is not redundant given actual processing activities."
        ),
    },

    # ── Minimisation ────────────────────────────────────────────────────────
    "unused-personal-data": {
        "requirement": (
            "GDPR Art. 5(1)(c) — Data minimisation.\n"
            "Personal data must be adequate, relevant, and limited to what is necessary. "
            "A field destructured from a request but never read or passed downstream indicates "
            "possible over-collection."
        ),
        "recommended_action": (
            "1. Remove the unused field from the destructuring / request body if it serves no purpose. "
            "2. If the field is intentionally collected but not yet used (e.g. future feature), "
            "document the purpose in the RoPA and add a comment explaining the retention reason. "
            "3. If collected for analytics/logging, ensure this is covered by the privacy notice."
        ),
        "human_review_required": (
            "PARTIAL — the removal of the field from code is automatable; "
            "confirming whether a legitimate future purpose exists requires legal/product review."
        ),
    },

    # ── Third-Party Transfers ───────────────────────────────────────────────
    "third-party-transfer": {
        "requirement": (
            "GDPR Art. 28 — Processor obligations.\n"
            "Where personal data is transmitted to an external service/processor, the controller "
            "must ensure: (a) a written Data Processing Agreement (DPA) is in place; "
            "(b) the processor provides sufficient guarantees of technical and organisational measures; "
            "(c) the processor processes data only on the controller's instructions.\n"
            "GDPR Art. 44-49 — International transfers.\n"
            "If the processor is located outside the EEA, an adequate transfer mechanism must exist "
            "(e.g. Standard Contractual Clauses, adequacy decision). "
            "International-transfer applicability could not be determined from source code alone."
        ),
        "recommended_action": (
            "1. Verify a signed DPA exists with this processor. "
            "2. Confirm the processor's sub-processor list and data residency. "
            "3. If the processor is outside the EEA, ensure SCCs or another Art. 46 mechanism is in place. "
            "4. Update the privacy notice to disclose this processor and the data shared. "
            "5. Add this processor to your RoPA."
        ),
        "human_review_required": (
            "YES — DPA status, international transfer mechanism, and privacy-notice accuracy "
            "cannot be verified from source code. Legal team must confirm."
        ),
    },

    # ── Storage / Security Controls ─────────────────────────────────────────
    "unprotected-pii-storage": {
        "requirement": (
            "GDPR Art. 32 — Security of processing.\n"
            "The controller must implement appropriate technical and organisational measures to ensure "
            "a level of security appropriate to the risk, including as appropriate: "
            "(a) pseudonymisation and/or encryption of personal data; "
            "(b) the ability to ensure ongoing confidentiality, integrity, availability and resilience; "
            "(c) a process for regularly testing and evaluating effectiveness of measures.\n"
            "Detection of a plain String type in a database schema does not itself constitute a violation — "
            "it is a signal that security controls for this field require explicit verification."
        ),
        "recommended_action": (
            "Verify the following for each flagged field:\n"
            "  • Encryption at rest: Is the database volume or field-level encryption enabled "
            "(e.g. MongoDB Atlas Encryption at Rest, client-side field-level encryption)?\n"
            "  • Transport security: Is all traffic between app and database over TLS?\n"
            "  • Access controls: Are database credentials scoped to least-privilege? "
            "Is network access restricted (VPC, IP allowlist)?\n"
            "  • Retention: Is there a documented retention schedule and automated deletion/anonymisation?\n"
            "  • Backup security: Are backups encrypted and access-controlled?\n"
            "NOTE: Hashing is only appropriate when the field does not need to be retrieved in its "
            "original form (e.g. passwords). For phone/email used for contact, reversible encryption "
            "or infrastructure-level protection is the appropriate control — do NOT hash contact fields."
        ),
        "human_review_required": (
            "YES — encryption-at-rest configuration, access controls, and retention schedules "
            "exist outside source code and must be verified against infrastructure and policy documentation. "
            "A technical security review or pen test may be required per Art. 32(1)(d)."
        ),
    },

    # ── Consent UI ──────────────────────────────────────────────────────────
    "consent-checkbox-default": {
        "requirement": (
            "GDPR Art. 7 — Conditions for consent.\n"
            "Where consent is the lawful basis, it must be: freely given, specific, informed, and "
            "unambiguous. Pre-ticked boxes (defaultChecked=true) do not constitute valid consent "
            "under GDPR Recital 32. The checkbox may be for a non-consent purpose (e.g. opt-in to "
            "a service feature) — the legal classification depends on context."
        ),
        "recommended_action": (
            "1. Determine whether this checkbox is being used for a consent-based processing activity. "
            "2. If yes: remove the defaultChecked attribute so the box starts unchecked. "
            "   Ensure the associated label clearly describes what the user is consenting to. "
            "3. If no (e.g. it is a service configuration toggle): document that consent is not the "
            "   applicable basis and this finding can be suppressed with a justification comment."
        ),
        "human_review_required": (
            "YES — whether this checkbox controls a consent-based processing activity, "
            "and whether the surrounding UI language constitutes valid informed consent, "
            "requires legal and UX review."
        ),
    },

    # ── Consent HR ──────────────────────────────────────────────────────────
    "human-review-consent": {
        "requirement": (
            "GDPR Art. 7 — Conditions for consent; Art. 7(3) — Right to withdraw consent.\n"
            "Consent must be freely given, specific, informed, and unambiguous (no pre-ticked boxes). "
            "Users must be able to withdraw consent as easily as they gave it."
        ),
        "recommended_action": (
            "1. Review the consent UI copy: is it specific about what the user is agreeing to? "
            "2. Is there a clear withdrawal mechanism (unsubscribe link, settings toggle)? "
            "3. Are consent records logged with timestamps for audit purposes? "
            "4. Is consent collected separately from terms of service acceptance?"
        ),
        "human_review_required": (
            "YES — legal team must assess whether consent language meets Art. 7 requirements "
            "and whether withdrawal is technically and practically achievable."
        ),
    },

    # ── Third-Party Legal Basis HR ──────────────────────────────────────────
    "human-review-processor": {
        "requirement": (
            "GDPR Art. 28 — Processor obligations; Art. 5(1)(a) — Lawful basis; "
            "Art. 12-14 — Transparency obligations.\n"
            "The controller must document and disclose all processors to data subjects and "
            "ensure each processor provides adequate data-protection guarantees."
        ),
        "recommended_action": (
            "1. Confirm a signed DPA exists with this processor. "
            "2. Confirm the processor is listed in your privacy notice. "
            "3. Confirm the processor is listed in your RoPA (Art. 30). "
            "4. If the processor has changed sub-processors or data locations, "
            "   reassess transfer safeguards."
        ),
        "human_review_required": (
            "YES — DPA existence and content, privacy-notice accuracy, and transfer "
            "mechanism adequacy are legal matters that cannot be determined from code."
        ),
    },

    # ── Messaging Purpose HR ────────────────────────────────────────────────
    "human-review-messaging": {
        "requirement": (
            "GDPR Art. 6 — Lawful basis for processing; Art. 7 — Consent (if applicable).\n"
            "The lawful basis for sending a message depends on its purpose:\n"
            "  • Transactional / service messages (e.g. order confirmations, OTPs): "
            "    typically lawful under contract performance (Art. 6(1)(b)) or legitimate interest.\n"
            "  • Marketing / promotional messages: typically require explicit opt-in consent "
            "    (Art. 6(1)(a)) and are subject to ePrivacy / local marketing regulations.\n"
            "Source code alone cannot determine which applies."
        ),
        "recommended_action": (
            "1. Classify every message type sent via this service as transactional or promotional. "
            "2. For promotional messages: ensure recipients have actively opted in and "
            "   a withdrawal mechanism (unsubscribe) is provided. "
            "3. For transactional messages: document the contractual or legitimate-interest basis. "
            "4. Ensure the messaging provider is listed as a processor in your privacy notice and RoPA."
        ),
        "human_review_required": (
            "YES — message purpose classification and applicable lawful basis must be "
            "determined by legal/product team. Cannot be derived from code analysis."
        ),
    },
}


# ── Convenience accessor ───────────────────────────────────────────────────────

def get_finding_spec(rule_id: str) -> dict:
    """Return the requirement spec for a given rule_id, or a safe default."""
    return FINDING_SPECS.get(rule_id, {
        "requirement": "See applicable GDPR article(s) for this finding type.",
        "recommended_action": "Review the detected code pattern and assess compliance impact.",
        "human_review_required": "PARTIAL — automated detection; human review of context required.",
    })
