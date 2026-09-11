"""
Centralized metadata and constants for India IT (SPDI Rules, 2011) Technical Readiness.
Reference: Information Technology (Reasonable Security Practices and Procedures and
Sensitive Personal Data or Information) Rules, 2011 under Section 43A of IT Act, 2000.
"""

FRAMEWORK_SPDI = "SPDI"
SPDI_EFFECTIVE_STATUS = "IN_FORCE"
SPDI_EFFECTIVE_FROM = "2011-04-11"

# Rule 3 Sensitive Personal Data Categories
SPDI_CATEGORIES = {
    "PASSWORDS": "passwords",
    "FINANCIAL_INFO": "financial_information",
    "HEALTH_CONDITION": "physical_physiological_mental_health",
    "SEXUAL_ORIENTATION": "sexual_orientation",
    "MEDICAL_RECORDS": "medical_records_history",
    "BIOMETRIC_INFO": "biometric_information",
    "RELATED_INFO": "related_information_for_above"
}

SPDI_REQUIREMENTS = {
    "SPDI-RULE-3-SENSITIVE-TAXONOMY": {
        "rule": "Rule 3",
        "title": "SPDI Rule 3 — Sensitive Personal Data Identification",
        "requirement": "Sensitive Personal Data or Information (SPDI) consists of passwords, financial information, health conditions, sexual orientation, medical records, and biometric data.",
        "recommended_action": "Ensure SPDI-sensitive fields are isolated, encrypted in transit and at rest, and subjected to enhanced consent and access controls."
    },
    "SPDI-RULE-3-ORDINARY-PII": {
        "rule": "Rule 3",
        "title": "SPDI Rule 3 — Ordinary Personal Data Classification",
        "requirement": "Ordinary personal data (phone numbers, email addresses, names, IP addresses) is not automatically classified as SPDI Sensitive Personal Data under Rule 3.",
        "recommended_action": "Maintain standard data protection and privacy notices for ordinary PII fields."
    },
    "SPDI-RULE-3-PUBLIC-DOMAIN": {
        "rule": "Rule 3 Exemption",
        "title": "SPDI Rule 3 — Public Domain Exemption",
        "requirement": "Information freely available or accessible in the public domain or furnished under the Right to Information Act, 2005 or any other law is not treated as SPDI.",
        "recommended_action": "Verify public domain status or statutory obligation for disclosed datasets."
    },
    "SPDI-RULE-4-PRIVACY-POLICY": {
        "rule": "Rule 4",
        "title": "SPDI Rule 4 — Privacy Policy Publication",
        "requirement": "Body corporate must provide a privacy policy for handling of or dealing in personal information including SPDI, published on website.",
        "recommended_action": "Publish a clear, accessible privacy policy covering collection, purpose, disclosure, security practices, and grievance officer details."
    },
    "SPDI-RULE-5-1-CONSENT": {
        "rule": "Rule 5(1)",
        "title": "SPDI Rule 5(1) — Prior Consent for SPDI Collection",
        "requirement": "Body corporate or any person on its behalf must obtain consent in writing or through letter or email or electronic means before collection of SPDI.",
        "recommended_action": "Implement explicit opt-in consent mechanisms before collecting sensitive personal data."
    },
    "SPDI-RULE-5-2-PURPOSE-DECLARATION": {
        "rule": "Rule 5(2)",
        "title": "SPDI Rule 5(2) — Lawful and Necessary Purpose",
        "requirement": "Body corporate shall not collect SPDI unless the information is collected for a lawful purpose connected with a function or activity of the body corporate and collection is necessary.",
        "recommended_action": "Document and declare lawful business necessity for each collected SPDI field."
    },
    "SPDI-RULE-5-3-COLLECTION-NOTICE": {
        "rule": "Rule 5(3)",
        "title": "SPDI Rule 5(3) — Pre-Collection Notice",
        "requirement": "While collecting information directly from data principal, body corporate shall take reasonable steps to ensure principal is aware that data is collected, purpose, intended recipients, and agency collecting/retaining data.",
        "recommended_action": "Provide clear privacy notice at point of collection detailing purpose and recipient entities."
    },
    "SPDI-RULE-5-4-RETENTION-LIMIT": {
        "rule": "Rule 5(4)",
        "title": "SPDI Rule 5(4) — Retention Limitation",
        "requirement": "Body corporate holding SPDI shall not retain information for longer than is required for the purposes for which the information may lawfully be used.",
        "recommended_action": "Configure TTL indexes, automated cleanup jobs, or storage lifecycle policies to purge data when purpose expires."
    },
    "SPDI-RULE-5-5-PURPOSE-RESTRICTION": {
        "rule": "Rule 5(5)",
        "title": "SPDI Rule 5(5) — Purpose Restriction",
        "requirement": "Information collected shall be used only for the purpose for which it has been collected.",
        "recommended_action": "Enforce strict scoping to prevent secondary use of SPDI beyond declared purposes."
    },
    "SPDI-RULE-5-6-REVIEW-CORRECTION": {
        "rule": "Rule 5(6)",
        "title": "SPDI Rule 5(6) — Review and Correction Right",
        "requirement": "Body corporate shall permit providers of information to review the information they had provided and ensure any inaccurate/deficient SPDI is corrected.",
        "recommended_action": "Expose user account profile edit features or self-service correction APIs."
    },
    "SPDI-RULE-5-7-OPT-OUT-WITHDRAWAL": {
        "rule": "Rule 5(7)",
        "title": "SPDI Rule 5(7) — Opt-Out and Consent Withdrawal",
        "requirement": "Body corporate shall provide option not to provide SPDI and right to withdraw consent at any time in writing.",
        "recommended_action": "Provide consent withdrawal settings and opt-out options in privacy settings."
    },
    "SPDI-RULE-5-8-SECURITY-PRACTICES": {
        "rule": "Rule 5(8)",
        "title": "SPDI Rule 5(8) — Secure Storage and Handling",
        "requirement": "Body corporate shall keep SPDI secure against unauthorized access or disclosure.",
        "recommended_action": "Implement encryption, strict access controls, and managerial security procedures."
    },
    "SPDI-RULE-5-9-GRIEVANCE-OFFICER": {
        "rule": "Rule 5(9)",
        "title": "SPDI Rule 5(9) — Grievance Officer Designation",
        "requirement": "Body corporate shall address any grievances of provider of information expeditiously. Grievance officer name and contact details must be published on website.",
        "recommended_action": "Designate a Grievance Officer and publish name, email, and contact mechanism on website/SECURITY.md."
    },
    "SPDI-RULE-6-THIRD-PARTY-DISCLOSURE": {
        "rule": "Rule 6",
        "title": "SPDI Rule 6 — Third-Party Disclosure Constraints",
        "requirement": "Disclosure of SPDI to any third party requires prior permission from provider of information unless agreed in contract or required by law.",
        "recommended_action": "Verify third-party processor agreements, explicit disclosure consent, and recipient security standards."
    },
    "SPDI-RULE-7-CROSS-BORDER-TRANSFER": {
        "rule": "Rule 7",
        "title": "SPDI Rule 7 — Cross-Border and Data Transfer Controls",
        "requirement": "Body corporate may transfer SPDI to any other body corporate or person in India, or outside India, only if recipient ensures same level of data protection as provided under SPDI Rules.",
        "recommended_action": "Execute data transfer agreements enforcing equivalent security standards for cross-border processors."
    },
    "SPDI-RULE-7-RETENTION-DELETION": {
        "rule": "Rule 7 / Rule 5(4)",
        "title": "SPDI Rule 7 & Rule 5(4) — Retention & Purge Controls",
        "requirement": "SPDI shall not be retained longer than required for lawful purpose. Automated cleanup or deletion procedures must be maintained.",
        "recommended_action": "Configure TTL indexes, automated deletion jobs, or lifecycle policies."
    },
    "SPDI-RULE-8-REASONABLE-SECURITY": {
        "rule": "Rule 8",
        "title": "SPDI Rule 8 — Reasonable Security Practices and Procedures (ISO 27001 / ISMS)",
        "requirement": "Body corporate shall implement reasonable security practices including a documented information security programme and policies. ISO/IEC 27001 or equivalent code of practice certified by independent auditor complies with Rule 8.",
        "recommended_action": "Maintain documented ISMS policies, managerial & technical security controls, and periodic security audits."
    }
}
