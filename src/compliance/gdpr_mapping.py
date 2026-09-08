from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class GDPRRequirement:
    article: str
    description: str
    automation_level: str
    existing_rules: List[str]  # e.g., ["eslint-plugin-deslint/no-default-checked", "semgrep/secure-cookie"]
    new_deterministic_checks: List[str]
    evidence_types: List[str]
    ai_usefulness: str
    manual_verification: str

# GDPR Mapping Definitions
GDPR_MAPPINGS: List[GDPRRequirement] = [
    GDPRRequirement(
        article="Art. 5(1)(c)",
        description="Data Minimisation",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["personal-data-field-detected"],
        evidence_types=["DTOs", "DB schemas", "Form inputs"],
        ai_usefulness="Trace PII flow from frontend to DB to flag excessive collection",
        manual_verification="Legal justification of necessity for the collected data."
    ),
    GDPRRequirement(
        article="Art. 5(1)(e)",
        description="Storage Limitation",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["ttl-configuration-missing"],
        evidence_types=["TTL indexes", "Cron jobs"],
        ai_usefulness="Trace custom cleanup scripts missed by strict regex.",
        manual_verification="Enforcing legal data retention schedules."
    ),
    GDPRRequirement(
        article="Art. 7",
        description="Consent",
        automation_level="Partially automated",
        existing_rules=["deslint/no-default-checked"],
        new_deterministic_checks=["consent-checkbox-default"],
        evidence_types=["Checkboxes", "API payloads"],
        ai_usefulness="Analyze UI copy for bundled vs. granular consent text.",
        manual_verification="Validity and clarity of the consent language."
    ),
    GDPRRequirement(
        article="Art. 7(3)",
        description="Withdrawal of Consent",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["missing-revoke-endpoint"],
        evidence_types=["Unsubscribe links", "API /revoke routes"],
        ai_usefulness="Trace whether withdrawal halts downstream processing.",
        manual_verification="None"
    ),
    GDPRRequirement(
        article="Art. 12-14",
        description="Transparency",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["missing-privacy-link"],
        evidence_types=["Links to /privacy"],
        ai_usefulness="Verify privacy policy link is universally accessible.",
        manual_verification="Legal drafting and accuracy of the privacy policy."
    ),
    GDPRRequirement(
        article="Art. 15",
        description="Right of Access",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["missing-export-endpoint"],
        evidence_types=["Endpoints fetching full user profile"],
        ai_usefulness="Check if endpoint aggregates all relational PII.",
        manual_verification="None"
    ),
    GDPRRequirement(
        article="Art. 16",
        description="Right to Rectification",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["missing-rectification-endpoint"],
        evidence_types=["PUT/PATCH endpoints linked to User IDs"],
        ai_usefulness="None",
        manual_verification="None"
    ),
    GDPRRequirement(
        article="Art. 17",
        description="Right to Erasure",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["missing-cascade-delete", "missing-delete-endpoint"],
        evidence_types=["DELETE /user routes", "onDelete: CASCADE", "Anonymization scripts"],
        ai_usefulness="Trace if deletion triggers cleanup in all logged systems.",
        manual_verification="Ensuring offline backups and logs are scrubbed."
    ),
    GDPRRequirement(
        article="Art. 20",
        description="Data Portability",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["missing-portability-export"],
        evidence_types=["Endpoints returning JSON/CSV of user data"],
        ai_usefulness="Verify exported payload matches stored PII schema.",
        manual_verification="None"
    ),
    GDPRRequirement(
        article="Art. 25",
        description="Privacy by Design / Default",
        automation_level="Partially automated",
        existing_rules=["semgrep/raw-pii-logging", "semgrep/insecure-defaults"],
        new_deterministic_checks=["raw-pii-logging"],
        evidence_types=["Logger masks", "Default boolean states"],
        ai_usefulness="Infer whether database defaults favor privacy.",
        manual_verification="Organisational policies on privacy integration."
    ),
    GDPRRequirement(
        article="Art. 28",
        description="Processors (Third-Parties)",
        automation_level="Partially automated",
        existing_rules=["dependency-cruiser"],
        new_deterministic_checks=["outbound-domain-extraction"],
        evidence_types=["package.json", "3rd party SDKs", "Outbound HTTP domains"],
        ai_usefulness="Classify external domains to see if PII is transmitted.",
        manual_verification="Signing Data Processing Agreements (DPAs) with vendors."
    ),
    GDPRRequirement(
        article="Art. 30",
        description="Records of Processing (RoPA)",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["ropa-draft-generation"],
        evidence_types=["OpenAPI specs", "Prisma schemas", "Data Flow Extraction"],
        ai_usefulness="Summarize data flow and auto-generate draft RoPA document.",
        manual_verification="DPO maintenance, legal review, and official approval of RoPA."
    ),
    GDPRRequirement(
        article="Art. 32",
        description="Security of Processing",
        automation_level="Partially automated",
        existing_rules=["bandit/*", "snyk/*", "semgrep/*", "pip-audit/*", "dep-scan/*", "codex-security/*"],
        new_deterministic_checks=[],
        evidence_types=["TLS settings", "Hashing", "Secure cookies", "Dependencies"],
        ai_usefulness="Context-aware risk assessment of security gaps.",
        manual_verification="Pen-testing, IAM policies, and organizational security audits."
    ),
    GDPRRequirement(
        article="Art. 33-34",
        description="Breach Notification",
        automation_level="Partially automated",
        existing_rules=["codex-architecture/missing-logging"],
        new_deterministic_checks=[],
        evidence_types=["Centralized logging", "Unhandled exception catches"],
        ai_usefulness="Verify authentication failures are persistently logged.",
        manual_verification="Legal/procedural obligation to notify DPAs/Users within 72 hours."
    ),
    GDPRRequirement(
        article="Art. 35",
        description="Data Protection Impact Assessment (DPIA)",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["high-risk-sdk-detection"],
        evidence_types=["Indicators of high-risk processing (AI/ML, biometrics)"],
        ai_usefulness="Flag potential DPIA triggers and high-risk processing indicators based on detected data flows and processing activities.",
        manual_verification="Legal determination to conduct the DPIA and execution process."
    ),
    GDPRRequirement(
        article="Art. 37-39",
        description="Data Protection Officer",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["privacy-contact-detection"],
        evidence_types=["Mentions of privacy contact emails (dpo@, privacy@)"],
        ai_usefulness="None",
        manual_verification="Appointing the DPO and ensuring their legal independence."
    ),
    GDPRRequirement(
        article="Art. 44-49",
        description="Cross-Border Transfers",
        automation_level="Partially automated",
        existing_rules=[],
        new_deterministic_checks=["non-eu-region-detection"],
        evidence_types=["Terraform AWS regions", "3rd party SDK endpoints"],
        ai_usefulness="Cross-reference 3rd party SDKs with known non-EU processors.",
        manual_verification="Executing Standard Contractual Clauses (SCCs)."
    )
]

def get_gdpr_articles_for_rule(rule_id: str) -> List[str]:
    """Map an existing rule_id to its relevant GDPR Articles."""
    articles = []
    for mapping in GDPR_MAPPINGS:
        if rule_id in mapping.new_deterministic_checks:
            articles.append(mapping.article)
            continue
        
        # Check existing rules with wildcard support
        for existing in mapping.existing_rules:
            if existing.endswith("*") and rule_id.startswith(existing[:-1]):
                articles.append(mapping.article)
            elif existing == rule_id:
                articles.append(mapping.article)
                
    return list(set(articles))
