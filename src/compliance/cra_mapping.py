"""
EU Cyber Resilience Act (CRA - Regulation 2024/2847) Requirement Mapping Layer.
Centralizes technical rule/tool -> CRA requirement IDs mapping.
"""
from typing import List, Dict, Optional

# CRA Requirement Metadata
CRA_REQUIREMENTS: Dict[str, Dict[str, str]] = {
    "CRA-I-1": {
        "title": "CRA Annex I, Part I (1) — Secure Development & Architecture",
        "requirement": "Products with digital elements must be designed, developed, and produced in such a way as to ensure an appropriate level of cybersecurity based on the risks.",
        "recommended_action": "Incorporate threat modeling and secure architecture principles into design reviews."
    },
    "CRA-I-2": {
        "title": "CRA Annex I, Part I (2) — Exploitable Vulnerabilities at Release",
        "requirement": "Products must be delivered without any known exploitable vulnerabilities.",
        "recommended_action": "Remediate all high/critical known vulnerabilities in direct and transitive dependencies prior to release."
    },
    "CRA-I-3a": {
        "title": "CRA Annex I, Part I (3a) — Secure Default Configuration",
        "requirement": "Products must ship with a secure default configuration and provide the ability to reset to a secure state.",
        "recommended_action": "Remove hardcoded default credentials/passwords and disable development/debug modes in production configurations."
    },
    "CRA-I-3b": {
        "title": "CRA Annex I, Part I (3b) — Data Confidentiality & Protection",
        "requirement": "Products must protect the confidentiality of stored, transmitted, or processed data by state-of-the-art encryption or protection mechanisms.",
        "recommended_action": "Enforce TLS for data in transit and strong encryption at rest for sensitive data stores."
    },
    "CRA-I-3c": {
        "title": "CRA Annex I, Part I (3c) — Integrity of Data, Commands & Programs",
        "requirement": "Products must protect the integrity of data, commands, code, and configuration against unauthorized modification.",
        "recommended_action": "Enforce signature verification and cryptographic checksums on update paths and sensitive payloads."
    },
    "CRA-I-3d": {
        "title": "CRA Annex I, Part I (3d) — Data Minimization",
        "requirement": "Products must process only data that is adequate, relevant, and limited to what is necessary in relation to the intended purpose.",
        "recommended_action": "Review personal data inventory and eliminate unused fields or excessive collection."
    },
    "CRA-I-3e": {
        "title": "CRA Annex I, Part I (3e) — Availability & DoS Resilience",
        "requirement": "Products must protect the availability of essential functions, including resilience against denial of service (DoS) attacks.",
        "recommended_action": "Conduct DoS resilience testing and document availability SLAs (Organizational attestation required)."
    },
    "CRA-I-3f": {
        "title": "CRA Annex I, Part I (3f) — Blast Radius Minimization & Containment",
        "requirement": "Products must minimize the negative impact of potential exploitation by applying principle of least privilege, sandboxing, and containment.",
        "recommended_action": "Enforce strict IAM boundaries, container sandboxing, and microservice isolation."
    },
    "CRA-I-3g": {
        "title": "CRA Annex I, Part I (3g) — Security Event Logging",
        "requirement": "Products must provide security-relevant logging mechanisms and audit trails without unnecessarily logging sensitive personal data.",
        "recommended_action": "Implement centralized security event logging with PII masking."
    },
    "CRA-I-3h": {
        "title": "CRA Annex I, Part I (3h) — Vulnerability Remediation Mechanism",
        "requirement": "Products must provide a mechanism to remediate vulnerabilities via secure updates.",
        "recommended_action": "Establish automated release, package, or image update delivery workflows."
    },
    "CRA-I-3i": {
        "title": "CRA Annex I, Part I (3i) — Attack Surface Minimization",
        "requirement": "Products must minimize attack surfaces, including unnecessary exposed interfaces, ports, and functionality.",
        "recommended_action": "Disable exposed debug endpoints, administrative interfaces, and open unnecessary ports."
    },
    "CRA-II-1": {
        "title": "CRA Annex I, Part II (1) — Component Identification & SBOM",
        "requirement": "Manufacturers must identify and document components, dependencies, and vulnerabilities, including by maintaining a Software Bill of Materials (SBOM).",
        "recommended_action": "Automate SBOM generation (CycloneDX/SPDX) on every release."
    },
    "CRA-II-2": {
        "title": "CRA Annex I, Part II (2) — Vulnerability Remediation SLA",
        "requirement": "Manufacturers must address and remediate vulnerabilities without delay, including through security updates.",
        "recommended_action": "Track vulnerability remediation age and enforce SLA targets for security fixes."
    },
    "CRA-II-3": {
        "title": "CRA Annex I, Part II (3) — Regular Security Testing",
        "requirement": "Manufacturers must apply effective, regular testing of security, including SAST, DAST, and security code reviews.",
        "recommended_action": "Integrate automated SAST and security scanners into CI/CD pipelines."
    },
    "CRA-II-4": {
        "title": "CRA Annex I, Part II (4) — Vulnerability Disclosure & Advisories",
        "requirement": "Manufacturers must publicly disclose fixed vulnerabilities, providing descriptions, impact, and remediation guidance.",
        "recommended_action": "Publish SECURITY.md advisories and security release notes."
    },
    "CRA-II-5": {
        "title": "CRA Annex I, Part II (5) — Coordinated Vulnerability Disclosure Policy",
        "requirement": "Manufacturers must put in place a coordinated vulnerability disclosure policy.",
        "recommended_action": "Maintain clear vulnerability disclosure guidelines in SECURITY.md."
    },
    "CRA-II-6": {
        "title": "CRA Annex I, Part II (6) — Vulnerability Reporting Contact",
        "requirement": "Manufacturers must provide a single point of contact to report vulnerabilities.",
        "recommended_action": "Publish security contact email/URL in SECURITY.md (shared with CERT-In requirements)."
    },
    "CRA-II-7": {
        "title": "CRA Annex I, Part II (7) — Free Distribution of Security Updates",
        "requirement": "Manufacturers must distribute security updates without delay, free of charge, with accompanying advisory information.",
        "recommended_action": "Establish organizational policy to distribute security patches free of charge (Organizational attestation required)."
    },
    "CRA-II-8": {
        "title": "CRA Annex I, Part II (8) — ENISA/CSIRT 24-Hour Early Warning",
        "requirement": "Manufacturers must notify ENISA and the designated CSIRT within 24 hours of becoming aware of any actively exploited vulnerability or severe incident.",
        "recommended_action": "Establish 24-hour incident notification process to ENISA/CSIRT (Organizational attestation required)."
    }
}

# Rule Patterns to CRA Requirement IDs Mapping
CRA_PATTERNS: Dict[str, List[str]] = {
    # Known vulnerabilities
    "snyk/*": ["CRA-I-2", "CRA-II-2"],
    "dep-scan/*": ["CRA-I-2", "CRA-II-2"],
    "pip-audit/*": ["CRA-I-2", "CRA-II-2"],
    "dependency-known-vulnerability": ["CRA-I-2", "CRA-II-2"],
    
    # SBOM & Component
    "cdxgen/*": ["CRA-II-1"],
    "sbom-missing": ["CRA-II-1"],
    "dependency-cruiser/*": ["CRA-II-1"],
    
    # Defaults
    "deslint/*": ["CRA-I-3a"],
    "hardcoded-credentials": ["CRA-I-3a"],
    "cra-i-3a-insecure-default": ["CRA-I-3a"],
    
    # Confidentiality & Storage
    "unprotected-pii-storage": ["CRA-I-3b"],
    "unprotected-storage": ["CRA-I-3b"],
    "tls-configuration-missing": ["CRA-I-3b"],
    
    # Integrity
    "unsigned-update-path": ["CRA-I-3c"],
    "missing-integrity-check": ["CRA-I-3c"],
    
    # Data Minimization
    "personal-data-field-detected": ["CRA-I-3d"],
    "unused-personal-data": ["CRA-I-3d"],
    
    # Sandboxing & Blast Radius
    "codex-architecture/*sandbox*": ["CRA-I-3f"],
    
    # Logging
    "codex-architecture/missing-logging": ["CRA-I-3g"],
    "logging-framework-detected": ["CRA-I-3g"],
    
    # Attack surface
    "exposed-debug-endpoint": ["CRA-I-3i"],
    
    # SECURITY.md Vulnerability Disclosure Policy & Contact
    "cra-ii-4-advisory-process": ["CRA-II-4"],
    "cra-ii-5-vulnerability-policy": ["CRA-II-5"],
    "cra-ii-6-vulnerability-contact": ["CRA-II-6"],
    "cra-security-md-disclosure": ["CRA-II-4", "CRA-II-5", "CRA-II-6"],
    
    # General Security Testing (SAST/DAST)
    "semgrep/*": ["CRA-II-3"],
    "bandit/*": ["CRA-II-3"],
    "codex-security/*": ["CRA-II-3"],
    "sonarqube/*": ["CRA-II-3"],
    "codex-architecture/*": ["CRA-I-1"]
}

def get_cra_references_for_rule(rule_id: str, detected_by: List[str] = None) -> List[str]:
    """Map rule_id or detected_by tools to CRA requirement IDs."""
    refs = set()
    clean_rule = str(rule_id or "").strip()
    
    # Direct pattern match
    for pat, cra_ids in CRA_PATTERNS.items():
        if pat.endswith("*"):
            prefix = pat[:-1]
            if clean_rule.startswith(prefix):
                refs.update(cra_ids)
        elif pat == clean_rule:
            refs.update(cra_ids)
            
    # Tool level fallback
    if detected_by:
        for tool in detected_by:
            tool_pat = f"{tool}/*"
            if tool_pat in CRA_PATTERNS:
                refs.update(CRA_PATTERNS[tool_pat])
                
    return sorted(list(refs))
