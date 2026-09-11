"""
India CERT-In (Cyber Security Directions under Section 70B(6) IT Act, 2000) Requirement Mapping Layer.
Centralizes technical rule/tool -> CERT-In requirement and Annexure I incident category IDs.
"""
from typing import List, Dict, Optional

# CERT-In Requirement & Annexure I Category Metadata
CERT_IN_REQUIREMENTS: Dict[str, Dict[str, str]] = {
    # Annexure I Incident Categories (20 Types)
    "CERT-IN-ANNEX-1": {
        "title": "CERT-In Annexure I (1) — Targeted Scanning / Probing of Critical Networks / Systems",
        "requirement": "Mandatory 6-hour reporting to CERT-In for targeted scanning/probing of critical networks/systems.",
        "recommended_action": "Maintain network intrusion detection systems and log scanning activity."
    },
    "CERT-IN-ANNEX-2": {
        "title": "CERT-In Annexure I (2) — Compromise of Critical Systems / Information",
        "requirement": "Mandatory 6-hour reporting to CERT-In for compromise of critical systems/information.",
        "recommended_action": "Remediate critical vulnerabilities and enforce system integrity controls."
    },
    "CERT-IN-ANNEX-3": {
        "title": "CERT-In Annexure I (3) — Unauthorised Access of IT Systems / Data",
        "requirement": "Mandatory 6-hour reporting to CERT-In for unauthorised access of IT systems/data.",
        "recommended_action": "Enforce strict identity/access management and eliminate hardcoded credentials."
    },
    "CERT-IN-ANNEX-4": {
        "title": "CERT-In Annexure I (4) — Defacement of Website or Intrusion into Website",
        "requirement": "Mandatory 6-hour reporting to CERT-In for website defacement or website intrusion.",
        "recommended_action": "Harden web applications, input validation, and content integrity verification."
    },
    "CERT-IN-ANNEX-5": {
        "title": "CERT-In Annexure I (5) — Malicious Code Attacks (Virus/Worm/Trojan/Botnet/Spyware)",
        "requirement": "Mandatory 6-hour reporting to CERT-In for malicious code outbreaks or infections.",
        "recommended_action": "Deploy anti-malware, endpoint protection, and software bill of materials (SBOM)."
    },
    "CERT-IN-ANNEX-6": {
        "title": "CERT-In Annexure I (6) — Attack on Servers (Database, Mail, DNS, Network Devices)",
        "requirement": "Mandatory 6-hour reporting to CERT-In for attacks targeting backend servers or network infrastructure.",
        "recommended_action": "Harden database access, mail gateway configurations, and DNS infrastructure."
    },
    "CERT-IN-ANNEX-7": {
        "title": "CERT-In Annexure I (7) — Identity Theft, Spoofing, Phishing Attacks",
        "requirement": "Mandatory 6-hour reporting to CERT-In for identity theft, brand spoofing, or phishing campaigns.",
        "recommended_action": "Enforce SPF/DKIM/DMARC, MFA, and anti-phishing technical controls."
    },
    "CERT-IN-ANNEX-8": {
        "title": "CERT-In Annexure I (8) — Denial of Service (DoS) and Distributed DoS (DDoS) Attacks",
        "requirement": "Mandatory 6-hour reporting to CERT-In for DoS/DDoS attacks affecting system availability.",
        "recommended_action": "Implement rate limiting, DoS protection services, and availability SLAs."
    },
    "CERT-IN-ANNEX-9": {
        "title": "CERT-In Annexure I (9) — Attacks on Critical Infrastructure / SCADA / OT Systems",
        "requirement": "Mandatory 6-hour reporting to CERT-In for attacks on critical infrastructure and SCADA systems.",
        "recommended_action": "Isolate operational technology (OT) networks and enforce zero-trust segmentation."
    },
    "CERT-IN-ANNEX-10": {
        "title": "CERT-In Annexure I (10) — Attacks on Applications (E-Governance, E-Commerce, etc.)",
        "requirement": "Mandatory 6-hour reporting to CERT-In for attacks exploiting application layer vulnerabilities.",
        "recommended_action": "Perform regular SAST/DAST testing and remediate high-severity web application flaws."
    },
    "CERT-IN-ANNEX-11": {
        "title": "CERT-In Annexure I (11) — Data Breach / Unauthorised Data Access",
        "requirement": "Mandatory 6-hour reporting to CERT-In for data breaches or unauthorized personal/sensitive data access.",
        "recommended_action": "Encrypt sensitive data at rest and in transit; audit data flow paths."
    },
    "CERT-IN-ANNEX-12": {
        "title": "CERT-In Annexure I (12) — Data Leak / Unintended Data Disclosure",
        "requirement": "Mandatory 6-hour reporting to CERT-In for unintended data exposure or public leak.",
        "recommended_action": "Enforce data loss prevention (DLP) and audit public cloud bucket/endpoint permissions."
    },
    "CERT-IN-ANNEX-13": {
        "title": "CERT-In Annexure I (13) — Attacks on Internet of Things (IoT) Devices",
        "requirement": "Mandatory 6-hour reporting to CERT-In for compromise or attacks on IoT hardware/firmware.",
        "recommended_action": "Secure IoT device management, firmware update signing, and network isolation."
    },
    "CERT-IN-ANNEX-14": {
        "title": "CERT-In Annexure I (14) — Attacks or Incidents Affecting Digital Payment Systems",
        "requirement": "Mandatory 6-hour reporting to CERT-In for attacks on digital payment systems or financial gateways.",
        "recommended_action": "Enforce PCI-DSS compliance, tokenization, and transactional security audits."
    },
    "CERT-IN-ANNEX-15": {
        "title": "CERT-In Annexure I (15) — Attacks Through Malicious Mobile Apps",
        "requirement": "Mandatory 6-hour reporting to CERT-In for incidents involving malicious mobile application vectors.",
        "recommended_action": "Sign mobile binaries, audit SDK dependencies, and enforce app transport security."
    },
    "CERT-IN-ANNEX-16": {
        "title": "CERT-In Annexure I (16) — Fake Mobile Apps",
        "requirement": "Mandatory 6-hour reporting to CERT-In for discovery of rogue or counterfeit mobile apps.",
        "recommended_action": "Monitor mobile app store listings and enforce brand protection."
    },
    "CERT-IN-ANNEX-17": {
        "title": "CERT-In Annexure I (17) — Unauthorized Access to Social Media Accounts",
        "requirement": "Mandatory 6-hour reporting to CERT-In for compromise of organizational social media accounts.",
        "recommended_action": "Enforce mandatory MFA and centralized access management for social media handles."
    },
    "CERT-IN-ANNEX-18": {
        "title": "CERT-In Annexure I (18) — Attacks / Compromise Related to Cloud Systems",
        "requirement": "Mandatory 6-hour reporting to CERT-In for attacks or compromised cloud infrastructure.",
        "recommended_action": "Audit cloud IAM roles, security groups, and cloud-native logging."
    },
    "CERT-IN-ANNEX-19": {
        "title": "CERT-In Annexure I (19) — Attacks / Compromise Related to AI / Machine Learning",
        "requirement": "Mandatory 6-hour reporting to CERT-In for attacks targeting AI/ML models or data pipelines.",
        "recommended_action": "Protect AI model parameters, training data integrity, and prompt safety boundaries."
    },
    "CERT-IN-ANNEX-20": {
        "title": "CERT-In Annexure I (20) — Ransomware / Extortion Attacks",
        "requirement": "Mandatory 6-hour reporting to CERT-In for ransomware infections or extortion demands.",
        "recommended_action": "Maintain immutable offline backups, endpoint detection, and rapid response SLAs."
    },
    
    # Statutory General & Specific Requirements
    "CERT-IN-POC": {
        "title": "CERT-In Point of Contact & Vulnerability Reporting Channel",
        "requirement": "Service providers, intermediaries, data centers, and bodies corporate must designate a Point of Contact to communicate with CERT-In.",
        "recommended_action": "Publish security contact email/URL in SECURITY.md."
    },
    "CERT-IN-LOG-RETENTION": {
        "title": "CERT-In Directions §5(v) Log Retention (180 Days) & Indian Residency",
        "requirement": "All service providers, intermediaries, data centers, and bodies corporate must securely maintain logs of all ICT systems for a rolling period of 180 days within the Indian jurisdiction.",
        "recommended_action": "Configure log retention policies for 180+ days and specify Indian cloud region storage (e.g., ap-south-1)."
    },
    "CERT-IN-NTP": {
        "title": "CERT-In Directions §5(i) NTP Time Synchronization",
        "requirement": "All ICT systems must synchronize system clocks with Network Time Protocol (NTP) servers traceable to NPL or NIC.",
        "recommended_action": "Configure NTP synchronization using NPL/NIC traceable time servers."
    },
    "CERT-IN-KYC": {
        "title": "CERT-In Directions §5(vi) 5-Year Subscriber / KYC Record-Keeping",
        "requirement": "Data centers, Virtual Private Server (VPS) providers, cloud service providers, and virtual asset exchanges must maintain subscriber/KYC records for 5 years.",
        "recommended_action": "Maintain subscriber identity, registration IP, and transaction records for 5 years."
    }
}

# Rule Patterns to CERT-In Category IDs Mapping
CERT_IN_PATTERNS: Dict[str, List[str]] = {
    # Known vulnerabilities in dependencies (compromise / application attack vectors)
    "snyk/*": ["CERT-IN-ANNEX-2", "CERT-IN-ANNEX-10"],
    "dep-scan/*": ["CERT-IN-ANNEX-2", "CERT-IN-ANNEX-10"],
    "pip-audit/*": ["CERT-IN-ANNEX-2", "CERT-IN-ANNEX-10"],
    "dependency-known-vulnerability": ["CERT-IN-ANNEX-2", "CERT-IN-ANNEX-10"],
    
    # SAST / Code Security findings (unauthorized access / application flaws / data breaches)
    "semgrep/*": ["CERT-IN-ANNEX-3", "CERT-IN-ANNEX-10"],
    "bandit/*": ["CERT-IN-ANNEX-3", "CERT-IN-ANNEX-10"],
    "codex-security/*": ["CERT-IN-ANNEX-3", "CERT-IN-ANNEX-10"],
    "sonarqube/*": ["CERT-IN-ANNEX-3", "CERT-IN-ANNEX-10"],
    "hardcoded-credentials": ["CERT-IN-ANNEX-3", "CERT-IN-ANNEX-11"],
    "unprotected-pii-storage": ["CERT-IN-ANNEX-11", "CERT-IN-ANNEX-12"],
    "unprotected-storage": ["CERT-IN-ANNEX-11", "CERT-IN-ANNEX-12"],
    
    # SECURITY.md Point of Contact
    "cra-security-md-disclosure": ["CERT-IN-POC"],
    "cra-ii-6-vulnerability-contact": ["CERT-IN-POC"],
}

def get_cert_in_references_for_rule(
    rule_id: str, 
    detected_by: List[str] = None, 
    severity: Optional[str] = None
) -> List[str]:
    """
    Map rule_id or detected_by tools to CERT-In Annexure I / requirement IDs.
    Guardrail: Only tag security tool findings if severity is high/critical or if explicitly matched by rule_id.
    """
    refs = set()
    clean_rule = str(rule_id or "").strip()
    clean_sev = str(severity or "").lower()
    
    # Direct pattern match
    for pat, cert_ids in CERT_IN_PATTERNS.items():
        if pat.endswith("*"):
            prefix = pat[:-1]
            if clean_rule.startswith(prefix):
                # For tool wildcard patterns, enforce severity filter (high/critical) unless specific rule
                if clean_sev in ("high", "critical", "error"):
                    refs.update(cert_ids)
        elif pat == clean_rule:
            refs.update(cert_ids)
            
    # Tool level fallback with severity guardrail
    if detected_by and clean_sev in ("high", "critical", "error"):
        for tool in detected_by:
            tool_pat = f"{tool}/*"
            if tool_pat in CERT_IN_PATTERNS:
                refs.update(CERT_IN_PATTERNS[tool_pat])
                
    return sorted(list(refs))
