from typing import List

EPRIVACY_SECURITY_RULES = [
    "CWE-311", "CWE-312", "CWE-319", "CWE-295", "CWE-300", 
    "CWE-200", "CWE-327", "CWE-328", "CWE-330", "CWE-522",
    "insecure-transport", "cleartext-transmission", "ssl-tls-misconfiguration"
]

def get_eprivacy_references_for_rule(rule_id: str, detected_by: List[str] = None) -> List[str]:
    """
    Returns the applicable ePrivacy Article reference(s) for a given rule_id.
    """
    rule_lower = rule_id.lower()
    refs = []

    # Article 4: Security of Processing (relevant to electronic communications)
    if any(s in rule_upper for s in EPRIVACY_SECURITY_RULES for rule_upper in [rule_id.upper()]):
        refs.append("EPRIVACY-ART4-SECURITY")
    
    # We don't map generic SQLi or XSS to ePrivacy unless it specifically compromises communications.
    if "insecure-transport" in rule_lower or "cleartext" in rule_lower:
        if "EPRIVACY-ART5-CONFIDENTIALITY" not in refs:
            refs.append("EPRIVACY-ART5-CONFIDENTIALITY")
            
    return refs
