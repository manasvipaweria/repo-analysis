"""
DPDP Act 2023 §4 & §7 Processing Basis Decision Tree.
Strictly DPDP-specific. Does NOT use or inherit GDPR legitimate-interest balancing logic.
"""
from typing import Dict, Any, List, Optional
from src.compliance.dpdp_constants import LEGITIMATE_USE_CATEGORIES

def evaluate_dpdp_processing_basis(
    processing_context: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates processing context against DPDP §6 (Consent) and §7 (Closed-list Legitimate Uses).
    Returns a structured processing_basis dictionary.
    """
    purpose = str(processing_context.get("purpose") or "").lower()
    field = str(processing_context.get("field") or "").lower()
    processor = str(processing_context.get("processor") or "").lower()
    is_consent_flow = processing_context.get("is_consent_flow", False)
    consent_ui_default_checked = processing_context.get("consent_ui_default_checked", False)
    
    # 1. Check Consent Path (§6)
    if is_consent_flow:
        if consent_ui_default_checked:
            return {
                "type": "consent",
                "section": "6",
                "subsection": "6(1)",
                "candidate_subsections": [],
                "status": "UNESTABLISHED",
                "evidence": "Consent element detected but pre-ticked by default (violates affirmative action requirement under DPDP §6(1)).",
                "human_review_required": True
            }
        return {
            "type": "consent",
            "section": "6",
            "subsection": "6(1)",
            "candidate_subsections": [],
            "status": "DETECTED",
            "evidence": "Affirmative consent mechanism detected for processing.",
            "human_review_required": False
        }
        
    # 2. Check Closed List of §7 Legitimate Uses
    candidates: List[str] = []
    
    # 7(a) Voluntary disclosure for specified purpose
    if "transactional" in purpose or "order" in purpose or "opt_in" in purpose or processor in ["twilio", "sendgrid", "stripe"]:
        candidates.append("7(a)")
        
    # 7(d) Legal disclosure obligation
    if "tax" in purpose or "compliance" in purpose or "audit" in purpose or "legal" in purpose:
        candidates.append("7(d)")
        
    # 7(e) Court order / judgment compliance
    if "court" in purpose or "subpoena" in purpose or "order" in purpose:
        candidates.append("7(e)")
        
    # 7(f) Medical emergency
    if "emergency" in purpose or "medical" in purpose:
        candidates.append("7(f)")
        
    # 7(g) Public health
    if "epidemic" in purpose or "health" in purpose:
        candidates.append("7(g)")
        
    # 7(h) Disaster safety
    if "disaster" in purpose or "safety" in purpose:
        candidates.append("7(h)")
        
    # 7(i) Employment related
    if "employee" in purpose or "payroll" in purpose or "staff" in purpose or "workforce" in purpose:
        candidates.append("7(i)")
        
    # Exclude generic strings like "business need", "legitimate business purpose", or "commercial interest"
    # They DO NOT qualify as DPDP §7 legitimate use!
    
    if len(candidates) == 1:
        sub = candidates[0]
        return {
            "type": "legitimate_use",
            "section": "7",
            "subsection": sub,
            "candidate_subsections": candidates,
            "status": "POSSIBLE",
            "evidence": f"Candidate DPDP §7 legitimate use category: {sub} ({LEGITIMATE_USE_CATEGORIES[sub]}). Legal review required to verify real-world conditions.",
            "human_review_required": True
        }
    elif len(candidates) > 1:
        return {
            "type": "legitimate_use",
            "section": "7",
            "subsection": None,
            "candidate_subsections": candidates,
            "status": "POSSIBLE",
            "evidence": f"Multiple candidate DPDP §7 legitimate use categories identified: {', '.join(candidates)}. Legal review required to verify applicable clause.",
            "human_review_required": True
        }
        
    # 3. Unestablished Basis
    return {
        "type": "unestablished",
        "section": None,
        "subsection": None,
        "candidate_subsections": [],
        "status": "UNESTABLISHED",
        "evidence": "No clear consent capture or §7 legitimate use candidate evidenced from repository AST/data flow context. Lawful basis remains unestablished.",
        "human_review_required": True
    }
