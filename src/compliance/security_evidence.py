from typing import List
from src.core.models import Finding, ComplianceFindingType, Category
from src.compliance.requirement_text import REQUIREMENTS
import uuid

def cross_reference_security(gdpr_findings: List[Finding], all_findings: List[Finding]) -> List[Finding]:
    security_gaps = []
    
    security_by_file = {}
    for f in all_findings:
        if f.category == Category.SECURITY.value:
            file_path = f.location.file if f.location else None
            if file_path:
                if file_path not in security_by_file:
                    security_by_file[file_path] = []
                security_by_file[file_path].append(f)
            
    for gf in gdpr_findings:
        if not hasattr(gf, "compliance_finding_type") or not gf.compliance_finding_type:
            continue
            
        file_path = gf.location.file if gf.location else None
        if not file_path:
            continue
            
        file_security = security_by_file.get(file_path, [])
        
        for sec in file_security:
            rule_id_lower = sec.rule_id.lower()
            if "secret" in rule_id_lower or "password" in rule_id_lower or "hardcoded" in rule_id_lower or "https" in rule_id_lower or "auth" in rule_id_lower:
                new_finding = Finding(
                    category=Category.SECURITY.value,
                    severity="high",
                    file=file_path,
                    line=gf.location.line if gf.location else 0,
                    message=f"Security gap found in file handling personal data ({gf.description or gf.message}). Evidence: {sec.rule_id}",
                    rule_id="security-gap-pii",
                    finding_id=str(uuid.uuid4()),
                    status="OPEN",
                    priority="P2",
                    title="GDPR: Article 32 Security Gap",
                    compliance_finding_type=ComplianceFindingType.SECURITY_GAP,
                    gdpr_references=["Art. 32"],
                    code_context=REQUIREMENTS["Art. 32"],
                    detected_by=["security_evidence"]
                )
                security_gaps.append(new_finding)
                
    return security_gaps
