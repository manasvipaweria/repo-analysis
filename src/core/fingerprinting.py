import hashlib
from typing import Optional, List
from src.core.models import Finding

def normalize_path(file_path: Optional[str], repo_root: Optional[str] = None) -> str:
    """Normalize file path for fingerprinting."""
    if not file_path:
        return ""
    
    norm_path = file_path.replace('\\', '/')
    
    if repo_root:
        repo_root = repo_root.replace('\\', '/')
        if norm_path.startswith(repo_root):
            norm_path = norm_path[len(repo_root):]
            if norm_path.startswith('/'):
                norm_path = norm_path[1:]
                
    if norm_path.startswith('./'):
        norm_path = norm_path[2:]
        
    return norm_path.lower()

def generate_fingerprint(finding: Finding, repo_root: Optional[str] = None) -> str:
    """Generate a stable fingerprint for a Finding."""
    components = []
    
    # 1. Tool/Detected By
    tools = sorted(finding.detected_by) if finding.detected_by else ["unknown"]
    components.append(",".join(tools).lower())
    
    # 2. Rule ID
    rule = finding.rule_id if finding.rule_id else "unknown"
    components.append(rule.lower())
    
    # 3. Category
    cat = finding.category if finding.category else "unknown"
    components.append(cat.lower())
    
    # 4. Normalized Path
    file_path = finding.location.file if finding.location else ""
    components.append(normalize_path(file_path, repo_root))
    
    # 5. Stable Location
    loc = "unknown"
    if finding.location and finding.location.line is not None:
        loc = str(finding.location.line)
        
    components.append(loc)
    
    # 6. Compliance Finding Type
    cft = finding.compliance_finding_type.value if finding.compliance_finding_type else "unknown"
    components.append(cft.lower())
    
    # 7. For repository-level organizational/checklist findings (no location), 
    # use the message to distinguish distinct findings that share the same rule.
    if not finding.location or (not finding.location.file and finding.location.line is None):
        msg = finding.description if finding.description else "no-message"
        components.append(msg.lower())
    
    # Hash the canonical representation
    canonical_string = "|".join(components)
    return hashlib.sha256(canonical_string.encode('utf-8')).hexdigest()

def assign_fingerprints(findings: List[Finding], repo_root: Optional[str] = None):
    for f in findings:
        if not getattr(f, 'fingerprint', None):
            f.fingerprint = generate_fingerprint(f, repo_root)
