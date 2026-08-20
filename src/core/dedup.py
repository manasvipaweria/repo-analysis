import re
from typing import List

from .models import Finding

def extract_words(text: str) -> set:
    text = text.lower()
    words = re.findall(r'\b\w+\b', text)
    # filter out common stop words and generic terms
    stop_words = {'the', 'a', 'an', 'is', 'in', 'at', 'of', 'for', 'to', 'and', 'or', 'with', 'on', 'use', 'using', 'used', 'found', 'detected'}
    return set(w for w in words if w not in stop_words)

def jaccard_similarity(set1: set, set2: set) -> float:
    if not set1 and not set2:
        return 1.0
    intersection = len(set1.intersection(set2))
    union = len(set1.union(set2))
    return intersection / union if union > 0 else 0.0

def is_duplicate(f1: Finding, f2: Finding) -> bool:
    if f1.file != f2.file or f1.line != f2.line or f1.category != f2.category:
        return False
    
    # Exact rule ID match
    if f1.rule_id == f2.rule_id:
        return True
        
    # Heuristic: check if they are the same underlying rule ID namespace
    # e.g., semgrep 'bandit.B101' and bandit 'B101'
    if f1.rule_id in f2.rule_id or f2.rule_id in f1.rule_id:
        return True
        
    # If both look like explicit vulnerability identifiers (CVE, GHSA, etc.)
    # and they didn't match above, they are definitely distinct vulnerabilities.
    is_vuln1 = f1.rule_id.startswith("CVE-") or f1.rule_id.startswith("GHSA-")
    is_vuln2 = f2.rule_id.startswith("CVE-") or f2.rule_id.startswith("GHSA-")
    if is_vuln1 and is_vuln2:
        return False
        
    # Heuristic: message similarity
    words1 = extract_words(f1.message)
    words2 = extract_words(f2.message)
    
    if jaccard_similarity(words1, words2) > 0.4:
        return True
        
    return False

def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Conservatively deduplicates findings across different tools.
    Multiple tools may identify the same underlying issue.
    We only merge if file, line, category match AND we have strong confidence
    (matching rule ID or high message similarity).
    """
    deduped: List[Finding] = []
    
    for f in findings:
        merged = False
        for d in deduped:
            if is_duplicate(f, d):
                # Merge f into d
                # Ensure detected_by is updated
                for tool in f.detected_by:
                    if tool not in d.detected_by:
                        d.detected_by.append(tool)
                
                # Combine rule IDs if they differ
                if f.rule_id not in d.rule_id:
                    d.rule_id = f"{d.rule_id}, {f.rule_id}"
                    
                merged = True
                break
        if not merged:
            deduped.append(f)
            
    return deduped
