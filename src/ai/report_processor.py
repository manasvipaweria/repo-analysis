import json
import re
from typing import Dict, Any

# Secret redaction regexes
SECRET_PATTERNS = [
    # Generic API Keys / Tokens
    (re.compile(r"(?i)(api[_-]?key[\s:=]+['\"]?)([a-zA-Z0-9_-]{16,})(['\"]?)"), r"\1[REDACTED_SECRET]\3"),
    (re.compile(r"(?i)(access[_-]?token[\s:=]+['\"]?)([a-zA-Z0-9_-]{16,})(['\"]?)"), r"\1[REDACTED_SECRET]\3"),
    (re.compile(r"(?i)(bearer[\s]+)([a-zA-Z0-9_\-\.]{16,})"), r"\1[REDACTED_SECRET]"),
    # Passwords (basic heuristic)
    (re.compile(r"(?i)(password[\s:=]+['\"]?)([^'\"\s]{8,})(['\"]?)"), r"\1[REDACTED_SECRET]\3"),
    # Private Keys
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[a-zA-Z0-9+/\n\s=]+-----END [A-Z ]+ PRIVATE KEY-----"), "[REDACTED_SECRET]"),
    # Connection Strings with credentials (e.g., mongodb://user:pass@host)
    (re.compile(r"(?i)(mongodb(?:\+srv)?://[^:]+:)([^@]+)(@)"), r"\1[REDACTED_SECRET]\3"),
    (re.compile(r"(?i)(postgres(?:ql)?://[^:]+:)([^@]+)(@)"), r"\1[REDACTED_SECRET]\3"),
    # Specific Cloud / Service Tokens
    (re.compile(r"(?i)(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})"), "[REDACTED_SECRET]"), # GitHub
    (re.compile(r"(?i)(AKIA[0-9A-Z]{16})"), "[REDACTED_SECRET]"), # AWS
    (re.compile(r"(?i)(sk-[a-zA-Z0-9]{48})"), "[REDACTED_SECRET]"), # OpenAI
]

def redact_secrets(text: str) -> str:
    if not text:
        return text
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted

def validate_report(report_data: Dict[str, Any]) -> None:
    findings = report_data.get("findings", [])
    summary = report_data.get("summary", {})
    
    # Calculate derived counts from findings
    derived_category_counts = {}
    for finding in findings:
        cat = finding.get("category", "unknown")
        derived_category_counts[cat] = derived_category_counts.get(cat, 0) + 1
        
    for cat, cat_summary in summary.items():
        summary_count = cat_summary.get("count", 0)
        derived_count = derived_category_counts.get(cat, 0)
        if summary_count != derived_count:
            # We don't crash, but we warn. In a real system, we could raise an error or just trust actual findings.
            print(f"Warning: Category '{cat}' summary count ({summary_count}) does not match actual findings count ({derived_count}).")

def process_report(input_file: str, output_file: str) -> None:
    with open(input_file, 'r', encoding='utf-8') as f:
        report_data = json.load(f)
        
    validate_report(report_data)
    
    ai_findings = []
    for raw_finding in report_data.get("findings", []):
        location = raw_finding.get("location", {})
        evidence = raw_finding.get("evidence", {})
        
        ai_finding = {
            "finding_id": raw_finding.get("finding_id"),
            "status": raw_finding.get("status"),
            "category": raw_finding.get("category"),
            "severity": raw_finding.get("severity"),
            "priority": raw_finding.get("priority"),
            "title": raw_finding.get("title"),
            "file": location.get("file"),
            "rule_id": raw_finding.get("rule_id"),
            "detected_by": raw_finding.get("detected_by"),
            "merge_blocking": raw_finding.get("merge_blocking")
        }
        
        if location.get("line") is not None and location.get("line") > 0:
            ai_finding["line"] = location["line"]
            
        if "confidence" in raw_finding and raw_finding["confidence"]:
            ai_finding["confidence"] = raw_finding["confidence"]
            
        # Redact secrets in message and code context
        ai_finding["message"] = redact_secrets(raw_finding.get("description", ""))
        
        context = evidence.get("code_context")
        if context:
            ai_finding["code_context"] = redact_secrets(context)
            
        ai_findings.append(ai_finding)
        
    ai_input = {
        "repository": report_data.get("repo"),
        "analysis_timestamp": report_data.get("timestamp"),
        "findings": ai_findings
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(ai_input, f, indent=2)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python report_processor.py <input_report.json> <output_ai_input.json>")
        sys.exit(1)
    process_report(sys.argv[1], sys.argv[2])
