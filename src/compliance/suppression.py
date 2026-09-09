import json
import os

SUPPRESSION_FILE = ".repo-analysis/suppressions.json"

def get_suppression_file(repo_path: str) -> str:
    return os.path.join(repo_path, SUPPRESSION_FILE)

def load_suppressions(repo_path: str) -> set:
    path = get_suppression_file(repo_path)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except:
            pass
    return set()

def save_suppression(repo_path: str, key: str):
    path = get_suppression_file(repo_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    suppressions = load_suppressions(repo_path)
    suppressions.add(key)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(list(suppressions), f, indent=2)

def generate_suppression_key(finding) -> str:
    # file + rule + finding_type
    finding_type = finding.compliance_finding_type.value if finding.compliance_finding_type else "unknown"
    file_path = finding.location.file if finding.location else "unknown"
    return f"{file_path}:{finding.rule_id}:{finding_type}"

def filter_suppressed_findings(findings, repo_path: str):
    suppressions = load_suppressions(repo_path)
    active = []
    dismissed_count = 0
    for f in findings:
        if hasattr(f, "compliance_finding_type") and f.compliance_finding_type:
            key = generate_suppression_key(f)
            if key in suppressions:
                dismissed_count += 1
                continue
        active.append(f)
    return active, dismissed_count
