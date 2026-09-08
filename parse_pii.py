import json

with open("report.json", "r", encoding="utf-8") as f:
    data = json.load(f)

pii_findings = [f for f in data.get("findings", []) if f.get("rule_id") in ("excessive-pii-fields", "personal-data-field-detected")]
all_gdpr = [f for f in data.get("findings", []) if "personal-data" in f.get("rule_id", "") or "consent" in f.get("rule_id", "") or "missing-export" in f.get("rule_id", "") or "excessive-pii" in f.get("rule_id", "")]

print(f"Total personal-data-field-detected: {len(pii_findings)}")
print(f"Total all GDPR findings: {len(all_gdpr)}")

fields = {}
for f in pii_findings:
    msg = f.get("description", "")
    file = f.get("location", {}).get("file", "")
    line = f.get("location", {}).get("line", "")
    field = msg.split(": ")[-1] if ": " in msg else "unknown"
    
    if field not in fields:
        fields[field] = []
    fields[field].append(f"{file}:{line}")

print(f"\nUnique detected fields: {len(fields)}")
for k, v in fields.items():
    print(f"\n  Field: {k} ({len(v)} occurrences)")
    for item in v[:3]:
        print(f"    - {item}")
    if len(v) > 3:
        print(f"    - ... and {len(v)-3} more")

print(f"\nAll GDPR rule_ids:")
from collections import Counter
rules = Counter(f.get("rule_id", "?") for f in data.get("findings", []) if "gdpr" in f.get("title", "").lower() or f.get("rule_id", "").startswith("personal") or f.get("rule_id", "").startswith("consent") or f.get("rule_id", "").startswith("missing"))
for r, c in rules.items():
    print(f"  {r}: {c}")
