import json
from collections import Counter

with open("report.json", encoding="utf-8") as f:
    data = json.load(f)

rules = Counter(f["rule_id"] for f in data["findings"] if "deslint" in f.get("rule_id", ""))
print("=== Findings by rule ===")
total = 0
for r, c in sorted(rules.items(), key=lambda x: -x[1]):
    print(f"{c:4d}  {r}")
    total += c
print(f"     ----")
print(f"{total:4d}  TOTAL")

inline = [f for f in data["findings"] if f["rule_id"] == "deslint/no-inline-styles"]
print(f"\nTotal no-inline-styles: {len(inline)}")

# Classify into A/B/C/D
cat_a = []  # Correct finding (static literal, no design-token)
cat_b = []  # False positive
cat_c = []  # Legitimate exception (dynamic that slipped through)
cat_d = []  # Design-system context needed (uses var(--)

for f in inline:
    loc = f.get("location", {})
    file_path = loc.get("file", "")
    line = loc.get("line", 0)
    ctx = f.get("evidence", {}).get("code_context", "")
    try:
        with open(file_path, encoding="utf-8", errors="replace") as src:
            lines = src.readlines()
            snippet = "".join(lines[max(0, line-3):line+3])
    except Exception:
        snippet = ctx

    if "var(--" in snippet:
        cat_d.append(f)  # references a design token, needs context
    elif "test" in file_path.lower() and ("Arbitrary" in file_path or "test" in file_path.lower()):
        cat_b.append(f)  # test file
    else:
        cat_a.append(f)  # correct finding

print("\n=== Classification (A/B/C/D) ===")
print(f"  A - Correct finding (static, no token):   {len(cat_a)}")
print(f"  B - False positive (test file):            {len(cat_b)}")
print(f"  C - Legitimate exception (dynamic missed): {len(cat_c)}")
print(f"  D - Needs design-system context (var(--):  {len(cat_d)}")

print("\n=== 5 Category A samples ===")
for f in cat_a[:5]:
    loc = f.get("location", {})
    print(f"  [{loc.get('file', '')}:{loc.get('line', '')}]")

print("\n=== 5 Category D samples (var(--) references) ===")
for f in cat_d[:5]:
    loc = f.get("location", {})
    print(f"  [{loc.get('file', '')}:{loc.get('line', '')}]")
