import json
import sys

with open("report.json", "r", encoding="utf-8") as f:
    data = json.load(f)

inline = [f for f in data["findings"] if f["rule_id"] == "deslint/no-inline-styles"]

print(f"Finding keys: {list(inline[0].keys())}")
print()

contexts = [f.get("evidence", {}).get("code_context", "") for f in inline]

# classify
static_cases = []
dynamic_cases = []
css_var_cases = []
width_pct_cases = []

for f in inline:
    ctx = f.get("evidence", {}).get("code_context", "")
    loc = f.get("location", {})
    desc = f.get("description", "")
    
    # Try to read actual file line
    file = loc.get("file", "")
    line = loc.get("line", 0)
    snippet = ""
    try:
        with open(file, "r", encoding="utf-8") as src:
            lines = src.readlines()
            snippet = "".join(lines[max(0,line-3):line+3])
    except:
        snippet = ctx
    
    if "var(--" in snippet:
        css_var_cases.append(snippet[:200])
    elif "width: \"100%\"" in snippet or "width: '100%'" in snippet:
        width_pct_cases.append(snippet[:200])
    elif any(dyn in snippet for dyn in ["? ", "||", "${", "=>", "Identifier", "MemberExpression"]):
        dynamic_cases.append(snippet[:200])
    else:
        static_cases.append(snippet[:200])

print(f"CSS var() refs: {len(css_var_cases)}")
print(f"width 100% (likely special): {len(width_pct_cases)}")
print(f"Dynamic patterns: {len(dynamic_cases)}")
print(f"Static literal: {len(static_cases)}")
print()

print("=== CSS VAR EXAMPLES (3) ===")
for c in css_var_cases[:3]:
    print("---")
    sys.stdout.buffer.write(c.encode("ascii", "replace") + b"\n")

print()
print("=== WIDTH 100% EXAMPLES (3) ===")
for c in width_pct_cases[:3]:
    print("---")
    sys.stdout.buffer.write(c.encode("ascii", "replace") + b"\n")

print()
print("=== STATIC EXAMPLES (5) ===")
for c in static_cases[:5]:
    print("---")
    sys.stdout.buffer.write(c.encode("ascii", "replace") + b"\n")
