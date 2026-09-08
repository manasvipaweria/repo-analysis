import json
import re

with open("report.json", "r", encoding="utf-8") as f:
    data = json.load(f)

inline_styles = [f for f in data["findings"] if f["rule_id"] == "deslint/no-inline-styles"]
others = [f for f in data["findings"] if f["rule_id"] in ["deslint/responsive-required", "deslint/no-arbitrary-colors", "deslint/no-arbitrary-spacing", "deslint/no-arbitrary-typography"]]

cat1_static = []
cat2_dynamic = []
cat3_special = []
cat4_generated = []
cat5_fp = []

for f in inline_styles:
    loc = f.get("location", {})
    file = loc.get("file", "")
    line = loc.get("line", 0)
    
    # Let's read the actual file
    snippet = ""
    try:
        with open(file, "r", encoding="utf-8") as source:
            lines = source.readlines()
            snippet = "".join(lines[max(0, line-2):min(len(lines), line+2)])
    except:
        pass
        
    if "components/ui/" in file or "node_modules" in file or "test" in file.lower() or "setup" in file:
        cat4_generated.append(f)
        continue

    if "style=" not in snippet and "style {{" not in snippet and "style={{" not in snippet and "style=" not in snippet.replace(" ", ""):
        cat5_fp.append(f)
        continue
        
    if "${" in snippet or "?" in snippet or "||" in snippet:
        if "transform" in snippet or "width" in snippet or "height" in snippet or "top" in snippet:
            cat3_special.append(f)
        else:
            cat2_dynamic.append(f)
    elif re.search(r"style=\{\{\s*[a-zA-Z]+:\s*['\"][^'\"]+['\"]\s*\}\}", snippet) or "color:" in snippet or "margin" in snippet or "marginTop" in snippet:
        cat1_static.append(f)
    else:
        # Check if it has simple static strings or numbers
        if "{" in snippet and "}" in snippet and not "=>" in snippet:
             cat1_static.append(f)
        else:
             cat2_dynamic.append(f)

print(f"Total inline: {len(inline_styles)}")
print(f"Cat1 Static: {len(cat1_static)}")
print(f"Cat2 Dynamic: {len(cat2_dynamic)}")
print(f"Cat3 Special: {len(cat3_special)}")
print(f"Cat4 Generated/Third-party: {len(cat4_generated)}")
print(f"Cat5 False Positive: {len(cat5_fp)}")

print("\n--- OTHERS ---")
for o in others:
    loc = o.get("location", {})
    print(f"{o['rule_id']} in {loc.get('file')}:{loc.get('line')}")
