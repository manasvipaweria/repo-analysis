import json
import re

with open("report.json", "r", encoding="utf-8") as f:
    data = json.load(f)

inline_styles = [f for f in data["findings"] if f["rule_id"] == "deslint/no-inline-styles"]

cat1_static = []
cat2_dynamic = []
cat3_special = []

for f in inline_styles:
    file = f.get("location", {}).get("file", "")
    line = f.get("location", {}).get("line", 0)
    
    snippet = ""
    try:
        with open(file, "r", encoding="utf-8") as source:
            lines = source.readlines()
            snippet = "".join(lines[max(0, line-5):min(len(lines), line+5)])
    except:
        pass

    style_match = re.search(r'style=\{\{([^}]+)\}\}', snippet)
    if style_match:
        style_content = style_match.group(1)
        if "${" in style_content or "?" in style_content or "||" in style_content or "&&" in style_content or "(" in style_content:
            if "transform" in style_content or "width" in style_content or "height" in style_content or "top" in style_content or "gridTemplateColumns" in style_content:
                cat3_special.append(f)
            else:
                cat2_dynamic.append(f)
        else:
            cat1_static.append(f)
    else:
        dynamic_match = re.search(r'style=\{([^}]+)\}', snippet)
        if dynamic_match:
            cat2_dynamic.append(f)
        else:
            cat1_static.append(f)

print(f"Total inline: {len(inline_styles)}")
print(f"Cat1 Static: {len(cat1_static)}")
print(f"Cat2 Dynamic: {len(cat2_dynamic)}")
print(f"Cat3 Special: {len(cat3_special)}")
