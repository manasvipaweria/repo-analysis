import json

with open("report.json", "r", encoding="utf-8") as f:
    data = json.load(f)

count = 0
for f in data["findings"]:
    if f["rule_id"] == "deslint/no-inline-styles":
        loc = f.get("location", {})
        file = loc.get("file", "")
        line = loc.get("line", 0)
        snippet = ""
        try:
            with open(file, "r", encoding="utf-8") as source:
                lines = source.readlines()
                snippet = "".join(lines[max(0, line-2):min(len(lines), line+2)])
        except:
            pass
        if "?" in snippet:
            print("---")
            print(snippet.strip().encode('ascii', 'ignore').decode('ascii'))
            count += 1
            if count > 10:
                break
