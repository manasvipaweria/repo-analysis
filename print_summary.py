import json

with open("report.json", "r", encoding="utf-8") as f:
    d = json.load(f)

summary = d.get("summary", {})
for cat, v in summary.items():
    print(cat, v["status"], v["count"], "findings")
    for tool, ts in v.get("tools", {}).items():
        err = ts.get("error_message", "")
        fc = ts.get("finding_count", 0)
        err_str = (" ERR: " + err[:80]) if err else ""
        print(f"  {tool}: {ts['status']} ({fc} findings){err_str}")
