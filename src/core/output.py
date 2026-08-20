import json
import csv
from typing import Any, Dict
from .models import Report

def write_json_report(report: Report, filepath: str) -> None:
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report.to_dict(), f, indent=2)

def write_csv_report(report: Report, filepath: str) -> None:
    """
    Writes the report to a CSV file.
    Includes summary/status rows for every configured category, including clean categories,
    followed by the normalized findings.
    """
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Write summary section
        writer.writerow(["Type", "Category", "Status", "Finding Count", "Metrics / Info"])
        for cat_name, cat_summary in report.summary.items():
            metrics_str = json.dumps(cat_summary.metrics) if cat_summary.metrics else ""
            writer.writerow(["SUMMARY", cat_name, cat_summary.status.value, cat_summary.count, metrics_str])
            
        writer.writerow([]) # blank line
        
        # Write findings section
        writer.writerow([
            "Type", "Finding ID", "Category", "Priority", "Severity", 
            "Merge Blocking", "File", "Line", "Rule ID", "Message", 
            "Code Context", "Detected By"
        ])
        for finding in report.findings:
            detected_by_str = ", ".join(finding.detected_by)
            writer.writerow([
                "FINDING",
                finding.finding_id,
                finding.category,
                finding.priority,
                finding.severity,
                finding.merge_blocking,
                finding.file,
                finding.line,
                finding.rule_id,
                finding.message,
                finding.code_context or "",
                detected_by_str
            ])
