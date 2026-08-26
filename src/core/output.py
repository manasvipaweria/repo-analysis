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
            "Type", "Finding ID", "Status", "Category", "Priority", "Severity", 
            "Merge Blocking", "File", "Line", "Title", "Description", 
            "Rule ID", "Code Context", "Detected By",
            "AI Summary", "Security Impact", "Remediation", "False Positive Prediction"
        ])
        for finding in report.findings:
            detected_by_str = ", ".join(finding.detected_by)
            
            # Safely handle nested locations and evidence
            file_path = finding.location.file if finding.location else ""
            line_num = finding.location.line if finding.location else ""
            context = finding.evidence.code_context if finding.evidence else ""
            
            # Safely handle AI fields
            ai = finding.ai_fields
            ai_summary = ai.analysis_summary if ai and ai.analysis_summary else ""
            ai_impact = ai.security_impact if ai and ai.security_impact else ""
            ai_remediation = ai.remediation_suggestion if ai and ai.remediation_suggestion else ""
            ai_fp = str(ai.is_false_positive_prediction) if ai and ai.is_false_positive_prediction is not None else ""
            
            writer.writerow([
                "FINDING",
                finding.finding_id,
                finding.status,
                finding.category,
                finding.priority,
                finding.severity,
                finding.merge_blocking,
                file_path,
                line_num,
                finding.title,
                finding.description,
                finding.rule_id,
                context or "",
                detected_by_str,
                ai_summary,
                ai_impact,
                ai_remediation,
                ai_fp
            ])
