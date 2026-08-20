import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import has_python_files

class BanditAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "bandit"

    @property
    def categories(self) -> List[str]:
        return [Category.SECURITY.value]

    def run(self, repo_path: str) -> ToolResult:
        if not has_python_files(repo_path):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="No Python files found."
            )
            
        try:
            result = subprocess.run(
                ["bandit", "-r", ".", "-f", "json"],
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                if not result.stdout.strip():
                    output_data = {}
                else:
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"Failed to parse Bandit output: {result.stderr or result.stdout}"
                    )
                
            findings = []
            for item in output_data.get('results', []):
                filename = os.path.relpath(item.get('filename', ''), repo_path)
                
                findings.append(Finding(
                    category=Category.SECURITY.value,
                    severity=item.get('issue_severity', 'MEDIUM').lower(),
                    file=filename,
                    line=item.get('line_number', 0),
                    message=item.get('issue_text', ''),
                    rule_id=item.get('test_id', 'UNKNOWN'),
                    confidence=item.get('issue_confidence', 'UNKNOWN').lower(),
                    detected_by=[self.tool_name]
                ))
                
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings
            )
            
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message="Bandit executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
