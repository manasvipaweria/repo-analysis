import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter

class SemgrepAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "semgrep"

    @property
    def categories(self) -> List[str]:
        return [Category.SECURITY.value]

    def run(self, repo_path: str) -> ToolResult:
        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config=auto", "--json", "."],
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
                        error_message=f"Failed to parse Semgrep output: {result.stderr or result.stdout}"
                    )
                
            findings = []
            for item in output_data.get('results', []):
                filename = os.path.relpath(item.get('path', ''), repo_path)
                
                findings.append(Finding(
                    category=Category.SECURITY.value,
                    severity=item.get('extra', {}).get('severity', 'WARNING').lower(),
                    file=filename,
                    line=item.get('start', {}).get('line', 0),
                    message=item.get('extra', {}).get('message', ''),
                    rule_id=item.get('check_id', 'UNKNOWN'),
                    confidence=item.get('extra', {}).get('metadata', {}).get('confidence', 'UNKNOWN').lower(),
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
                error_message="Semgrep executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
