import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter

class RuffAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "ruff"

    @property
    def categories(self) -> List[str]:
        return [Category.QUALITY.value]

    def run(self, repo_path: str) -> ToolResult:
        try:
            # Ruff might exit with 1 if there are lint errors
            result = subprocess.run(
                ["ruff", "check", ".", "--output-format", "json"],
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If there are no issues and it outputs something else, or if there's a real error
                if not result.stdout.strip():
                    output_data = []
                else:
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"Failed to parse Ruff output: {result.stderr or result.stdout}"
                    )
                
            findings = []
            for item in output_data:
                filename = os.path.relpath(item.get('filename', ''), repo_path)
                row = item.get('location', {}).get('row', 0)
                
                findings.append(Finding(
                    category=Category.QUALITY.value,
                    severity="medium",
                    file=filename,
                    line=row,
                    message=item.get('message', ''),
                    rule_id=item.get('code', 'UNKNOWN'),
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
                error_message="Ruff executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
