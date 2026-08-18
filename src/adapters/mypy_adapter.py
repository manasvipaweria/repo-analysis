import subprocess
import os
import re
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter

class MypyAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "mypy"

    @property
    def categories(self) -> List[str]:
        return [Category.TYPING.value]

    def run(self, repo_path: str) -> ToolResult:
        try:
            result = subprocess.run(
                ["mypy", ".", "--show-error-codes"],
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            findings = []
            # file.py:42: error: Incompatible types [assignment]
            # Optional column: file.py:42:15: error: ...
            pattern = re.compile(r'^(.+?):(\d+):(?:(\d+):)? (error|note|warning): (.+) \[([^\]]+)\]$')
            
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                match = pattern.match(line)
                if match:
                    filename, row, col, severity, message, rule_id = match.groups()
                    if severity == 'note':
                        continue
                        
                    findings.append(Finding(
                        category=Category.TYPING.value,
                        severity="medium",
                        file=os.path.relpath(filename, repo_path) if os.path.isabs(filename) else filename,
                        line=int(row),
                        message=message.strip(),
                        rule_id=rule_id,
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
                error_message="mypy executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
