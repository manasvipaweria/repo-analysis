import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import is_react_project

class ReactDoctorAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "react-doctor"

    @property
    def categories(self) -> List[str]:
        return [Category.QUALITY.value]

    def run(self, repo_path: str) -> ToolResult:
        if not is_react_project(repo_path):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="No React project detected."
            )

        try:
            # We assume react-doctor supports a --json flag or similar standard output
            cmd = ["npx", "react-doctor", "--format", "json"]
            
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            try:
                # Eslint-like JSON array
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                if not result.stdout.strip():
                    output_data = []
                else:
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"Failed to parse react-doctor output: {result.stderr or result.stdout}"
                    )
            
            findings = []
            
            # Format depends on actual react-doctor JSON format
            # We assume it follows an eslint-like format since it's common for React tools
            for file_result in output_data:
                file_path = file_result.get("filePath", "")
                if file_path.startswith(repo_path):
                    file_path = os.path.relpath(file_path, repo_path).replace("\\", "/")
                    
                messages = file_result.get("messages", [])
                for msg in messages:
                    severity_num = msg.get("severity", 1)
                    if severity_num == 2:
                        severity = "high"
                    elif severity_num == 1:
                        severity = "medium"
                    else:
                        severity = "low"
                        
                    findings.append(Finding(
                        category=Category.QUALITY.value,
                        severity=severity,
                        file=file_path,
                        line=msg.get("line", 0),
                        message=msg.get("message", "React Doctor finding"),
                        rule_id=msg.get("ruleId", "react-doctor-rule"),
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
                error_message="npx executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
