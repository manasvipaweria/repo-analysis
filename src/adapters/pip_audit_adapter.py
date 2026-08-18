import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter

class PipAuditAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "pip-audit"

    @property
    def categories(self) -> List[str]:
        return [Category.DEPENDENCIES.value]

    def run(self, repo_path: str) -> ToolResult:
        try:
            cmd = ["pip-audit", "-f", "json"]
            req_file = os.path.join(repo_path, 'requirements.txt')
            
            if os.path.exists(req_file):
                cmd.extend(["-r", "requirements.txt"])
            else:
                # If there's no requirements.txt, pip-audit will scan the current environment,
                # which isn't the repo. Better to skip.
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    error_message="No requirements.txt found to audit."
                )

            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            try:
                output_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                if "No dependencies found" in result.stderr or not result.stdout.strip():
                    output_data = []
                else:
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"Failed to parse pip-audit output: {result.stderr or result.stdout}"
                    )
                
            findings = []
            
            # Pip audit json output is a list of results, e.g. [{"name": "requests", "version": "...", "vulns": [...]}]
            # Or dictionary if there's an error. 
            if isinstance(output_data, dict) and 'dependencies' in output_data:
                items = output_data['dependencies']
            elif isinstance(output_data, list):
                items = output_data
            else:
                items = []
                
            for item in items:
                pkg_name = item.get('name', 'unknown')
                version = item.get('version', 'unknown')
                for vuln in item.get('vulns', []):
                    findings.append(Finding(
                        category=Category.DEPENDENCIES.value,
                        severity="high", # pip-audit default
                        file="requirements.txt",
                        line=0,
                        message=f"Vulnerable dependency {pkg_name} ({version}): {vuln.get('description', '')} / {vuln.get('fix_versions', [])}",
                        rule_id=vuln.get('id', 'UNKNOWN'),
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
                error_message="pip-audit executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
