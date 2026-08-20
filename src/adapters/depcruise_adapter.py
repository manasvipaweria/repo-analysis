import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import has_js_ts_files

class DepcruiseAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "dependency-cruiser"

    @property
    def categories(self) -> List[str]:
        return [Category.ARCHITECTURE.value]

    def run(self, repo_path: str) -> ToolResult:
        if not has_js_ts_files(repo_path):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="No JS/TS files found."
            )

        config_files = ['.dependency-cruiser.js', '.dependency-cruiser.cjs', '.dependency-cruiser.json']
        has_config = any(os.path.exists(os.path.join(repo_path, c)) for c in config_files)
        
        cmd = ["npx", "dependency-cruiser", ".", "--output-type", "json"]
        
        if not has_config:
            # Fall back to default central configuration
            central_config = os.path.abspath(
                os.path.join(os.path.dirname(__file__), '..', '..', 'configs', '.dependency-cruiser.js')
            )
            if not os.path.exists(central_config):
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message="No local dependency-cruiser configuration found, and central default is missing."
                )
            cmd.extend(["--config", central_config])

        try:
            
            result = subprocess.run(
                cmd,
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
                        error_message=f"Failed to parse dependency-cruiser output: {result.stderr or result.stdout}"
                    )
            
            findings = []
            summary = output_data.get('summary', {})
            violations = summary.get('violations', [])
            
            for violation in violations:
                rule_name = violation.get('rule', {}).get('name', 'UNKNOWN')
                severity = violation.get('rule', {}).get('severity', 'warn')
                
                # depcruise uses warn/error/info
                if severity == "error":
                    normalized_severity = "high"
                elif severity == "warn":
                    normalized_severity = "medium"
                else:
                    normalized_severity = "low"
                    
                from_path = violation.get('from', '').replace("\\", "/")
                to_path = violation.get('to', '').replace("\\", "/")
                
                msg = f"Dependency violation ({rule_name}): {from_path} -> {to_path}"
                
                findings.append(Finding(
                    category=Category.ARCHITECTURE.value,
                    severity=normalized_severity,
                    file=from_path,
                    line=0,
                    message=msg,
                    rule_id=rule_name,
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
                error_message="npx or dependency-cruiser executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
