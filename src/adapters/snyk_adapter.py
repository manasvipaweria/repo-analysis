import subprocess
import json
import os
import tempfile
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import has_js_ts_files

class SnykAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "snyk"

    @property
    def categories(self) -> List[str]:
        return [Category.DEPENDENCIES.value]

    def run(self, repo_path: str) -> ToolResult:
        if not has_js_ts_files(repo_path):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="No JS/TS manifests found."
            )
            
        if not os.environ.get("SNYK_TOKEN"):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="SNYK_TOKEN environment variable is not set. Snyk requires authentication."
            )

        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp_file:
            json_output_path = tmp_file.name

        try:
            # snyk test --all-projects --json-file-output=...
            cmd = ["snyk", "test", "--all-projects", f"--json-file-output={json_output_path}"]
            
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            # Snyk returns 0 if success and no vulns
            # returns 1 if success and vulns found
            # returns 2 or higher on error
            if result.returncode > 1 and not os.path.exists(json_output_path) or os.path.getsize(json_output_path) == 0:
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message=f"Snyk execution failed (code {result.returncode}): {result.stderr or result.stdout}"
                )
                
            with open(json_output_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                if not content.strip():
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.COMPLETED,
                        findings=[]
                    )
                output_data = json.loads(content)
                
            # If --all-projects is used, output_data might be a list of results per project
            if not isinstance(output_data, list):
                output_data = [output_data]
                
            findings = []
            for project in output_data:
                # Snyk project structure has a targetFile (e.g. package.json)
                target_file = project.get("displayTargetFile", "package.json").replace("\\", "/")
                
                vulnerabilities = project.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    vuln_id = vuln.get('id', 'UNKNOWN')
                    package_name = vuln.get('name', 'UNKNOWN')
                    package_version = vuln.get('version', 'UNKNOWN')
                    severity = vuln.get('severity', 'high').lower()
                    
                    # Extract best standard identifier
                    rule_id = vuln_id
                    identifiers = vuln.get('identifiers', {})
                    if identifiers.get('CVE'):
                        rule_id = identifiers['CVE'][0]
                    elif identifiers.get('GHSA'):
                        rule_id = identifiers['GHSA'][0]
                        
                    msg = vuln.get('title', 'Dependency Vulnerability')
                    msg += f" in {package_name}@{package_version}"
                    
                    finding = Finding(
                        category=Category.DEPENDENCIES.value,
                        severity=severity,
                        file=target_file,
                        line=0,
                        message=msg,
                        rule_id=rule_id,
                        detected_by=[self.tool_name]
                    )
                    findings.append(finding)
                    
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings
            )
            
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message="snyk executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
        finally:
            if os.path.exists(json_output_path):
                try:
                    os.remove(json_output_path)
                except Exception:
                    pass
