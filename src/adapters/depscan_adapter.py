import subprocess
import json
import os
import glob
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import has_js_ts_files

class DepScanAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "dep-scan"

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

        reports_dir = os.path.join(repo_path, "reports_depscan")
        timeout_seconds = int(os.environ.get("DEPSCAN_TIMEOUT_SECONDS", 600))
        
        try:
            cmd = ["depscan", "--src", repo_path, "--reports-dir", reports_dir]
            
            try:
                result = subprocess.run(
                    cmd,
                    cwd=repo_path,
                    capture_output=True,
                    text=True, encoding="utf-8", errors="replace",
                    timeout=timeout_seconds
                )
            except subprocess.TimeoutExpired as e:
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    error_message=f"dep-scan execution timed out after {timeout_seconds} seconds."
                )
            
            findings = []
            
            # DepScan writes depscan-*.json in the reports directory
            if os.path.isdir(reports_dir):
                json_files = glob.glob(os.path.join(reports_dir, "depscan-*.json"))
                for json_file in json_files:
                    with open(json_file, 'r', encoding='utf-8', errors='replace') as f:
                        # Some versions of dep-scan write NDJSON (JSON-lines), some write JSON arrays.
                        # We'll handle both.
                        content = f.read().strip()
                        if not content:
                            continue
                            
                        items = []
                        if content.startswith('['):
                            items = json.loads(content)
                        else:
                            items = [json.loads(line) for line in content.splitlines() if line.strip()]
                            
                        for item in items:
                            vuln_id = item.get("id", "UNKNOWN")
                            pkg = item.get("package", "UNKNOWN")
                            version = item.get("version", "UNKNOWN")
                            severity = item.get("severity", "high").lower()
                            
                            # Standardize rule_id to CVE or GHSA if possible
                            rule_id = vuln_id
                            
                            msg = f"{item.get('short_description', 'Dependency Vulnerability')} in {pkg}@{version}"
                            
                            # Dep-scan sometimes gives a manifest path, or we default
                            manifest = item.get("manifest", "package.json")
                            if manifest.startswith(repo_path):
                                manifest = os.path.relpath(manifest, repo_path).replace("\\", "/")
                                
                            findings.append(Finding(
                                category=Category.DEPENDENCIES.value,
                                severity=severity,
                                file=manifest,
                                line=0,
                                message=msg,
                                rule_id=rule_id,
                                detected_by=[self.tool_name]
                            ))
                            
            # Clean up reports directory
            import shutil
            shutil.rmtree(reports_dir, ignore_errors=True)
                            
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings
            )
            
        except FileNotFoundError:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message="depscan executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
