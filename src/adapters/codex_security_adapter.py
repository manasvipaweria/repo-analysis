import json
import os
import subprocess
from typing import List

from src.adapters.base import BaseAdapter
from src.core.models import Finding, Category, FindingLocation, FindingEvidence, ToolResult, ToolStatus

class CodexSecurityAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "codex-security"
        
    @property
    def categories(self) -> List[str]:
        return [Category.SECURITY.value]
        
    def run(self, repo_path: str) -> ToolResult:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return ToolResult(tool=self.tool_name, status=ToolStatus.SKIPPED, findings=[], error_message="OPENAI_API_KEY not set")
            
        codex_home = os.environ.get("CODEX_HOME", os.path.expanduser("~/.codex"))
        scan_state_dir = os.path.join(codex_home, "state", "plugins", "codex-security", "scans")

        try:
            os.makedirs(scan_state_dir, exist_ok=True)
            test_file = os.path.join(scan_state_dir, f".write_test_{os.getpid()}")
            with open(test_file, "w") as f:
                f.write("test")
            if os.path.exists(test_file):
                os.remove(test_file)
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                findings=[],
                error_message=f"Scan state directory '{scan_state_dir}' is not writable: {e}"
            )

        cmd = [
            "npx", "-y", "@openai/codex-security", "scan", ".", 
            "--format", "json", 
            "--headless", 
            "--effort", "low", 
            "--max-cost", "10.00"
        ]
        
        # Scope scan paths to source directories to exclude node_modules from cost estimation
        sub_paths = []
        for p in ["backend", "frontend", "src"]:
            if os.path.isdir(os.path.join(repo_path, p)):
                sub_paths.extend(["--path", p])
        if sub_paths:
            cmd.extend(sub_paths)
            
        env = os.environ.copy()
        env["CODEX_HOME"] = codex_home
        if "CODEX_PERMISSION_PROFILE" not in env:
            env["CODEX_PERMISSION_PROFILE"] = ":workspace"
        
        try:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                env=env,
                timeout=900  # 15 minutes max
            )
            
            if result.returncode != 0:
                err_out = (result.stderr or "").lower() + (result.stdout or "").lower()
                # If access/auth fails, CLI usually returns a non-zero code and logs the error
                if any(k in err_out for k in ["unauthorized", "forbidden", "access denied", "http 401", "http 403"]):
                    return ToolResult(tool=self.tool_name, status=ToolStatus.SKIPPED, findings=[], error_message=f"Account lacks access (Auth error: {result.stderr.strip()[:100]})")
                
                stderr_summary = result.stderr.strip() if result.stderr and result.stderr.strip() else result.stdout.strip()
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.ERROR,
                    findings=[],
                    error_message=f"CLI failed with code {result.returncode}. Stderr: {stderr_summary[-500:]}"
                )
                    
            try:
                # Isolate JSON from possible npx warnings
                output = result.stdout or ""
                if "{" in output:
                    json_str = output[output.find("{"):]
                    data = json.loads(json_str)
                else:
                    return ToolResult(tool=self.tool_name, status=ToolStatus.ERROR, findings=[], error_message="No JSON output found")
            except json.JSONDecodeError:
                return ToolResult(tool=self.tool_name, status=ToolStatus.ERROR, findings=[], error_message=f"Failed to parse JSON. Output start: {result.stdout[:100]}")
                
            findings = []
            repo_findings = data.get("repositoryFindings", [])
            for raw_f in repo_findings:
                severity = raw_f.get("severity", "medium").lower()
                title = raw_f.get("title", "")
                description = raw_f.get("description", "")
                rule_id = raw_f.get("ruleId", "codex-sec-finding")
                
                # Parse location flexibly based on Sarif-like structures
                file_path = None
                line = 0
                locations = raw_f.get("locations", [])
                if locations and len(locations) > 0:
                    loc = locations[0]
                    file_path = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                    if not file_path:
                        file_path = loc.get("filePath")
                    
                    region = loc.get("physicalLocation", {}).get("region", {})
                    line = region.get("startLine", 0)
                    if not line:
                        line = loc.get("startLine", 0)
                        
                if not file_path:
                    file_path = raw_f.get("filePath", "unknown")
                    line = raw_f.get("startLine", 0)
                
                # Extract evidence if available
                snippet = raw_f.get("snippet", "")
                
                findings.append(Finding(
                    category=Category.SECURITY.value,
                    severity=severity,
                    file=file_path,
                    line=line,
                    message=f"{title}\n{description}".strip(),
                    rule_id=rule_id,
                    detected_by=[self.tool_name],
                    code_context=snippet
                ))
                
            return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=findings)
            
        except subprocess.TimeoutExpired:
            return ToolResult(tool=self.tool_name, status=ToolStatus.ERROR, findings=[], error_message="Scan timed out after 15 minutes.")
        except Exception as e:
            return ToolResult(tool=self.tool_name, status=ToolStatus.ERROR, findings=[], error_message=f"Unexpected error: {e}")
