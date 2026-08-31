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
            
        cmd = [
            "npx", "-y", "@openai/codex-security", "scan", ".", 
            "--format", "json", 
            "--headless", 
            "--effort", "low", 
            "--max-cost", "2.00"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=900  # 15 minutes max
            )
            
            if result.returncode != 0:
                err_out = result.stderr.lower() + result.stdout.lower()
                # If access/auth fails, CLI usually returns a non-zero code and logs the error
                if any(k in err_out for k in ["unauthorized", "forbidden", "access denied", "401", "403"]):
                    return ToolResult(tool=self.tool_name, status=ToolStatus.SKIPPED, findings=[], error_message=f"Account lacks access (Auth error: {result.stderr.strip()[:100]})")
                # Sometimes it outputs JSON even on error, we can try to parse stdout
                if not result.stdout.strip():
                    return ToolResult(tool=self.tool_name, status=ToolStatus.ERROR, findings=[], error_message=f"CLI failed with code {result.returncode}. Stderr: {result.stderr[:200]}")
                    
            try:
                # Isolate JSON from possible npx warnings
                output = result.stdout
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
