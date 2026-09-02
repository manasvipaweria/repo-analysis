import os
import subprocess
import json
import uuid
import openai
from typing import List, Dict, Any

from src.core.models import Finding, FindingLocation, FindingEvidence, ToolResult, ToolStatus, Category
from src.adapters.base import BaseAdapter

class ApniMandiDesignAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "apnimandi-design"
        
    @property
    def categories(self) -> List[str]:
        return [Category.QUALITY.value]
        
    def _run_semgrep_static(self, repo_path: str) -> List[Finding]:
        rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules", "apnimandi-design.yaml")
        if not os.path.exists(rules_path):
            print(f"Warning: Design rules not found at {rules_path}")
            return []
            
        cmd = ["semgrep", "scan", "--config", rules_path, "--json", repo_path]
        findings = []
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if not result.stdout.strip():
                return []
                
            data = json.loads(result.stdout)
            for raw_finding in data.get("results", []):
                file_path = raw_finding.get("path", "")
                line = raw_finding.get("start", {}).get("line", 0)
                message = raw_finding.get("extra", {}).get("message", "")
                rule_id = raw_finding.get("check_id", "apnimandi-design")
                snippet = raw_finding.get("extra", {}).get("lines", "")
                severity = "high" if raw_finding.get("extra", {}).get("severity", "WARNING") == "ERROR" else "medium"
                
                findings.append(Finding(
                    category=Category.QUALITY.value,
                    severity=severity,
                    file=file_path,
                    line=line,
                    message=message,
                    rule_id=rule_id,
                    detected_by=[self.tool_name],
                    code_context=snippet,
                    merge_blocking=(severity == "high")
                ))
        except Exception as e:
            print(f"[{self.tool_name}] Semgrep static analysis failed: {e}")
            
        return findings

    def _run_gemini_semantic(self, repo_path: str) -> List[Finding]:
        # Semantic checks via AI if requested
        # For this to run, we must have OPENAI_API_KEY (or GEMINI) and ENABLE_DESIGN_AI="true"
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return []
            
        try:
            client = openai.OpenAI(api_key=api_key)
            # Find main page files to review
            pages_context = ""
            for root, _, files in os.walk(repo_path):
                if "node_modules" in root or ".next" in root:
                    continue
                for file in files:
                    if file.endswith("page.tsx") or file.endswith("page.jsx"):
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, repo_path)
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()[:5000] # bounded
                            pages_context += f"\n--- {rel_path} ---\n{content}\n"
                            
            if not pages_context.strip():
                return []
                
            prompt = (
                "You are an expert design system reviewer enforcing the Apni Mandi Design System.\n"
                "Analyze the following React page components for semantic design violations.\n"
                "Focus on: 1) Multiple primary buttons in one view. 2) Using Mandi Green (primary) for generic success alerts. "
                "3) Using Mirchi (destructive) for non-critical alerts. 4) Bad copywriting (using 'Submit' instead of descriptive actions).\n\n"
                "Return a structured JSON object exactly like this:\n"
                "{\n"
                '  "findings": [\n'
                "    {\n"
                '      "file": "path",\n'
                '      "line": 10,\n'
                '      "message": "Found multiple primary buttons...",\n'
                '      "rule_id": "ai-semantic-buttons"\n'
                "    }\n"
                "  ]\n"
                "}\n\n"
                f"Context:\n{pages_context}"
            )
            
            response = client.chat.completions.create(
                model="gpt-4o",
                response_format={ "type": "json_object" },
                messages=[
                    {"role": "system", "content": "You enforce strict UI design semantic rules."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1500,
                temperature=0.1
            )
            
            data = json.loads(response.choices[0].message.content)
            findings = []
            for f in data.get("findings", []):
                findings.append(Finding(
                    category=Category.QUALITY.value,
                    severity="info",
                    file=f.get("file", "unknown"),
                    line=f.get("line", 0),
                    message=f.get("message", ""),
                    rule_id=f.get("rule_id", "ai-semantic-design"),
                    detected_by=[self.tool_name],
                    code_context="",
                    merge_blocking=False # AI checks are never merge blocking
                ))
            return findings
            
        except Exception as e:
            print(f"[{self.tool_name}] Semantic AI analysis failed: {e}")
            return []

    def run(self, repo_path: str) -> ToolResult:
        # 1. Run Static
        static_findings = self._run_semgrep_static(repo_path)
        
        # 2. Run Semantic (only if feature flag is ON)
        semantic_findings = []
        if os.environ.get("ENABLE_DESIGN_AI") == "true":
            semantic_findings = self._run_gemini_semantic(repo_path)
            
        all_findings = static_findings + semantic_findings
        
        if not all_findings:
            return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=[])
            
        return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=all_findings)
