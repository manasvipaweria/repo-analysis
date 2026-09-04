import os
import subprocess
import json
import uuid
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

    # Case-insensitive suffixes covering Next.js, CRA, Vite, and plain JS conventions
    DESIGN_FILE_SUFFIXES = (
        "page.tsx", "page.jsx", "page.js",
        "layout.tsx", "layout.jsx", "layout.js",
        "app.jsx", "app.tsx", "app.js",
    )

    def _run_ai_semantic(self, repo_path: str) -> List[Finding]:
        # Semantic checks via AI if requested
        # For this to run, we must have GEMINI_API_KEY and ENABLE_DESIGN_AI="true"
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            print(f"[{self.tool_name}] GEMINI_API_KEY not set — skipping AI semantic check")
            return []
            
        try:
            import requests
            # Find main page/app files — case-insensitive, covers .js/.jsx/.tsx
            pages_context = ""
            matched_files = []
            for root, _, files in os.walk(repo_path):
                skip_dirs = ["node_modules", ".next", "dist", "build", "coverage", "__tests__", ".git"]
                if any(d in root for d in skip_dirs):
                    continue
                for file in files:
                    if file.lower().endswith(self.DESIGN_FILE_SUFFIXES):
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, repo_path)
                        matched_files.append(rel_path)
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                            raw = fh.read()
                            if len(raw) > 20000:
                                print(f"[{self.tool_name}] File {rel_path} truncated to 20000 chars (actual: {len(raw)} chars)")
                            content = raw[:20000]
                            pages_context += f"\n--- {rel_path} ---\n{content}\n"

            # Explicit log so discovery failures are visible in CI logs
            print(f"[{self.tool_name}] Design files discovered: {matched_files if matched_files else 'NONE'}")

            if not pages_context.strip():
                print(f"[{self.tool_name}] No matching design files found under {repo_path} — skipping AI semantic check")
                return []
                
            prompt = (
                "You are a strict UI Design System enforcer reviewing legacy React code.\n"
                "Your job is to aggressively FIND design system violations in the provided code.\n"
                "FLAG THE FOLLOWING VIOLATIONS:\n"
                "1. ANY use of inline styles (e.g. style={{ background: '#...' }}). All styling must use CSS classes or Tailwind.\n"
                "2. ANY use of raw HTML <button> tags instead of a unified <Button> component.\n"
                "3. Multiple primary action buttons in the same view.\n"
                "4. Bad copywriting (e.g. using generic words like 'Submit' instead of descriptive actions).\n\n"
                "Return a structured JSON object exactly like this:\n"
                "{\n"
                '  "findings": [\n'
                "    {\n"
                '      "file": "path",\n'
                '      "line": 10,\n'
                '      "message": "Found raw HTML <button> tag. Must use unified <Button> component.",\n'
                '      "rule_id": "ai-semantic-legacy-element"\n'
                "    }\n"
                "  ]\n"
                "}\n\n"
                f"Context:\n{pages_context}"
            )
            
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key={api_key}"
            payload = {
                "system_instruction": {
                    "parts": [{"text": "You enforce strict UI design semantic rules."}]
                },
                "contents": [
                    {"parts": [{"text": prompt}]}
                ],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "temperature": 0.1
                }
            }
            
            response = requests.post(url, json=payload, headers={"Content-Type": "application/json"})
            if response.status_code != 200:
                print(f"[{self.tool_name}] Gemini API error: {response.status_code} {response.text}")
                return []
                
            data = response.json()
            
            # Token Tracking & Logging
            usage = data.get("usageMetadata", {})
            input_tokens = usage.get("promptTokenCount", 0)
            output_tokens = usage.get("candidatesTokenCount", 0)
            print(f"[{self.tool_name}] AI Token Usage - Input: {input_tokens} | Output: {output_tokens} | Total: {input_tokens + output_tokens}")
            
            # Safe response parsing — guard against safety-filtered/malformed candidates
            candidates = data.get("candidates", [])
            if not candidates:
                print(f"[{self.tool_name}] Gemini returned no candidates (possible safety filter). Raw: {data}")
                return []
            candidate = candidates[0]
            finish_reason = candidate.get("finishReason", "UNKNOWN")
            if finish_reason not in ("STOP", "MAX_TOKENS"):
                print(f"[{self.tool_name}] Unexpected finishReason: {finish_reason}. Skipping.")
                return []
            parts = candidate.get("content", {}).get("parts", [])
            if not parts:
                print(f"[{self.tool_name}] Gemini candidate had empty parts. Raw: {candidate}")
                return []
            text_response = parts[0].get("text", "{}")
            try:
                result_json = json.loads(text_response)
            except json.JSONDecodeError as je:
                print(f"[{self.tool_name}] Failed to parse Gemini JSON: {je}. Raw: {text_response[:500]}")
                return []
            
            findings = []
            for f in result_json.get("findings", []):
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
            semantic_findings = self._run_ai_semantic(repo_path)
            
        all_findings = static_findings + semantic_findings
        
        if not all_findings:
            return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=[])
            
        return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=all_findings)
