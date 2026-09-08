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
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            print(f"[{self.tool_name}] GEMINI_API_KEY not set - skipping AI semantic check")
            return []
            
        try:
            import requests
            import subprocess
            
            extractor_script = os.path.join(os.path.dirname(__file__), "extract_ui_context.js")
            
            pages_context = ""
            matched_files = []
            
            # 1. Discover files
            for root, _, files in os.walk(repo_path):
                skip_dirs = ["node_modules", ".next", "dist", "build", "coverage", "__tests__", ".git"]
                if any(d in root for d in skip_dirs):
                    continue
                for file in files:
                    if file.lower().endswith(self.DESIGN_FILE_SUFFIXES):
                        full_path = os.path.join(root, file)
                        rel_path = os.path.relpath(full_path, repo_path)
                        matched_files.append(full_path)
            
            print(f"[{self.tool_name}] Design files discovered: {len(matched_files)}")
            
            if not matched_files:
                return []
                
            # 2. Extract UI Context
            for full_path in matched_files:
                rel_path = os.path.relpath(full_path, repo_path)
                try:
                    result = subprocess.run(["node", extractor_script, full_path], capture_output=True, text=True, check=True)
                    ui_map = result.stdout.strip()
                    if ui_map:
                        pages_context += f"\n--- FILE: {rel_path} ---\n{ui_map}\n"
                except subprocess.CalledProcessError as e:
                    print(f"[{self.tool_name}] Failed to extract UI context for {rel_path}: {e.stderr}")
                    continue
                    
            if not pages_context.strip():
                print(f"[{self.tool_name}] No UI context extracted - skipping AI semantic check")
                return []

            system_instruction = (
                "You are an expert UX and UI Design System reviewer evaluating React applications.\n"
                "Your goal is to find high-signal, semantic design and UX problems based on the application's UI structure and behavior.\n"
                "Do NOT report simple deterministic issues (like raw formatting, basic inline styles, or exact Tailwind syntax).\n"
                "Focus on semantic reasoning: visual hierarchy, component consistency across the app, UX clarity, semantic accessibility concerns, and responsive UX.\n\n"
                "Apni Mandi Design System Context:\n"
                "- Colors (Shadcn standard utilities): primary, secondary, muted, accent, destructive, background, foreground, border, card.\n"
                "- Custom Colors (CSS variables): --success, --danger, --warning, --text-primary, --text-secondary, --border-color, --primary-light.\n"
                "- Typography: font-body (Plus Jakarta Sans), font-display (Bricolage Grotesque), font-mono (Geist Mono).\n"
                "- Spacing: Standard Tailwind 4px grid.\n"
                "- Border radius: standard Tailwind rounded classes and --radius token.\n"
                "- Use semantic components (e.g. <Button>, <Card>, <Input>, <Badge>) where possible rather than raw elements.\n\n"
                "Guidelines:\n"
                "1. If multiple primary actions exist with identical visual emphasis in the same view, flag it as a visual hierarchy issue.\n"
                "2. If similar UI areas use completely different interaction patterns or layouts without reason, flag component consistency.\n"
                "3. If a form is missing clear labels or grouping, flag UX clarity.\n"
                "4. If interactive icons lack accessible names or text, flag accessibility.\n"
                "5. If a stateful component has 'loading' or 'error' state variables but no visible UI branches to handle them, flag state handling.\n"
                "6. DO NOT invent findings if the UI Context Map looks reasonable.\n"
                "7. ONLY report findings that require semantic/human-like reasoning."
            )
            
            prompt = (
                "Review the following UI Context Maps extracted from the React application.\n"
                "The maps show the component signatures, state variables, event handlers, and the JSX UI hierarchy (filtered to show meaningful elements, conditions, and classes).\n\n"
                f"{pages_context}\n\n"
                "Return a structured JSON object with your findings:\n"
                "{\n"
                '  "findings": [\n'
                "    {\n"
                '      "file": "path/to/file",\n'
                '      "line": 10,\n'
                '      "message": "Clear description of the semantic design issue and why it harms UX.",\n'
                '      "rule_id": "gemini/design-hierarchy",\n'
                '      "severity": "medium",\n'
                '      "category": "Quality",\n'
                '      "confidence": "high",\n'
                '      "recommendation": "How to fix it"\n'
                "    }\n"
                "  ]\n"
                "}\n\n"
                "IMPORTANT: If there are no meaningful semantic issues, return an empty findings array []. Do NOT invent trivial issues."
            )
            
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key={api_key}"
            payload = {
                "system_instruction": {
                    "parts": [{"text": system_instruction}]
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
            
            usage = data.get("usageMetadata", {})
            input_tokens = usage.get("promptTokenCount", 0)
            output_tokens = usage.get("candidatesTokenCount", 0)
            print(f"[{self.tool_name}] AI Token Usage - Input: {input_tokens} | Output: {output_tokens} | Total: {input_tokens + output_tokens}")
            
            candidates = data.get("candidates", [])
            if not candidates:
                return []
            candidate = candidates[0]
            finish_reason = candidate.get("finishReason", "UNKNOWN")
            if finish_reason not in ("STOP", "MAX_TOKENS"):
                return []
            parts = candidate.get("content", {}).get("parts", [])
            if not parts:
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
                    category=f.get("category", Category.QUALITY.value),
                    severity=f.get("severity", "medium"),
                    file=f.get("file", "unknown"),
                    line=f.get("line", 0),
                    message=f.get("message", ""),
                    rule_id=f.get("rule_id", "gemini/semantic-design"),
                    detected_by=[self.tool_name],
                    code_context=f.get("recommendation", ""),
                    merge_blocking=False
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
