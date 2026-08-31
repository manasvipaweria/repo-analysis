import json
import os
from typing import List

try:
    import openai
except ImportError:
    openai = None

from src.adapters.base import BaseAdapter
from src.core.models import Finding, Category, FindingLocation, FindingEvidence, ToolResult, ToolStatus

class CodexArchitectureAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "codex-architecture"
        
    @property
    def categories(self) -> List[str]:
        return [Category.ARCHITECTURE.value]
        
    def _build_context(self, repo_path: str) -> str:
        context_parts = []
        
        # 1. Directory Tree (max 3 levels deep)
        context_parts.append("### Directory Structure:")
        try:
            for root, dirs, files in os.walk(repo_path):
                # Ignore common hidden/build dirs
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'dist', 'build', '__pycache__')]
                
                rel_path = os.path.relpath(root, repo_path)
                level = rel_path.count(os.sep) if rel_path != '.' else 0
                if level > 2:
                    continue
                    
                indent = '  ' * level
                context_parts.append(f"{indent}{os.path.basename(root) if rel_path != '.' else '.'}/")
                subindent = '  ' * (level + 1)
                for f in files:
                    if not f.startswith('.'):
                        context_parts.append(f"{subindent}{f}")
        except Exception as e:
            context_parts.append(f"Error reading tree: {e}")
            
        # 2. Key structural files (if they exist)
        structural_files = [
            'package.json', 'pom.xml', 'docker-compose.yml', 
            'README.md', 'architecture.md', 'requirements.txt'
        ]
        
        for sf in structural_files:
            sf_path = os.path.join(repo_path, sf)
            if os.path.isfile(sf_path):
                try:
                    with open(sf_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        # Truncate if too long (e.g. giant package.json)
                        if len(content) > 5000:
                            content = content[:5000] + "\n...[truncated]..."
                        context_parts.append(f"\n### {sf}:\n```\n{content}\n```")
                except Exception:
                    pass
                    
        return "\n".join(context_parts)
        
    def run(self, repo_path: str) -> ToolResult:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return ToolResult(tool=self.tool_name, status=ToolStatus.SKIPPED, findings=[], error_message="OPENAI_API_KEY not set")
            
        if openai is None:
            return ToolResult(tool=self.tool_name, status=ToolStatus.SKIPPED, findings=[], error_message="'openai' Python package not installed")
            
        client = openai.OpenAI(api_key=api_key)
        
        context = self._build_context(repo_path)
        
        prompt = (
            "Analyze the following repository structure and structural files to determine its architecture.\n"
            "Return a structured JSON object with the following schema exactly:\n"
            "{\n"
            '  "hld_summary": "High level design summary...",\n'
            '  "lld_summary": "Low level design summary...",\n'
            '  "recommended_target_architecture": "Target architecture recommendation...",\n'
            '  "findings": [\n'
            "    {\n"
            '      "category": "architecture",\n'
            '      "severity": "medium",\n'
            '      "file": "file path if applicable, or general",\n'
            '      "line": 0,\n'
            '      "message": "Finding description",\n'
            '      "rule_id": "rule_id_name"\n'
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Here is the context:\n"
            f"{context}"
        )
        
        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                response_format={ "type": "json_object" },
                messages=[
                    {"role": "system", "content": "You are an expert software architect analyzing a codebase."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.2,
                timeout=60
            )
            
            content = response.choices[0].message.content
            if not content:
                return ToolResult(tool=self.tool_name, status=ToolStatus.ERROR, findings=[], error_message="Empty response from OpenAI")
                
            data = json.loads(content)
            findings_data = data.get("findings", [])
            
            findings = []
            
            hld = data.get("hld_summary", "")
            lld = data.get("lld_summary", "")
            target_arch = data.get("recommended_target_architecture", "")
            
            summary_desc = f"HLD: {hld}\n\nLLD: {lld}\n\nRecommended: {target_arch}"
            
            findings.append(Finding(
                category=Category.ARCHITECTURE.value,
                severity="info",
                file="repository_architecture",
                line=0,
                message=summary_desc.strip(),
                rule_id="arch-summary",
                detected_by=[self.tool_name],
                code_context=""
            ))
            
            for raw_f in findings_data:
                findings.append(Finding(
                    category=Category.ARCHITECTURE.value,
                    severity=raw_f.get("severity", "medium").lower(),
                    file=raw_f.get("file", "unknown"),
                    line=raw_f.get("line", 0),
                    message=raw_f.get("message", ""),
                    rule_id=raw_f.get("rule_id", "arch-finding"),
                    detected_by=[self.tool_name],
                    code_context=""
                ))
                
            return ToolResult(tool=self.tool_name, status=ToolStatus.COMPLETED, findings=findings)
            
        except Exception as e:
            return ToolResult(tool=self.tool_name, status=ToolStatus.ERROR, findings=[], error_message=f"Unexpected error during API call: {e}")
