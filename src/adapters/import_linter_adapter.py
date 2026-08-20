import subprocess
import os
import json
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import has_python_files

class ImportLinterAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "import-linter"

    @property
    def categories(self) -> List[str]:
        return [Category.ARCHITECTURE.value]

    def run(self, repo_path: str) -> ToolResult:
        if not has_python_files(repo_path):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="No Python files found."
            )

        try:
            # Check for config file loosely
            has_config = False
            for cfg in [".import_linter", "setup.cfg", "pyproject.toml"]:
                if os.path.exists(os.path.join(repo_path, cfg)):
                    # A better implementation would parse the file to check for [importlinter]
                    # For V1, we assume if it exists, they might have config, or the tool will tell us.
                    has_config = True
                    break
                    
            if not has_config:
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    error_message="No import-linter configuration file found."
                )
                
            result = subprocess.run(
                ["lint-imports"],
                cwd=repo_path,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            if "could not find any configuration" in result.stderr.lower() or "no contract" in result.stdout.lower():
                return ToolResult(
                    tool=self.tool_name,
                    status=ToolStatus.SKIPPED,
                    error_message="No import contracts defined."
                )
                
            findings = []
            if result.returncode != 0:
                # Basic parsing since import-linter doesn't have native JSON output easily
                findings.append(Finding(
                    category=Category.ARCHITECTURE.value,
                    severity="high",
                    file="architecture",
                    line=0,
                    message="Import boundary violation detected. Please run 'lint-imports' manually for details.",
                    rule_id="import_contract_violation",
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
                error_message="lint-imports executable not found."
            )
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
