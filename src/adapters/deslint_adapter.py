import subprocess
import json
import os
from typing import List

from src.core.models import ToolResult, ToolStatus, Finding, Category
from src.adapters.base import BaseAdapter
from src.utils.project import is_react_project

class DeslintAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "deslint"

    @property
    def categories(self) -> List[str]:
        return [Category.QUALITY.value]

    def run(self, repo_path: str) -> ToolResult:
        if os.environ.get("ENABLE_DESLINT") != "true":
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="Deslint is opt-in. Set ENABLE_DESLINT=true to run."
            )

        if not is_react_project(repo_path):
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.SKIPPED,
                error_message="No React project detected."
            )

        # Build the allowlist of CSS properties that are legitimately inline because
        # they reference runtime values (width/height for charts, SVGs, canvas sizing)
        # or because the Apni Mandi design system doesn't have a Tailwind utility for them.
        #
        # Design-system findings based on dakiya.apnimandi.us/frontend/src/index.css:
        #   - Custom tokens: --success, --danger, --warning, --text-primary, --text-secondary,
        #                    --accent-blue, --border-color, --primary-light, --bg-app
        #   - Standard shadcn tokens: --primary, --secondary, --muted, --card, --background, etc.
        #   - Radius scale:  --radius (0.5rem), with sm/md/lg/xl variants
        #   - Fonts: --font-body (Plus Jakarta Sans), --font-display (Bricolage Grotesque)
        #
        # Rules selected rationale:
        #   no-inline-styles (warn, allowDynamic:true):
        #       Flag static style={{}} objects only. allowDynamic:true means the rule
        #       already skips computed values (identifiers, conditionals, template literals
        #       with expressions) — so charts, progress bars, transforms are not flagged.
        #       allowlist: CSS properties that have NO direct Tailwind v4 equivalent in
        #       the Apni Mandi theme (gridTemplateColumns, gap computed values, SVG attrs).
        #
        #   no-arbitrary-colors (warn):
        #       Flags bg-[#hex] in className. Legitimate — Apni Mandi has semantic tokens.
        #       Does NOT flag var(--token) usage (those are correct).
        #
        #   no-arbitrary-spacing (warn):
        #       Flags p-[23px] style arbitrary values in className. Tailwind v4 4px grid
        #       should be used. Single instance in TestArbitrary.jsx = test file.
        #
        #   no-arbitrary-typography (warn):
        #       Same as above for text-[15px]. Single instance in TestArbitrary.jsx.
        #
        #   responsive-required (warn):
        #       Flags fixed-width arbitrary Tailwind classes (w-[500px]) that break mobile.
        #       Single instance in TestArbitrary.jsx. Low noise, high signal.
        #
        #   consistent-border-radius (off):
        #       The Apni Mandi CSS uses 5px, 8px, 10px, 12px, 16px, 20px, 100px all
        #       legitimately in different contexts (pill vs card vs avatar vs badge).
        #       This rule would fire ~50+ times with zero actionable signal. OFF.
        #
        #   consistent-component-spacing (off):
        #       Mixed spacing is intentional (0.4rem pill vs 1.2rem card). OFF.
        #
        #   missing-states (off):
        #       Too opinionated without knowing which components need states. OFF.
        #
        #   a11y-color-contrast (off):
        #       Useful but requires theme-aware color resolution. Without knowing oklch
        #       values of all combinations, produces false positives. OFF for now.

        config_content = """import deslint from '@deslint/eslint-plugin';

export default [
  {
    files: ['**/*.{js,jsx,ts,tsx}'],
    ignores: ['**/__tests__/**', '**/node_modules/**', '**/*.test.*', '**/*.spec.*'],
    plugins: { deslint },
    rules: {
      // ── Design-system inline style enforcement ───────────────────────────────
      // allowDynamic:true (default) already skips dynamic expressions:
      //   style={{ width: `${val}px` }}  ← skipped (TemplateLiteral with expr)
      //   style={{ color: statusColor }} ← skipped (Identifier)
      //   style={{ opacity: isActive ? 1 : 0.5 }} ← skipped (ConditionalExpression)
      //
      // allowlist: properties with NO Tailwind v4 equivalent in this project.
      //   'gridTemplateColumns' → complex computed grids
      //   'strokeDasharray', 'strokeDashoffset' → SVG animation properties
      //   'willChange' → performance hints
      //   'WebkitOverflowScrolling' → legacy Safari scrolling
      'deslint/no-inline-styles': ['warn', {
        allowDynamic: true,
        allowlist: [
          'gridTemplateColumns',
          'gridColumn',
          'gridRow',
          'strokeDasharray',
          'strokeDashoffset',
          'willChange',
          'WebkitOverflowScrolling',
          'animationDelay',
          'animationDuration'
        ]
      }],

      // ── Arbitrary Tailwind value detection ───────────────────────────────────
      // These catch bg-[#hex], p-[23px], text-[15px] in className strings.
      // Apni Mandi has full semantic token coverage so arbitrary values bypass the theme.
      'deslint/no-arbitrary-colors': 'warn',
      'deslint/no-arbitrary-spacing': 'warn',
      'deslint/no-arbitrary-typography': 'warn',

      // ── Responsive design ────────────────────────────────────────────────────
      // Flags fixed-width Tailwind arbitrary classes (w-[500px]) without
      // responsive variants. Only fires when there's deterministic evidence.
      'deslint/responsive-required': 'warn',

      // ── OFF: require design-system context or too noisy ──────────────────────
      // consistent-border-radius: Apni Mandi legitimately uses 5/8/10/12/16/20/100px
      //   in different contexts. Would produce 50+ low-signal findings.
      'deslint/consistent-border-radius': 'off',

      // consistent-component-spacing: Mixed intentional spacing across card vs pill.
      'deslint/consistent-component-spacing': 'off',

      // missing-states: Too opinionated without explicit component contracts.
      'deslint/missing-states': 'off',

      // a11y-color-contrast: Requires resolved oklch values, not string tokens.
      //   Cannot deterministically verify var(--primary) contrast without rendering.
      'deslint/a11y-color-contrast': 'off'
    },
    languageOptions: {
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        ecmaFeatures: { jsx: true }
      }
    }
  }
];
"""
        react_dir = repo_path
        for root_dir, dirs, files in os.walk(repo_path):
            if 'node_modules' in dirs:
                dirs.remove('node_modules')
            if 'package.json' in files:
                try:
                    with open(os.path.join(root_dir, 'package.json'), 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                        if 'react' in deps or 'react-dom' in deps:
                            react_dir = root_dir
                            break
                except Exception:
                    pass

        config_path = os.path.join(react_dir, ".deslint.config.mjs")
        
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(config_content)
                
            cmd = "npx eslint -c .deslint.config.mjs . -f json"
            result = subprocess.run(
                cmd,
                cwd=react_dir,
                capture_output=True,
                shell=True,
                text=True, encoding="utf-8", errors="replace"
            )
            
            if not result.stdout.strip():
                if result.returncode != 0:
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"ESLint failed with exit code {result.returncode}: {result.stderr.strip()[:500]}"
                    )
                output_data = []
            else:
                try:
                    output_data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    error_src = result.stderr if result.stderr.strip() else result.stdout
                    return ToolResult(
                        tool=self.tool_name,
                        status=ToolStatus.ERROR,
                        error_message=f"Failed to parse ESLint JSON (exit code {result.returncode}): {error_src.strip()[:500]}"
                    )
            
            findings = []
            for file_result in output_data:
                file_path = file_result.get("filePath", "")
                abs_file_path = file_path  # keep full path for classifier
                if file_path.startswith(repo_path):
                    file_path = os.path.relpath(file_path, repo_path).replace("\\", "/")
                    
                for msg in file_result.get("messages", []):
                    rule_id = msg.get("ruleId") or ""
                    if not rule_id.startswith("deslint/"):
                        continue

                    line_no = msg.get("line", 0)

                    # ── Inline-style classification ───────────────────────────
                    # For no-inline-styles findings only, attempt to classify the
                    # finding into one of four categories using the verified
                    # Apni Mandi design-system mapping. Does not modify Dakiya source.
                    classification = None
                    suggested_migration = None
                    if rule_id == "deslint/no-inline-styles":
                        try:
                            from src.adapters.deslint_classifier import classify_inline_style
                            result_cls = classify_inline_style(abs_file_path, line_no)
                            classification = result_cls.category
                            suggested_migration = result_cls.suggested_migration
                        except Exception:
                            classification = "UNCATEGORIZED"

                    from src.core.models import FindingEvidence
                    findings.append(Finding(
                        category=Category.QUALITY.value,
                        severity="medium",
                        file=file_path,
                        line=line_no,
                        message=msg.get("message", "Deslint finding"),
                        rule_id=rule_id,
                        detected_by=[self.tool_name],
                        evidence=FindingEvidence(
                            classification=classification,
                            suggested_migration=suggested_migration,
                        )
                    ))
                    
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.COMPLETED,
                findings=findings
            )
            
        except Exception as e:
            return ToolResult(
                tool=self.tool_name,
                status=ToolStatus.ERROR,
                error_message=str(e)
            )
        finally:
            if os.path.exists(config_path):
                os.remove(config_path)
