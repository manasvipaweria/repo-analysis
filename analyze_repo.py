import argparse
import sys
import os

from src.core.orchestrator import Orchestrator
from src.core.output import write_json_report, write_csv_report
from src.utils.git import clone_repo, cleanup_repo

from src.adapters.ruff_adapter import RuffAdapter
from src.adapters.bandit_adapter import BanditAdapter
from src.adapters.semgrep_adapter import SemgrepAdapter
from src.adapters.pip_audit_adapter import PipAuditAdapter
from src.adapters.mypy_adapter import MypyAdapter
from src.adapters.pytest_adapter import PytestAdapter
from src.adapters.import_linter_adapter import ImportLinterAdapter
from src.adapters.snyk_adapter import SnykAdapter
from src.adapters.depscan_adapter import DepScanAdapter
from src.adapters.depcruise_adapter import DepcruiseAdapter
from src.adapters.sonarqube_adapter import SonarQubeAdapter
from src.adapters.react_doctor_adapter import ReactDoctorAdapter
from src.adapters.codex_security_adapter import CodexSecurityAdapter
from src.adapters.codex_architecture_adapter import CodexArchitectureAdapter
from src.adapters.design_adapter import ApniMandiDesignAdapter
from src.adapters.deslint_adapter import DeslintAdapter

ALL_ADAPTERS = {
    "ruff": RuffAdapter(),
    "bandit": BanditAdapter(),
    "semgrep": SemgrepAdapter(),
    "pip-audit": PipAuditAdapter(),
    "mypy": MypyAdapter(),
    "pytest": PytestAdapter(),
    "import-linter": ImportLinterAdapter(),
    "snyk": SnykAdapter(),
    "dep-scan": DepScanAdapter(),
    "dependency-cruiser": DepcruiseAdapter(),
    "sonarqube": SonarQubeAdapter(),
    "react-doctor": ReactDoctorAdapter(),
    "codex-security": CodexSecurityAdapter(),
    "codex-architecture": CodexArchitectureAdapter(),
    "apnimandi-design": ApniMandiDesignAdapter(),
    "deslint": DeslintAdapter(),
}

def main():
    parser = argparse.ArgumentParser(description="Unified Repo Analysis Orchestrator")
    parser.add_argument("repo_url", help="URL of the git repository to analyze (or local path)")
    parser.add_argument("--repo-name", help="Identifier for the report (e.g. repo URL or name) when analyzing a local path", default=None)
    parser.add_argument("--branch", help="Branch or commit to checkout", default=None)
    parser.add_argument(
        "--tools", 
        help="Comma-separated list of tools to run. Defaults to all available.",
        default=",".join(ALL_ADAPTERS.keys())
    )
    parser.add_argument("--output", help="Comma-separated list of outputs (json,csv)", default="json,csv")
    parser.add_argument("--run-ai", action="store_true", help="Run the AI analysis stage after scanner execution")
    
    args = parser.parse_args()
    
    tools_to_run = [t.strip() for t in args.tools.split(",") if t.strip()]
    invalid_tools = [t for t in tools_to_run if t not in ALL_ADAPTERS]
    if invalid_tools:
        print(f"Error: Invalid tools specified: {', '.join(invalid_tools)}")
        print(f"Available tools: {', '.join(ALL_ADAPTERS.keys())}")
        sys.exit(1)
        
    adapters = [ALL_ADAPTERS[t] for t in tools_to_run]
    
    repo_path = None
    try:
        if os.path.isdir(args.repo_url):
            repo_path = args.repo_url
            cleanup = False
            print(f"[*] Using local directory: {repo_path}")
        else:
            print(f"[*] Cloning repository: {args.repo_url} (branch: {args.branch or 'default'})")
            repo_path = clone_repo(args.repo_url, args.branch)
            cleanup = True
            print(f"[*] Cloned to {repo_path}")
            
        orchestrator = Orchestrator(adapters=adapters)
        
        print(f"[*] Running analysis with tools: {', '.join(tools_to_run)}")
        report_identifier = args.repo_name if args.repo_name else args.repo_url
        report = orchestrator.analyze(report_identifier, repo_path)
        
        outputs = [o.strip() for o in args.output.split(",") if o.strip()]
        
        if "json" in outputs:
            json_file = "report.json"
            write_json_report(report, json_file)
            print(f"[*] JSON report saved to {json_file}")
            
            if args.run_ai:
                print("\n[*] Starting AI Analysis Stage")
                ai_input_file = "ai_input.json"
                try:
                    from src.ai.report_processor import process_report
                    from src.ai.ai_adapter import AIAdapter
                    
                    process_report(json_file, ai_input_file)
                    print(f"[*] AI input generated at {ai_input_file}")
                    
                    ai_adapter = AIAdapter()
                    ai_result = ai_adapter.run(ai_input_file, json_file)
                    print(f"[*] AI Adapter Result: {ai_result}")
                    
                    # Reload the enriched report from JSON so CSV output has AI fields
                    import json
                    from src.core.models import Report
                    with open(json_file, 'r', encoding='utf-8') as f:
                        report = Report.from_dict(json.load(f))
                        
                except ImportError as e:
                    print(f"[-] AI modules not found or failed to load: {e}")
                except Exception as e:
                    print(f"[-] Error during AI processing: {e}")
                    import traceback
                    traceback.print_exc()
            
        if "csv" in outputs:
            csv_file = "report.csv"
            write_csv_report(report, csv_file)
            print(f"[*] CSV report saved to {csv_file}")
            
        print("\n--- Analysis Summary ---")
        
        # GDPR summary section
        from src.core.models import ComplianceFindingType
        gdpr_findings = [f for f in report.findings if getattr(f, 'compliance_finding_type', None) is not None]
        if gdpr_findings:
            inventory = [f for f in gdpr_findings if f.compliance_finding_type == ComplianceFindingType.INVENTORY]
            third_party = [f for f in gdpr_findings if f.compliance_finding_type == ComplianceFindingType.THIRD_PARTY_RISK]
            security = [f for f in gdpr_findings if f.compliance_finding_type == ComplianceFindingType.SECURITY_GAP]
            minimisation = [f for f in gdpr_findings if f.compliance_finding_type == ComplianceFindingType.MINIMISATION_FLAG]
            human = [f for f in gdpr_findings if f.compliance_finding_type == ComplianceFindingType.HUMAN_REVIEW]
            
            print(f"Personal Data Inventory: {len(inventory)} items")
            print(f"Third-Party Transfer Risk: {len(third_party)}")
            print(f"Security Gaps: {len(security)}")
            print(f"Minimisation Flags: {len(minimisation)}")
            print(f"Human/Legal Review Required: {len(human)}")
            print("------------------------")

        # DPDP summary section
        dpdp_findings = [f for f in report.findings if getattr(f, 'framework', None) == "DPDP"]
        if dpdp_findings:
            in_force = [f for f in dpdp_findings if f.effective_status == "IN_FORCE"]
            future_state = [f for f in dpdp_findings if f.effective_status == "FUTURE_STATE"]
            dpdp_human = [f for f in dpdp_findings if f.human_review_required and f.human_review_required.startswith("YES")]
            
            print(f"DPDP Findings: {len(dpdp_findings)} total")
            print(f"  - In Force (Tier 1): {len(in_force)}")
            print(f"  - Future State (Tiers 2 & 3): {len(future_state)}")
            print(f"  - Human/Legal Review Required: {len(dpdp_human)}")
            print("------------------------")

        # CRA summary section
        from src.compliance.cra_engine import evaluate_cra_applicability
        cra_app, cra_reason = evaluate_cra_applicability(repo_path)
        cra_findings = [f for f in report.findings if getattr(f, 'cra_references', None) and len(f.cra_references) > 0]
        if cra_findings:
            part_i = [f for f in cra_findings if any(r.startswith("CRA-I-") for r in f.cra_references)]
            part_ii = [f for f in cra_findings if any(r.startswith("CRA-II-") for r in f.cra_references)]
            attestations = [f for f in cra_findings if getattr(f, 'compliance_finding_type', None) == ComplianceFindingType.ATTESTATION_REQUIRED]
            
            print(f"EU Cyber Resilience Act (CRA) Technical Readiness:")
            print(f"  - Applicability State: {cra_app}")
            print(f"  - Annex I, Part I (Security Properties): {len(part_i)} evidence items")
            print(f"  - Annex I, Part II (Vulnerability Handling): {len(part_ii)} evidence items")
            print(f"  - Organizational Attestations Required: {len(attestations)} checklist items")
            print("------------------------")

        # CERT-In summary section
        try:
            from src.compliance.cert_in_engine import evaluate_cert_in_applicability
            cert_app, cert_entity, cert_reason = evaluate_cert_in_applicability(repo_path)
            cert_in_tagged = [f for f in report.findings if getattr(f, 'cert_in_references', None) and len(f.cert_in_references) > 0]
            cert_in_dedicated = [f for f in report.findings if getattr(f, 'framework', None) == "CERT-IN"]
            cert_attestations = [f for f in report.findings if getattr(f, 'framework', None) == "CERT-IN" and getattr(f, 'compliance_finding_type', None) == ComplianceFindingType.ATTESTATION_REQUIRED]
            
            print(f"India CERT-In Technical Readiness:")
            print(f"  - Applicability State: {cert_app} (Scope: {cert_entity})")
            print(f"  - Annexure I Incident Readiness Evidence: {len(cert_in_tagged)} tagged security findings")
            print(f"  - General Statutory Requirements (Retention/NTP): {len(cert_in_dedicated) - len(cert_attestations)} evidence items")
            print(f"  - Organizational Attestations Required: {len(cert_attestations)} checklist items")
            print("------------------------")
        except Exception as e:
            print(f"India CERT-In Technical Readiness: Configuration Error ({e})")
            print("------------------------")

        for cat, summary in report.summary.items():
            print(f"{cat.upper()}: {summary.status.value} ({summary.count} findings)")
            for tool, tool_summary in summary.tools.items():
                print(f"  - {tool}: {tool_summary['status']} ({tool_summary.get('finding_count', 0)} findings)")
                if 'error_message' in tool_summary:
                    print(f"      Error: {tool_summary['error_message']}")
                if 'metrics' in tool_summary:
                    print(f"      Metrics: {tool_summary['metrics']}")
                    
    except Exception as e:
        print(f"Error during execution: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if repo_path and 'cleanup' in locals() and cleanup:
            print("[*] Cleaning up temporary directory")
            cleanup_repo(repo_path)

if __name__ == "__main__":
    main()
