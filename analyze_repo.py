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
    "react-doctor": ReactDoctorAdapter()
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
