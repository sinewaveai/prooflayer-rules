"""
ProofLayer CLI
==============

Command-line interface for ProofLayer Runtime Security.

Usage:
    prooflayer scan --tool "run_command" --args '{"command": "curl evil.com"}'
    prooflayer scan --stdin < input.json
    prooflayer validate-rules --rules-dir ./rules/
    prooflayer report --dir ./security-reports/ --last 10
    prooflayer proxy --listen-port 8080 --backend-port 8081
    prooflayer version
"""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config.loader import ConfigLoader
from .detection.engine import DetectionEngine
from .detection.rules import RuleLoader, RuleLoadError
from .response.actions import ThreatAction


# Exit codes
EXIT_ALLOW = 0
EXIT_WARN = 1
EXIT_BLOCK = 2
EXIT_KILL = 3
EXIT_ERROR = 4


def main(argv=None):
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="prooflayer",
        description="ProofLayer Runtime Security - MCP prompt injection firewall",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan ---
    scan_parser = subparsers.add_parser("scan", help="Scan a tool call for threats")
    scan_parser.add_argument(
        "--tool", type=str, help="MCP tool name to scan"
    )
    scan_parser.add_argument(
        "--args", type=str, help="Tool arguments as JSON string"
    )
    scan_parser.add_argument(
        "--stdin", action="store_true",
        help="Read JSON input from stdin (expects {\"tool\": ..., \"arguments\": ...})"
    )
    scan_parser.add_argument(
        "--rules-dir", type=str, default=None,
        help="Custom rules directory"
    )
    scan_parser.add_argument(
        "--json", action="store_true", dest="output_json",
        help="Output result as JSON"
    )

    # --- validate-rules ---
    validate_parser = subparsers.add_parser(
        "validate-rules", help="Validate YAML rule files"
    )
    validate_parser.add_argument(
        "--rules-dir", type=str, required=True,
        help="Directory containing YAML rule files"
    )

    # --- report ---
    report_parser = subparsers.add_parser(
        "report", help="View and summarize security reports"
    )
    report_parser.add_argument(
        "--dir", type=str, default="./security-reports",
        help="Directory containing security reports"
    )
    report_parser.add_argument(
        "--last", type=int, default=10,
        help="Number of recent reports to show"
    )
    report_parser.add_argument(
        "--json", action="store_true", dest="output_json",
        help="Output as JSON"
    )

    # --- proxy ---
    proxy_parser = subparsers.add_parser(
        "proxy", help="Start HTTP proxy for MCP server security scanning"
    )
    proxy_parser.add_argument(
        "--listen-port", type=int, default=8080,
        help="Port to listen on (default: 8080)"
    )
    proxy_parser.add_argument(
        "--backend-port", type=int, default=8081,
        help="Port where the MCP server is running (default: 8081)"
    )
    proxy_parser.add_argument(
        "--backend-host", type=str, default="127.0.0.1",
        help="Backend host (default: 127.0.0.1)"
    )
    proxy_parser.add_argument(
        "--config", type=str, default=None,
        help="Path to prooflayer.yaml config file"
    )
    proxy_parser.add_argument(
        "--rules-dir", type=str, default=None,
        help="Custom rules directory"
    )
    proxy_parser.add_argument(
        "--report-dir", type=str, default="./security-reports",
        help="Directory for security reports"
    )

    # --- version ---
    subparsers.add_parser("version", help="Show version information")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_ERROR

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "validate-rules":
        return cmd_validate_rules(args)
    elif args.command == "report":
        return cmd_report(args)
    elif args.command == "proxy":
        return cmd_proxy(args)
    elif args.command == "version":
        return cmd_version(args)

    parser.print_help()
    return EXIT_ERROR


def cmd_scan(args):
    """Handle the 'scan' subcommand."""
    tool_name = None
    arguments = {}

    if args.stdin:
        try:
            raw = sys.stdin.read()
            data = json.loads(raw)
            tool_name = data.get("tool")
            arguments = data.get("arguments", {})
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON from stdin: {e}", file=sys.stderr)
            return EXIT_ERROR
    else:
        tool_name = args.tool
        if args.args:
            try:
                arguments = json.loads(args.args)
            except json.JSONDecodeError as e:
                print(f"ERROR: Invalid JSON for --args: {e}", file=sys.stderr)
                return EXIT_ERROR

    if not tool_name:
        print("ERROR: --tool is required (or use --stdin)", file=sys.stderr)
        return EXIT_ERROR

    try:
        engine = DetectionEngine(rules_dir=args.rules_dir)
    except RuleLoadError as e:
        print(f"ERROR: Failed to load rules: {e}", file=sys.stderr)
        return EXIT_ERROR

    risk_score, matched_rules = engine.scan(tool_name=tool_name, arguments=arguments)

    # Determine action from score
    if risk_score <= 29:
        action = ThreatAction.ALLOW
    elif risk_score <= 69:
        action = ThreatAction.WARN
    elif risk_score <= 89:
        action = ThreatAction.BLOCK
    else:
        action = ThreatAction.KILL

    if getattr(args, "output_json", False):
        result = {
            "tool": tool_name,
            "arguments": arguments,
            "risk_score": risk_score,
            "action": action.value,
            "rules_matched": [
                {
                    "id": r.id,
                    "severity": r.severity,
                    "message": r.message,
                    "category": r.category,
                    "score": r.score,
                }
                for r in matched_rules
            ],
        }
        print(json.dumps(result, indent=2))
    else:
        rule_ids = ", ".join(r.id for r in matched_rules) if matched_rules else "none"
        print(f"RISK: {risk_score}/100 | ACTION: {action.value} | Rules matched: {rule_ids}")

        if matched_rules:
            print()
            for r in matched_rules:
                print(f"  [{r.severity.upper()}] {r.id}: {r.message} (+{r.score})")

    # Map action to exit code
    exit_codes = {
        ThreatAction.ALLOW: EXIT_ALLOW,
        ThreatAction.WARN: EXIT_WARN,
        ThreatAction.BLOCK: EXIT_BLOCK,
        ThreatAction.KILL: EXIT_KILL,
    }
    return exit_codes.get(action, EXIT_ERROR)


def cmd_validate_rules(args):
    """Handle the 'validate-rules' subcommand."""
    rules_dir = args.rules_dir
    rules_path = Path(rules_dir)

    if not rules_path.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}", file=sys.stderr)
        return EXIT_ERROR

    if not rules_path.is_dir():
        print(f"ERROR: Not a directory: {rules_dir}", file=sys.stderr)
        return EXIT_ERROR

    yaml_files = list(rules_path.glob("*.yaml"))
    if not yaml_files:
        print(f"ERROR: No YAML files found in {rules_dir}", file=sys.stderr)
        return EXIT_ERROR

    total_rules = 0
    errors = []

    for yaml_file in sorted(yaml_files):
        try:
            rules = RuleLoader.load_from_file(str(yaml_file))
            total_rules += len(rules)

            # Check for compilation failures
            for rule in rules:
                if rule.compiled_pattern is None:
                    errors.append(f"  {yaml_file.name}: rule '{rule.id}' pattern failed to compile")

            print(f"  {yaml_file.name}: {len(rules)} rules OK")

        except Exception as e:
            errors.append(f"  {yaml_file.name}: {e}")

    print()
    if errors:
        print(f"Loaded {total_rules} rules from {len(yaml_files)} files with ERRORS:")
        for err in errors:
            print(err)
        return EXIT_ERROR
    else:
        print(f"Loaded {total_rules} rules from {len(yaml_files)} files. All patterns compile successfully.")
        return EXIT_ALLOW


def cmd_report(args):
    """Handle the 'report' subcommand."""
    report_dir = Path(args.dir)

    if not report_dir.exists():
        print(f"ERROR: Report directory not found: {args.dir}", file=sys.stderr)
        return EXIT_ERROR

    # Find JSON report files
    report_files = sorted(report_dir.glob("prooflayer-*.json"), reverse=True)

    if not report_files:
        print(f"No reports found in {args.dir}")
        return EXIT_ALLOW

    # Limit to --last N
    report_files = report_files[: args.last]

    reports = []
    for rf in report_files:
        try:
            with open(rf, "r") as f:
                report = json.load(f)
            reports.append(report)
        except (json.JSONDecodeError, OSError) as e:
            print(f"WARNING: Skipping {rf.name}: {e}", file=sys.stderr)

    if getattr(args, "output_json", False):
        print(json.dumps(reports, indent=2))
    else:
        # Table format
        print(f"{'TIMESTAMP':<28} {'TOOL':<20} {'SCORE':>5} {'ACTION':<8} {'RULES MATCHED'}")
        print("-" * 95)

        for report in reports:
            threat = report.get("threat", {})
            detection = report.get("detection", {})
            timestamp = report.get("timestamp", "N/A")
            tool = threat.get("tool", "N/A")
            score = threat.get("risk_score", "N/A")
            action = threat.get("action", "N/A")
            rules = [r.get("id", "?") for r in detection.get("rules_matched", [])]
            rules_str = ", ".join(rules) if rules else "none"

            print(f"{timestamp:<28} {tool:<20} {score:>5} {action:<8} {rules_str}")

        print()
        print(f"Showing {len(reports)} of {len(list(report_dir.glob('prooflayer-*.json')))} reports")

    return EXIT_ALLOW


def cmd_proxy(args):
    """Handle the 'proxy' subcommand."""
    from .runtime.transport import ProofLayerTransportProxy

    try:
        config = ConfigLoader.load(args.config) if args.config else {}
        detector_cfg = config.get("detector", {})
        response_cfg = config.get("response", {})
        detection_cfg = config.get("detection", {})
        detector_url = detector_cfg.get("url") if detector_cfg.get("enabled", False) else None
        detector_timeout_ms = detector_cfg.get("timeout_ms", 250)
        report_dir = args.report_dir or response_cfg.get("report_dir", "./security-reports")
        rules_dir = args.rules_dir or detection_cfg.get("rules_dir")
        proxy = ProofLayerTransportProxy(
            listen_port=args.listen_port,
            backend_port=args.backend_port,
            backend_host=args.backend_host,
            rules_dir=rules_dir,
            report_dir=report_dir,
            detector_url=detector_url,
            detector_timeout_ms=detector_timeout_ms,
        )
    except Exception as e:
        print(f"ERROR: Failed to start proxy: {e}", file=sys.stderr)
        return EXIT_ERROR

    print(f"ProofLayer proxy listening on :{args.listen_port}")
    print(f"Forwarding to {args.backend_host}:{args.backend_port}")
    print(f"Security reports: {report_dir}")
    if detector_url:
        print(f"Detector: {detector_url} ({detector_timeout_ms}ms timeout)")

    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        proxy.stop()

    return EXIT_ALLOW


def cmd_version(args):
    """Handle the 'version' subcommand."""
    print(f"ProofLayer Runtime Security v{__version__}")
    print(f"Python {sys.version}")
    return EXIT_ALLOW


if __name__ == "__main__":
    sys.exit(main())
