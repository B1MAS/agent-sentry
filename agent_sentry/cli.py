import argparse
import json
from .scanner import scan, sarif

def main() -> int:
    parser = argparse.ArgumentParser(prog="agent-sentry", description="Scan AI agent skills and MCP configs before they run.")
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("scan", help="scan a directory")
    cmd.add_argument("path", nargs="?", default=".")
    cmd.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    cmd.add_argument("--fail-on", choices=["critical", "high", "medium", "never"], default="high")
    args = parser.parse_args()
    report = scan(args.path)
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.format == "sarif":
        print(json.dumps(sarif(report), indent=2, ensure_ascii=False))
    else:
        print(f"AgentSentry scanned {report['scanned_files']} files")
        print("Findings: " + ", ".join(f"{k}={v}" for k, v in report["counts"].items()))
        for finding in report["findings"]:
            print(f"[{finding['severity'].upper()}] {finding['rule_id']} {finding['path']}:{finding['line']} - {finding['title']}")
            print(f"  {finding['evidence']}")
    threshold = {"critical": {"critical"}, "high": {"critical", "high"}, "medium": {"critical", "high", "medium"}, "never": set()}[args.fail_on]
    return 1 if any(f["severity"] in threshold for f in report["findings"]) else 0

if __name__ == "__main__":
    raise SystemExit(main())
