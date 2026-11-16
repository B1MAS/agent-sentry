import argparse
import json
from .scanner import scan, sarif
from .policy import decide, load_policy
from .ledger import replay
from .report import render_html

def main() -> int:
    parser = argparse.ArgumentParser(prog="agent-sentry", description="Scan AI agent skills and MCP configs before they run.")
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("scan", help="scan a directory")
    cmd.add_argument("path", nargs="?", default=".")
    cmd.add_argument("--format", choices=["text", "json", "sarif", "html"], default="text")
    cmd.add_argument("--fail-on", choices=["critical", "high", "medium", "never"], default="high")
    check = sub.add_parser("check-call", help="evaluate a tool call against a policy")
    check.add_argument("--policy", required=True)
    check.add_argument("--call", required=True)
    rep = sub.add_parser("replay", help="verify and print a JSONL action ledger")
    rep.add_argument("path")
    args = parser.parse_args()
    if args.command == "check-call":
        result = decide(json.loads(open(args.call, encoding="utf-8").read()), load_policy(args.policy))
        print(f"{result.action.upper()}: {result.reason}")
        return 0 if result.action == "allow" else 1
    if args.command == "replay":
        events = replay(args.path)
        for event in events:
            print(f"{'OK' if event['valid_hash'] else 'BROKEN'} {event.get('ts', '')} {event.get('event', '')} {event.get('decision', '')}")
        return 0 if all(event["valid_hash"] for event in events) else 1
    report = scan(args.path)
    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    elif args.format == "sarif":
        print(json.dumps(sarif(report), indent=2, ensure_ascii=False))
    elif args.format == "html":
        print(render_html(report))
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
