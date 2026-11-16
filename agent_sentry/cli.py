import argparse
import json
import sys
from .scanner import scan, sarif
from .policy import decide, load_policy
from .ledger import replay
from .ledger import append_event
from .report import render_html
from .mcp import decision_for_jsonrpc

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
    gate = sub.add_parser("gate", help="gate newline-delimited tool calls from stdin")
    gate.add_argument("--policy", required=True)
    gate.add_argument("--ledger")
    mcp = sub.add_parser("mcp-check", help="check MCP JSON-RPC requests from stdin")
    mcp.add_argument("--policy", required=True)
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
    if args.command == "gate":
        policy = load_policy(args.policy)
        previous = ""
        exit_code = 0
        for line in sys.stdin:
            if not line.strip():
                continue
            call = json.loads(line)
            result = decide(call, policy)
            output = {"tool": call.get("tool", ""), "decision": result.action, "reason": result.reason}
            print(json.dumps(output, ensure_ascii=False), flush=True)
            if args.ledger:
                previous = append_event(args.ledger, {"event": "tool_call", "tool": call.get("tool", ""), "decision": result.action, "reason": result.reason}, previous)
            if result.action == "deny":
                exit_code = 1
        return exit_code
    if args.command == "mcp-check":
        policy = load_policy(args.policy)
        exit_code = 0
        for line in sys.stdin:
            if not line.strip():
                continue
            request = json.loads(line)
            result = decision_for_jsonrpc(request, policy)
            print(json.dumps({"id": request.get("id"), "decision": result.action, "reason": result.reason}, ensure_ascii=False), flush=True)
            if result.action == "deny":
                exit_code = 1
        return exit_code
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
