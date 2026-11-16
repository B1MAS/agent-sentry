from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
import json

@dataclass(frozen=True)
class Decision:
    action: str
    reason: str

def load_policy(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def decide(call: dict, policy: dict) -> Decision:
    tool = str(call.get("tool", ""))
    args = call.get("args") or {}
    path = str(args.get("path", args.get("file", "")))
    defaults = policy.get("defaults", {})
    for rule in policy.get("rules", []):
        if rule.get("tool") and rule["tool"] != tool:
            continue
        if rule.get("path") and not fnmatch(path, rule["path"]):
            continue
        if rule.get("host") and rule["host"] != args.get("host"):
            continue
        return Decision(rule.get("decision", "ask"), f"matched rule for {tool}")
    if tool in {"shell", "run_command", "process.exec", "filesystem.delete"}:
        return Decision(defaults.get("shell", "deny"), "dangerous tool default")
    if tool in {"http_request", "browser.navigate", "network.send"}:
        return Decision(defaults.get("network", "ask"), "network tool default")
    if any(secret in path.replace("\\", "/") for secret in (".env", ".ssh/", "id_rsa", "credentials")):
        return Decision("deny", "known secret path")
    return Decision(defaults.get("filesystem", "ask"), "default policy")
