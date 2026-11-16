from pathlib import Path
from .rules import scan_text

NAMES = {"SKILL.md", "CLAUDE.md", "AGENTS.md", "mcp.json", "settings.json", "config.json"}

def candidate_files(root: Path) -> list[Path]:
    result = []
    for path in root.rglob("*"):
        if not path.is_file() or any(part in {".git", ".venv", "node_modules"} for part in path.parts):
            continue
        if path.name in NAMES or path.suffix.lower() in {".md", ".json", ".yaml", ".yml", ".py", ".js", ".ts", ".ps1", ".sh"}:
            result.append(path)
    return sorted(result)

def scan(root: str | Path) -> dict:
    base = Path(root).resolve()
    findings = []
    scanned = 0
    for path in candidate_files(base):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        findings.extend(scan_text(text, str(path.relative_to(base))))
    findings.sort(key=lambda item: (item["path"], item["line"], item["rule_id"]))
    counts = {level: sum(f["severity"] == level for f in findings) for level in ("critical", "high", "medium", "low")}
    return {"version": "0.1", "root": str(base), "scanned_files": scanned, "counts": counts, "findings": findings}

def sarif(report: dict) -> dict:
    rules = {f["rule_id"]: f for f in report["findings"]}
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "AgentSentry", "version": "0.1.0", "rules": [{"id": key, "shortDescription": {"text": value["title"]}, "help": {"text": value["description"]}} for key, value in rules.items()]}},
        "results": [{"ruleId": f["rule_id"], "level": "error" if f["severity"] in {"critical", "high"} else "warning", "message": {"text": f["description"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}, "region": {"startLine": f["line"]}}}]} for f in report["findings"]]
    }]}
