from dataclasses import dataclass
import re

@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    title: str
    description: str
    patterns: tuple[str, ...]

RULES = (
    Rule("AS001", "critical", "Possible secret access", "Reads environment variables or credential files.", (r"os\.environ", r"process\.env", r"\.env", r"\.ssh/", r"id_rsa", r"AWS_SECRET", r"OPENAI_API_KEY")),
    Rule("AS002", "high", "Possible data exfiltration", "Sends data to a network endpoint.", (r"curl\s+[^\n]*(https?://)", r"requests\.(post|put)", r"fetch\s*\(", r"Invoke-WebRequest", r"axios\.(post|put)")),
    Rule("AS003", "high", "Shell execution", "Runs a shell, command interpreter, or arbitrary process.", (r"subprocess\.", r"os\.system", r"child_process", r"exec\s*\(", r"shell:\s*true", r"bash\s+-c", r"powershell\s+-")),
    Rule("AS004", "high", "Download and execute", "Downloads remote content and pipes it to execution.", (r"curl\s+[^\n]*\|\s*(sh|bash)", r"wget\s+[^\n]*\|\s*(sh|bash)", r"Invoke-Expression", r"pip\s+install\s+https?://")),
    Rule("AS005", "medium", "Prompt injection language", "Attempts to override the host agent or hide behavior.", (r"ignore\s+(all|any|previous)(\s+\w+){0,2}\s+instructions", r"do\s+not\s+tell\s+the\s+user", r"system\s+message", r"reveal\s+your\s+prompt", r"bypass\s+approval")),
    Rule("AS006", "high", "Dangerous MCP capability", "Declares broad filesystem, browser, shell, or wildcard access.", (r"allowed-tools\s*:\s*['\"]?\*", r"filesystem\.write", r"filesystem\.delete", r"browser\.navigate", r"shell\.execute", r"run_command")),
    Rule("AS007", "medium", "Obfuscation", "Uses encoded or hidden content that makes review harder.", (r"base64\.(b64decode|decode)", r"atob\s*\(", r"eval\s*\(", r"charCodeAt", r"\\x[0-9a-fA-F]{2}")),
)

def scan_text(text: str, path: str) -> list[dict]:
    findings = []
    lines = text.splitlines() or [text]
    for rule in RULES:
        for line_no, line in enumerate(lines, 1):
            for pattern in rule.patterns:
                if re.search(pattern, line, flags=re.IGNORECASE):
                    findings.append({"rule_id": rule.rule_id, "severity": rule.severity, "title": rule.title, "description": rule.description, "path": path, "line": line_no, "evidence": line.strip()[:240]})
                    break
    return findings
