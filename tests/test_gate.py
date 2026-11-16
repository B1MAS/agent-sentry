import json
import subprocess
import sys

def test_gate_denies_secret_and_shell(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    process = subprocess.run(
        [sys.executable, "-m", "agent_sentry.cli", "gate", "--policy", "examples/policy.json", "--ledger", str(ledger)],
        input='{"tool":"read_file","args":{"path":".env"}}\n{"tool":"shell","args":{"command":"whoami"}}\n',
        text=True, capture_output=True,
    )
    assert process.returncode == 1
    outputs = [json.loads(line) for line in process.stdout.splitlines()]
    assert [item["decision"] for item in outputs] == ["deny", "deny"]
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 2
