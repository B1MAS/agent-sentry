import json
from agent_sentry.policy import decide, load_policy
from agent_sentry.ledger import append_event, replay

def test_policy_allow_and_deny():
    policy = load_policy("examples/policy.json")
    assert decide({"tool": "read_file", "args": {"path": "workspace/README.md"}}, policy).action == "allow"
    assert decide({"tool": "read_file", "args": {"path": ".env"}}, policy).action == "deny"
    assert decide({"tool": "shell", "args": {"command": "whoami"}}, policy).action == "deny"

def test_ledger_hash_chain(tmp_path):
    path = tmp_path / "run.jsonl"
    previous = append_event(path, {"event": "tool_call", "tool": "read_file", "decision": "allow"})
    append_event(path, {"event": "tool_result", "status": "ok"}, previous)
    events = replay(path)
    assert len(events) == 2
    assert all(event["valid_hash"] for event in events)
