from agent_sentry.mcp import decision_for_jsonrpc
from agent_sentry.policy import load_policy

def test_mcp_tool_call_uses_policy():
    policy = load_policy("examples/policy.json")
    request = {"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": ".env"}}}
    assert decision_for_jsonrpc(request, policy).action == "deny"

def test_unknown_mcp_method_requires_review():
    assert decision_for_jsonrpc({"method": "prompts/get"}, {}).action == "ask"
