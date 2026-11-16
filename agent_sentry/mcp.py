from .policy import Decision, decide

def decision_for_jsonrpc(request: dict, policy: dict) -> Decision:
    method = request.get("method", "")
    params = request.get("params") or {}
    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        return decide({"tool": name, "args": arguments}, policy)
    if method == "resources/read":
        return decide({"tool": "read_file", "args": {"path": params.get("uri", "")}}, policy)
    return Decision("ask", f"unknown MCP method: {method or 'missing'}")
