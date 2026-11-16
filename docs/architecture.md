# Architecture

```text
input files ──> deterministic scanner ──> findings ──> text / JSON / SARIF / HTML
tool calls ──> policy engine ──> allow / ask / deny ──> redacted hash-chain ledger
```

The scanner and gate are deliberately separate. A scan is safe to run over untrusted files because it never imports, installs or executes them. The gate prototype evaluates structured tool calls before an external runner would execute them. The next runtime adapter will connect this decision boundary to MCP stdio without changing the policy model.

The ledger stores event metadata, decisions, reasons and hashes. It does not store raw tool arguments or file contents by default. Replay verifies the chain and marks tampered or reordered events as invalid.
