# AgentSentry

Scan the AI agent supply chain before it gets permission to act.

AgentSentry is a local-first, zero-API-key security scanner for AI agent skills, MCP configurations, prompts, hooks and bundled scripts. It finds dangerous shell execution, secret access, network exfiltration, download-and-execute chains, prompt injection language, broad tool grants and obfuscation. Reports work in the terminal, JSON and SARIF/GitHub Code Scanning.

## Try it in one minute

```bash
python -m pip install -e .
agent-sentry scan examples/unsafe-skill
agent-sentry scan examples/safe-skill
agent-sentry scan . --format sarif > agent-sentry.sarif
agent-sentry check-call --policy examples/policy.json --call examples/tool-call.json
```

The unsafe fixture is intentionally harmless text. It demonstrates findings without contacting a network or running a command.

## Why this exists

AI agents increasingly load third-party skills and MCP tools that can read files, run commands and call APIs. AgentSentry gives developers a fast pre-install and pre-merge check that runs locally and keeps source code on the machine.

## What the MVP detects

- secret and credential access (`.env`, SSH keys, API key environment variables)
- network egress and common exfiltration calls
- shell/process execution
- download-and-execute chains
- prompt injection and approval bypass language
- broad filesystem/browser/shell tool grants
- simple obfuscation patterns

The policy prototype can evaluate a tool call before execution and the ledger module can verify an append-only, hash-chained JSONL run record.

This is a static signal scanner, not a sandbox and not proof that a skill is safe. Use it as a review gate with least-privilege policies and isolated execution.

## Roadmap

- policy-as-code for MCP tool calls with allow/ask/deny
- MCP stdio proxy and redacted replayable action ledger
- safe red-team fixture corpus and public benchmark leaderboard
- optional local-model explanations with no source upload
- signed reports and package reputation metadata

## Contributing

Add a focused rule with a safe fixture and a test. Rules must include a false-positive note and never execute fixture payloads.

MIT licensed.
