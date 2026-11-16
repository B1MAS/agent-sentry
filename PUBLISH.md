# Publish AgentSentry

The repository is ready for a public GitHub repository. From this directory:

```bash
git remote add origin https://github.com/YOUR_USERNAME/agent-sentry.git
git push -u origin main
```

Recommended repository settings:

- visibility: Public;
- description: `Local-first security scanner and policy gate for AI agent skills and MCP tools`;
- topics: `ai`, `agents`, `mcp`, `security`, `prompt-injection`, `supply-chain`, `devsecops`;
- enable Issues and Discussions;
- keep the included GitHub Action enabled;
- create the first release as `v0.1.0` after the first successful workflow run.

Before pushing, verify:

```bash
uv run --project . --with pytest python -m pytest -q tests
python -m agent_sentry.cli scan examples/safe-skill --fail-on high
```
