# Threat model

AgentSentry protects the review and installation boundary around AI agent skills and MCP configuration. It is designed for a developer who may load third-party instructions that can influence an agent with filesystem, shell, browser or network tools.

## Assets

- source code and local configuration;
- credentials, tokens and SSH keys;
- source repositories and production APIs;
- user approval and audit evidence.

## Threats

- prompt injection hidden in a skill or tool description;
- a skill reading secrets and sending them to an external endpoint;
- shell or process execution hidden behind an apparently harmless tool;
- a dependency or installer that downloads and executes code;
- broad wildcard permissions and unsafe MCP capabilities;
- obfuscation that prevents a quick human review.

## Trust boundaries

The scanner treats every input file as untrusted data and never imports, executes or installs it. Static findings are signals, not proof of compromise. The future runtime proxy will mediate only calls that are routed through it; a process that bypasses the proxy is outside the boundary.

## Non-goals

AgentSentry is not a malware detector, sandbox, EDR, or guarantee that an AI agent is safe. It should be combined with OS isolation, least privilege, dependency review and human approval for sensitive actions.
