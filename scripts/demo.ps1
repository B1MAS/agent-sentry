$ErrorActionPreference = 'Stop'
Write-Host '== unsafe fixture ==' -ForegroundColor Yellow
python -m agent_sentry.cli scan examples/unsafe-skill --fail-on never
Write-Host ''
Write-Host '== safe fixture ==' -ForegroundColor Green
python -m agent_sentry.cli scan examples/safe-skill --fail-on never
Write-Host ''
Write-Host '== policy gate ==' -ForegroundColor Cyan
Get-Content examples/tool-calls.jsonl | python -m agent_sentry.cli gate --policy examples/policy.json --ledger demo-ledger.jsonl
