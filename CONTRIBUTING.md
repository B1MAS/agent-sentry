# Contributing

Small, reproducible contributions are welcome.

1. Add or update a safe fixture.
2. Add a focused regression test.
3. Explain false positives and a safe remediation.
4. Run `uv run --project . --with pytest python -m pytest -q tests`.
5. Keep scanner rules deterministic and offline.

Do not add rules that execute input files, download dependencies during a scan, or upload source code.
