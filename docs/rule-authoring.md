# Rule authoring

Each rule should be small, readable and paired with an inert fixture and a regression test.

1. State the threat in one sentence.
2. Prefer a high-signal pattern over a broad keyword.
3. Include a concrete file and line in the finding.
4. Document likely false positives and a safe remediation.
5. Never execute fixture content during scanning.

Rule IDs are stable public API. Use the `AS` prefix and a three-digit number. A future rules format will move these definitions into versioned YAML so contributors can add rules without editing Python.
