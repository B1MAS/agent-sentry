from agent_sentry.report import render_html

def test_html_report_escapes_evidence():
    report = {"root": ".", "scanned_files": 1, "counts": {"critical": 1, "high": 0, "medium": 0, "low": 0}, "findings": [{"rule_id": "AS001", "severity": "critical", "title": "Secret", "path": "x.md", "line": 1, "evidence": "<script>alert(1)</script>"}]}
    output = render_html(report)
    assert "&lt;script&gt;" in output
    assert "<script>alert(1)</script>" not in output
