import html

def render_html(report: dict) -> str:
    rows = []
    for finding in report["findings"]:
        sev = html.escape(finding["severity"].upper())
        rows.append(
            "<tr><td><span class='badge " + sev.lower() + "'>" + sev + "</span></td>"
            "<td><code>" + html.escape(finding["rule_id"]) + "</code></td>"
            "<td>" + html.escape(finding["title"]) + "</td>"
            "<td><code>" + html.escape(finding["path"]) + ":" + str(finding["line"]) + "</code></td>"
            "<td>" + html.escape(finding["evidence"]) + "</td></tr>"
        )
    body = "".join(rows) or "<tr><td colspan='5' class='clean'>No findings</td></tr>"
    counts = " ".join("<span>" + key + ": <b>" + str(value) + "</b></span>" for key, value in report["counts"].items())
    return """<!doctype html><html lang='en'><meta charset='utf-8'><title>AgentSentry report</title>
<style>body{font:15px system-ui,sans-serif;background:#0b1020;color:#e7ecf5;max-width:1180px;margin:40px auto;padding:0 24px}h1{letter-spacing:-.03em}.sub{color:#9eabc2}.summary{display:flex;gap:20px;flex-wrap:wrap;background:#141c32;padding:18px;border-radius:14px;margin:24px 0}table{width:100%;border-collapse:collapse;background:#11182a}th,td{padding:13px;border-bottom:1px solid #26324d;text-align:left;vertical-align:top}th{color:#9eabc2}.badge{display:inline-block;padding:3px 8px;border-radius:99px;font-weight:700;font-size:12px}.critical{background:#ff5c75;color:#24050b}.high{background:#ffad5c;color:#261402}.medium{background:#ffe36e;color:#292000}.low{background:#89e0a1;color:#06200e}.clean{text-align:center;padding:32px;color:#89e0a1}</style>
<body><h1>AgentSentry</h1><p class='sub'>Local-first AI agent supply-chain security report</p>
<div class='summary'><span>Scanned files: <b>""" + str(report["scanned_files"]) + """</b></span>""" + counts + """</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th><th>Location</th><th>Evidence</th></tr></thead><tbody>""" + body + """</tbody></table></body></html>"""
