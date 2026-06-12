# -*- coding: utf-8 -*-
"""
Fredo — Community Edition
HTML scan report exporter.
"""
from __future__ import annotations

import html
import os
from datetime import datetime, timezone

from .scanner import ScanResult, score_label


def export_html(result: ScanResult, filename: str | None = None) -> str:
    if filename is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe = "".join(c if c.isalnum() or c in ".-_" else "_" for c in result.target)
        filename = f"fredo_scan_{safe}_{ts}.html"

    label, color = score_label(result.threat_score)
    ports_str = ", ".join(map(str, result.open_ports)) or "None detected"
    services_rows = "".join(
        f"<tr><td>{p}</td><td>{html.escape(str(result.services.get(p, '')))}</td></tr>"
        for p in result.open_ports
    ) or "<tr><td colspan='2'>No open ports.</td></tr>"

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Fredo Community Scan — {html.escape(result.target)}</title>
<style>
body{{font-family:'Segoe UI',Inter,Calibri,sans-serif;background:#111;color:#F5F5F0;padding:24px;max-width:900px;margin:auto}}
h1{{color:#C9A227;border-bottom:1px solid #1C3B30;padding-bottom:8px;letter-spacing:2px}}
h2{{color:#00BFA6;margin-top:20px}}
.section{{margin-bottom:16px;padding:14px;border:1px solid #1C3B30;border-radius:8px;background:#0B3D2E}}
.ports{{color:#00BFA6;font-size:15px;font-weight:bold}}
.threat{{font-size:22px;font-weight:bold}}
table{{width:100%;border-collapse:collapse}}
td,th{{border:1px solid #1C3B30;padding:6px 10px;text-align:left}}
pre{{white-space:pre-wrap;word-wrap:break-word;font-size:13px;line-height:1.6;font-family:Consolas,monospace}}
.badge{{display:inline-block;background:#0a1812;border:1px solid #C9A227;color:#C9A227;padding:4px 10px;border-radius:6px;font-size:12px;margin-top:6px}}
</style></head><body>
<h1>Fredo — Community Scan Report</h1>
<div class="section"><h2>Target</h2><p>{html.escape(result.target)}</p></div>
<div class="section"><h2>Engine / Time (UTC)</h2><p>{result.engine} · {result.timestamp}</p></div>
<div class="section"><h2>Open Ports</h2><p class="ports">{html.escape(ports_str)}</p></div>
<div class="section"><h2>Threat Score</h2>
  <p class="threat" style="color:{color}">{result.threat_score}/100
  <span style="font-size:13px;font-weight:normal">{label}</span></p></div>
<div class="section"><h2>Services</h2>
  <table><tr><th>Port</th><th>Service / Version</th></tr>{services_rows}</table></div>
<div class="section"><h2>Analysis</h2><pre>{html.escape(result.analysis)}</pre></div>
{f'<div class="section"><h2>Raw Output</h2><pre>{html.escape(result.raw_output)}</pre></div>' if result.raw_output else ''}
<p class="badge">Fredo · Community Edition (Free / 7-day trial)</p>
</body></html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(doc)
    return os.path.abspath(filename)
