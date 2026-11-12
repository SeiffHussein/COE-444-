"""
modules/reporting.py - CSV and HTML report export.

Both functions take the COMBINED result of orchestrator.run_assessment()
(not just a findings list), so a report can also show each tool's status and
errors, the scan id and whether the data is sample or real.

Security: every value in a finding is untrusted - it can contain text sent by
a scanned web server. Every value is passed through html.escape() before it
is placed in the HTML. Never build HTML from unescaped result text.
"""

from __future__ import annotations

import csv
import html
from pathlib import Path

import config
from modules.orchestrator import summarize
from schemas import FINDING_FIELDS, ML_PRIORITIES, SEVERITIES, TOOLS

CSV_COLUMNS: tuple[str, ...] = ("scan_id",) + FINDING_FIELDS


def _prepare_path(output_path: str) -> Path:
    path = Path(output_path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Cannot create folder {path.parent}: {exc}") from exc
    return path


def _cell(value: object) -> str:
    """Text for a CSV cell. Cells starting with = + - @ get a leading quote so
    a spreadsheet does not run scanner-controlled text as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def generate_csv_report(result: dict, output_path: str) -> str:
    """Write the findings of an assessment to a CSV file (one row per finding).

    Args:
        result: combined orchestrator result. No findings -> header-only CSV.
        output_path: file path, e.g. "reports/assessment.csv". Folders are created.

    Returns:
        The path written, as a string.

    Raises:
        RuntimeError: the file cannot be written.
    """
    path = _prepare_path(output_path)
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(CSV_COLUMNS)
            for finding in result.get("findings", []):
                writer.writerow([_cell(result.get("scan_id", ""))]
                                + [_cell(finding.get(name, "")) for name in FINDING_FIELDS])
    except OSError as exc:
        raise RuntimeError(f"Cannot write CSV report to {path}: {exc}") from exc
    return str(path)


def generate_html_report(result: dict, output_path: str) -> str:
    """Write a self-contained HTML report (inline CSS, all values escaped).

    Args:
        result: combined orchestrator result.
        output_path: file path, e.g. "reports/assessment.html". Folders are created.

    Returns:
        The path written, as a string.

    Raises:
        RuntimeError: the file cannot be written.
    """
    path = _prepare_path(output_path)
    esc = lambda value: html.escape("" if value is None else str(value), quote=True)  # noqa: E731
    findings = result.get("findings", [])
    summary = summarize(result)
    sample = bool(result.get("is_sample"))

    # ---- header facts
    mode = ("<span class='badge sample'>SAMPLE DATA - fixtures, not a real scan</span>" if sample
            else "<span class='badge real'>REAL SCAN</span>")
    facts = "".join(f"<tr><th>{esc(label)}</th><td>{value}</td></tr>" for label, value in [
        ("Scan ID", esc(result.get("scan_id"))),
        ("Target", esc(result.get("target"))),
        ("Data", mode),
        ("Started", esc(result.get("started_at"))),
        ("Finished", esc(result.get("finished_at"))),
        ("Duration", f"{esc(result.get('duration_s'))} s"),
    ])

    # ---- tool status
    tool_rows = ""
    for tool in TOOLS:
        scan = result.get("scans", {}).get(tool, {})
        status = scan.get("status", "SKIPPED")
        tool_rows += (f"<tr><td>{esc(tool)}</td><td class='st-{esc(status).lower()}'>{esc(status)}</td>"
                      f"<td>{len(scan.get('findings', []))}</td><td>{esc(scan.get('duration_s', 0))} s</td>"
                      f"<td>{esc(scan.get('error', ''))}</td></tr>")
    ml = result.get("ml", {})
    tool_rows += (f"<tr><td>ML classifier</td><td class='st-{esc(ml.get('status', '')).lower()}'>"
                  f"{esc(ml.get('status', ''))}</td><td>-</td><td>-</td><td>{esc(ml.get('error', ''))}</td></tr>")

    errors = "".join(f"<li>{esc(e)}</li>" for e in result.get("errors", []))
    errors_block = f"<h2>Errors</h2><ul class='errors'>{errors}</ul>" if errors else ""

    # ---- totals
    severity_cells = "".join(f"<td class='sev-{s.lower()}'><b>{summary['by_severity'].get(s, 0)}</b><br>{s}</td>"
                             for s in SEVERITIES)
    priority_cells = "".join(f"<td><b>{summary['by_ml_priority'].get(p, 0)}</b><br>{p}</td>" for p in ML_PRIORITIES)

    # ---- findings
    if findings:
        blocks = ""
        for f in findings:
            port = f"{esc(f.get('port'))}" + (f" ({esc(f.get('service'))})" if f.get("service") else "") \
                if f.get("port") is not None else esc(f.get("service") or "-")
            blocks += f"""
<div class="finding">
 <h3><span class="pill sev-{esc(f.get('severity', 'Info')).lower()}">{esc(f.get('severity'))}</span> {esc(f.get('title'))}</h3>
 <table class="kv">
  <tr><th>Tool</th><td>{esc(f.get('source'))}</td><th>Port / service</th><td>{port}</td></tr>
  <tr><th>Original severity</th><td>{esc(f.get('original_severity') or '(none given by tool)')}</td>
      <th>Normalized severity</th><td>{esc(f.get('severity'))}</td></tr>
  <tr><th>ML priority</th><td>{esc(f.get('ml_priority') or '(not classified)')}</td>
      <th>ML action</th><td>{esc(f.get('ml_action') or '(not classified)')}</td></tr>
  <tr><th>CVE</th><td>{esc(f.get('cve') or '-')}</td><th>Check ID</th><td>{esc(f.get('check_id') or '-')}</td></tr>
 </table>
 <p><b>Description:</b> {esc(f.get('description') or '-')}</p>
 <p><b>Evidence:</b></p><pre>{esc(f.get('evidence') or '-')}</pre>
 <p><b>Recommendation:</b> {esc(f.get('recommendation') or '-')}</p>
</div>"""
    else:
        blocks = "<p>No findings were recorded for this assessment.</p>"

    # ---- remediation outcome (only if a fix was attempted or simulated)
    remediation = result.get("remediation")
    remediation_block = ""
    if remediation:
        steps = "".join(
            f"<tr><td>{esc(s.get('step'))}</td><td>{esc(s.get('name'))}</td>"
            f"<td class='{'st-success' if s.get('ok') else 'st-failed'}'>{'OK' if s.get('ok') else 'FAILED'}</td>"
            f"<td>{esc(s.get('detail'))}</td></tr>" for s in remediation.get("steps", []))
        label = "SIMULATION (nothing was changed)" if remediation.get("simulated") else "Real run"
        remediation_block = f"""
<h2>Remediation outcome</h2>
<table class="kv">
 <tr><th>Type</th><td>{esc(label)}</td><th>Finding ID</th><td>{esc(remediation.get('finding_id'))}</td></tr>
 <tr><th>Applied</th><td>{esc(remediation.get('applied'))}</td><th>Verified</th><td>{esc(remediation.get('verified'))}</td></tr>
 <tr><th>Backup</th><td colspan="3">{esc(remediation.get('backup_path') or '(no earlier file to back up)')}</td></tr>
 <tr><th>Result</th><td colspan="3">{esc(remediation.get('message'))}</td></tr>
</table>
<table><thead><tr><th>Step</th><th>Action</th><th>Result</th><th>Detail</th></tr></thead><tbody>{steps}</tbody></table>"""

    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(config.APP_NAME)} - report {esc(result.get('scan_id'))}</title>
<style>
 body {{ font-family: Arial, Helvetica, sans-serif; margin: 32px auto; max-width: 1000px; padding: 0 16px; color: #1f2933; line-height: 1.45; }}
 h1 {{ margin-bottom: 4px; }} h2 {{ border-bottom: 2px solid #d9dee4; padding-bottom: 4px; margin-top: 32px; }}
 h3 {{ margin: 0 0 8px; font-size: 16px; }}
 table {{ border-collapse: collapse; width: 100%; font-size: 13px; margin: 8px 0; }}
 th, td {{ border: 1px solid #cbd2d9; padding: 6px 8px; text-align: left; vertical-align: top; }}
 th {{ background: #f1f3f5; white-space: nowrap; }}
 .totals td {{ text-align: center; width: 20%; }} .totals b {{ font-size: 20px; }}
 .finding {{ border: 1px solid #cbd2d9; border-radius: 6px; padding: 12px 14px; margin: 14px 0; page-break-inside: avoid; }}
 pre {{ background: #f6f7f9; border: 1px solid #e1e5ea; padding: 8px; white-space: pre-wrap; word-break: break-all; font-size: 12px; margin: 4px 0; }}
 .pill, .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: bold; }}
 .badge.sample {{ background: #fff3cd; border: 1px solid #d9b441; }} .badge.real {{ background: #d7ecff; border: 1px solid #6aa5d8; }}
 .sev-critical {{ background: #f5c2c7; }} .sev-high {{ background: #fbd5b5; }}
 .sev-medium {{ background: #fff0b3; }} .sev-low {{ background: #d8ecd0; }} .sev-info {{ background: #dce6f5; }}
 .st-success {{ color: #1b6e2d; font-weight: bold; }} .st-failed {{ color: #b3261e; font-weight: bold; }}
 .st-skipped, .st-not_applicable {{ color: #6b7280; font-weight: bold; }}
 .errors li {{ color: #b3261e; }} .small {{ color: #52606d; font-size: 13px; }}
</style></head><body>
<h1>Security Assessment Report</h1>
<p class="small">{esc(config.APP_NAME)} v{esc(config.APP_VERSION)} - COE 444 Computer Security project.
Authorized lab use only.</p>
<table class="kv">{facts}</table>

<h2>Tool status</h2>
<table><thead><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Duration</th><th>Error / note</th></tr></thead>
<tbody>{tool_rows}</tbody></table>
{errors_block}

<h2>Summary</h2>
<p><b>Total findings: {summary['total']}</b></p>
<p class="small">By normalized severity</p>
<table class="totals"><tr>{severity_cells}</tr></table>
<p class="small">By ML priority (advisory)</p>
<table class="totals"><tr>{priority_cells}</tr></table>

<h2>Findings</h2>
{blocks}
{remediation_block}

<h2>Limitations</h2>
<ul>
 <li>The scans are not exhaustive: Nmap checks only the top {esc(config.NMAP_TOP_PORTS)} TCP ports, Nuclei and Nikto
     run non-intrusive checks only, and a tool that failed or was skipped contributed nothing.
     The absence of a finding does not prove the absence of a vulnerability.</li>
 <li>ML priority and ML action are advisory. Both models were trained on synthetic data labelled by
     hand-written rules, so their accuracy says nothing about real-world performance.</li>
 <li>Nikto does not rate its findings; their severity is estimated from keywords.</li>
 <li>Recommendations are general guidance and must be reviewed by a person before being applied.</li>
</ul>
</body></html>
"""
    try:
        path.write_text(document, encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Cannot write HTML report to {path}: {exc}") from exc
    return str(path)
