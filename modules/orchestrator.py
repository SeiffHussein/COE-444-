"""
modules/orchestrator.py - runs one complete assessment, start to finish.

    authorize -> Nmap -> Nuclei + Nikto -> Lynis -> merge -> ML -> recommendations

app.py calls run_assessment() and only DISPLAYS the result. All scanner logic
lives in the scanner modules.

Combined result (a plain dict):
    scan_id        e.g. "20260501-140322-3fa2"
    target         the target text
    is_sample      True = fixtures, False = real tools were run
    authorized     False = rejected before any tool started
    started_at / finished_at / duration_s
    scans          {"nmap": ScanResult, "nuclei": ..., "nikto": ..., "lynis": ...}
    findings       merged findings of all tools (with ML fields and recommendations)
    ml             {"status": "SUCCESS" | "FAILED" | "SKIPPED", "error": str}
    errors         every problem as readable text (empty list = no problems)
    remediation    None, or the outcome dict of remediation.apply_fix()

One tool failing never stops the others and never erases their findings.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime

from modules import host_auditor, ml_classifier, remediation, target_scanner, tool_utils, vulnerability_scanner
from schemas import TOOLS, sort_by_severity

DEFAULT_OPTIONS = {"run_nuclei": True, "run_nikto": True, "run_lynis": True}


def run_assessment(target: str, sample_mode: bool = True, options: dict | None = None) -> dict:
    """Run the whole pipeline against one authorized target. Never raises.

    Args:
        target: IP / hostname. Must pass validate_target() AND is_authorized().
        sample_mode: True -> every scanner returns labelled fixtures; no tool runs.
        options: optional switches, see DEFAULT_OPTIONS. A switched-off tool is SKIPPED.
    """
    options = {**DEFAULT_OPTIONS, **(options or {})}
    target = target.strip() if isinstance(target, str) else str(target)
    started_at, start = tool_utils.now_text(), time.monotonic()
    result = {
        "scan_id": f"{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}",
        "target": target,
        "is_sample": bool(sample_mode),
        "authorized": False,
        "started_at": started_at, "finished_at": started_at, "duration_s": 0.0,
        "scans": {},
        "findings": [],
        "ml": {"status": "SKIPPED", "error": "Assessment did not run."},
        "errors": [],
        "remediation": None,
    }

    # ---- 1. authorize: format check + permission check, before any tool starts
    reason = tool_utils.check_target(target)
    if reason:
        result["scans"] = {tool: tool_utils.not_run(tool, "SKIPPED", "Target rejected; nothing was scanned.",
                                                    bool(sample_mode)) for tool in TOOLS}
        result["errors"].append(reason)
        return _finish(result, start)
    result["authorized"] = True

    # ---- 2. Nmap discovery
    nmap = _safe("nmap", lambda: target_scanner.scan_target(target, sample_mode), sample_mode)
    web_urls = target_scanner.find_web_urls(nmap["findings"])

    # ---- 3. Nuclei and Nikto
    if not options["run_nuclei"]:
        nuclei = tool_utils.not_run("nuclei", "SKIPPED", "Switched off for this assessment.", sample_mode)
    else:
        nuclei = _safe("nuclei", lambda: vulnerability_scanner.scan_nuclei(target, web_urls, sample_mode), sample_mode)

    if not options["run_nikto"]:
        nikto = tool_utils.not_run("nikto", "SKIPPED", "Switched off for this assessment.", sample_mode)
    elif nmap["status"] != "SUCCESS":
        nikto = tool_utils.not_run("nikto", "SKIPPED",
                                   "Discovery failed, so the web ports are unknown.", sample_mode)
    else:   # scan_nikto itself answers NOT_APPLICABLE when there is no web URL
        nikto = _safe("nikto", lambda: vulnerability_scanner.scan_nikto(target, web_urls, sample_mode), sample_mode)

    # ---- 4. Lynis host audit over SSH
    if not options["run_lynis"]:
        lynis = tool_utils.not_run("lynis", "SKIPPED", "Switched off for this assessment.", sample_mode)
    else:
        lynis = _safe("lynis", lambda: host_auditor.audit_host(target, sample_mode), sample_mode)

    result["scans"] = {"nmap": nmap, "nuclei": nuclei, "nikto": nikto, "lynis": lynis}
    for tool, scan in result["scans"].items():
        if scan["status"] == "FAILED":
            result["errors"].append(f"{tool}: {scan['error']}")

    # ---- 5. merge -> ML -> recommendations
    findings = [f for scan in result["scans"].values() for f in scan["findings"]]
    findings, result["ml"] = ml_classifier.classify_findings(findings)
    if result["ml"]["status"] == "FAILED":
        result["errors"].append(result["ml"]["error"])
    result["findings"] = sort_by_severity(remediation.add_recommendations(findings))
    return _finish(result, start)


def _safe(tool: str, scan, sample_mode: bool) -> dict:
    """Call a scanner; even an unexpected crash becomes a FAILED ScanResult."""
    try:
        return scan()
    except Exception as exc:   # a bug in one scanner must not stop the others
        return tool_utils.not_run(tool, "FAILED", f"Unexpected error: {exc}", bool(sample_mode))


def _finish(result: dict, start: float) -> dict:
    result["finished_at"] = tool_utils.now_text()
    result["duration_s"] = round(time.monotonic() - start, 2)
    return result


def summarize(result: dict) -> dict:
    """Counts used by the dashboard and the reports."""
    findings = result.get("findings", [])
    count = lambda key: {v: sum(1 for f in findings if f.get(key) == v)      # noqa: E731
                         for v in sorted({f.get(key) for f in findings if f.get(key)})}
    return {"total": len(findings), "by_severity": count("severity"),
            "by_ml_priority": count("ml_priority"), "by_tool": count("source")}
