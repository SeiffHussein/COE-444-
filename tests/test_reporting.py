"""Reports: content checks, HTML escaping, empty results, write failures."""

from __future__ import annotations

import csv

import pytest

import schemas
from modules import orchestrator, remediation, reporting

EVIL = "<script>alert('xss')</script>"


@pytest.fixture
def result():
    return orchestrator.run_assessment("127.0.0.1", sample_mode=True)


def read(path) -> str:
    return open(path, encoding="utf-8").read()


def test_csv_report_content(result, tmp_path):
    path = reporting.generate_csv_report(result, str(tmp_path / "sub" / "r.csv"))
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == len(result["findings"]) == 18
    assert tuple(rows[0]) == ("scan_id",) + schemas.FINDING_FIELDS
    assert all(r["scan_id"] == result["scan_id"] and r["is_sample"] == "True" for r in rows)
    first = result["findings"][0]
    assert rows[0]["title"] == first["title"] and rows[0]["original_severity"] == first["original_severity"]
    assert rows[0]["ml_priority"] == first["ml_priority"] and rows[0]["ml_action"] == first["ml_action"]


def test_csv_neutralizes_spreadsheet_formulas(result, tmp_path):
    result["findings"][0]["title"] = "=HYPERLINK(\"http://evil\")"
    path = reporting.generate_csv_report(result, str(tmp_path / "r.csv"))
    with open(path, newline="", encoding="utf-8") as fh:
        assert next(csv.DictReader(fh))["title"].startswith("'=")


def test_html_report_content(result, tmp_path):
    page = read(reporting.generate_html_report(result, str(tmp_path / "r.html")))
    assert page.startswith("<!doctype html>") and "<style>" in page
    assert "<link" not in page and "<script" not in page and "src=" not in page   # self-contained
    for expected in ("Security Assessment Report", result["scan_id"], "127.0.0.1", result["started_at"],
                     result["finished_at"], "SAMPLE DATA", "Tool status", "Total findings: 18",
                     "By normalized severity", "By ML priority", "Limitations", "not exhaustive", "synthetic data"):
        assert expected in page, expected
    for tool in schemas.TOOLS:
        assert f"<td>{tool}</td>" in page
    for f in result["findings"]:
        assert f["ml_priority"] in page and f["ml_action"] in page
    assert "Original severity" in page and "Normalized severity" in page
    assert "(none given by tool)" in page                               # Nmap/Nikto give no severity
    assert "CVE-2021-41773" in page and "SSH-7408" in page
    assert "Remediation outcome" not in page                            # nothing was attempted


def test_html_report_shows_real_label_tool_errors_and_statuses(result, tmp_path):
    result["is_sample"] = False
    result["scans"]["nikto"] = {**result["scans"]["nikto"], "status": "FAILED", "error": "'nikto' is not installed"}
    result["scans"]["lynis"] = {**result["scans"]["lynis"], "status": "NOT_APPLICABLE", "error": "n/a"}
    result["errors"] = ["nikto: 'nikto' is not installed"]
    result["ml"] = {"status": "FAILED", "error": "ML unavailable: model missing"}
    page = read(reporting.generate_html_report(result, str(tmp_path / "r.html")))
    assert "REAL SCAN" in page and "badge sample" not in page.split("</style>")[1]
    assert "class='st-failed'>FAILED" in page and "&#x27;nikto&#x27; is not installed" in page
    assert "NOT_APPLICABLE" in page and "ML unavailable: model missing" in page and "<h2>Errors</h2>" in page


def test_html_escapes_all_scanner_controlled_text(result, tmp_path):
    for f in result["findings"]:
        for name in schemas.TEXT_FIELDS:
            if name not in ("severity", "ml_priority", "ml_action"):
                f[name] = EVIL
    result["target"] = result["scan_id"] = EVIL
    result["errors"] = [EVIL]
    result["scans"]["nmap"]["error"] = EVIL
    result["ml"]["error"] = EVIL
    result["remediation"] = {"finding_id": EVIL, "applied": False, "verified": False, "backup_path": EVIL,
                             "steps": [{"step": 1, "name": EVIL, "ok": False, "detail": EVIL}],
                             "message": EVIL, "simulated": False}
    page = read(reporting.generate_html_report(result, str(tmp_path / "r.html")))
    assert "<script" not in page and "alert('xss')" not in page
    assert page.count("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;") > 50


def test_html_report_includes_remediation_outcome(result, tmp_path):
    finding = next(f for f in result["findings"] if f["remediation_supported"])
    result["remediation"] = remediation.apply_fix(finding, simulate=True)
    page = read(reporting.generate_html_report(result, str(tmp_path / "r.html")))
    assert "Remediation outcome" in page and "SIMULATION (nothing was changed)" in page
    assert "SIMULATED - Would run" in page and finding["id"] in page


def test_reports_handle_empty_result(tmp_path):
    result = orchestrator.run_assessment("8.8.8.8", sample_mode=True)   # rejected -> no findings
    csv_text = read(reporting.generate_csv_report(result, str(tmp_path / "e.csv")))
    assert csv_text.strip() == ",".join(("scan_id",) + schemas.FINDING_FIELDS)
    page = read(reporting.generate_html_report(result, str(tmp_path / "e.html")))
    assert "No findings were recorded" in page and "AUTHORIZED_TARGETS" in page and "SKIPPED" in page


def test_report_write_failure_raises_runtime_error(result, tmp_path):
    blocker = tmp_path / "file.txt"
    blocker.write_text("x")
    for generate in (reporting.generate_csv_report, reporting.generate_html_report):
        with pytest.raises(RuntimeError):
            generate(result, str(blocker / "sub" / "report.out"))
