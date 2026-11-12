"""Orchestrator: authorization first, tool ordering, failures isolated, combined result shape."""

from __future__ import annotations

import pytest

import config
import schemas
from modules import host_auditor, orchestrator, target_scanner, tool_utils, vulnerability_scanner
from tests.conftest import LAB_HOST, completed, fixture_text
from tests.test_contract import assert_finding

RESULT_KEYS = {"scan_id", "target", "is_sample", "authorized", "started_at", "finished_at", "duration_s",
               "scans", "findings", "ml", "errors", "remediation"}


def fake_lab(monkeypatch, nmap="nmap_scan.xml", broken=()):
    """Mock every external call of a real-mode assessment. `broken` = tools that fail."""
    started = []

    def run_tool(args, timeout=None):
        tool = args[0]
        started.append(tool)
        if tool in broken:
            raise RuntimeError(f"'{tool}' is not installed or not on PATH.")
        if tool == "nmap":
            return completed(fixture_text(nmap))
        if tool == "nuclei":
            return completed(fixture_text("nuclei_results.jsonl"))
        if tool == "nikto":
            with open(args[args.index("-output") + 1], "w", encoding="utf-8") as fh:
                fh.write(fixture_text("nikto_results.json"))
            return completed()
        raise AssertionError(f"unexpected tool {tool}")

    def run_ssh(host, command, timeout=None):
        started.append("lynis")
        if "lynis" in broken:
            return completed(stderr="ssh: connect to host port 22: Connection timed out", returncode=255)
        return completed(fixture_text("lynis_report.dat"))

    monkeypatch.setattr(tool_utils, "run_tool", run_tool)
    monkeypatch.setattr(tool_utils, "run_ssh", run_ssh)
    return started


def test_sample_assessment_end_to_end(monkeypatch):
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("sample mode must not run tools"))
    monkeypatch.setattr(tool_utils, "run_ssh", lambda *a, **k: pytest.fail("sample mode must not use ssh"))
    result = orchestrator.run_assessment("127.0.0.1", sample_mode=True)
    assert set(result) == RESULT_KEYS and result["authorized"] is True and result["is_sample"] is True
    assert result["errors"] == [] and result["remediation"] is None and result["scan_id"]
    assert set(result["scans"]) == set(schemas.TOOLS)
    for scan in result["scans"].values():
        assert scan["status"] == "SUCCESS" and scan["is_sample"] is True
        schemas.validate_scan_result(scan)
    assert len(result["findings"]) == 3 + 4 + 4 + 7 == sum(len(s["findings"]) for s in result["scans"].values())
    assert result["ml"] == {"status": "SUCCESS", "error": ""}
    for f in result["findings"]:
        assert_finding(f)
        assert f["is_sample"] and f["ml_priority"] and f["ml_action"] and f["recommendation"]
    scores = [schemas.SEVERITY_SCORES[f["severity"]] for f in result["findings"]]
    assert scores == sorted(scores, reverse=True)
    assert sum(f["remediation_supported"] for f in result["findings"]) == 1
    summary = orchestrator.summarize(result)
    assert summary["total"] == 18 and sum(summary["by_severity"].values()) == 18
    assert summary["by_tool"] == {"lynis": 7, "nikto": 4, "nmap": 3, "nuclei": 4}


def test_real_assessment_runs_tools_in_order(monkeypatch):
    started = fake_lab(monkeypatch)
    result = orchestrator.run_assessment(LAB_HOST, sample_mode=False)
    assert started[:3] == ["nmap", "nuclei", "nikto"] and started[-1] == "lynis"
    assert started.count("nikto") == 2                                 # one run per discovered web port
    assert result["is_sample"] is False and result["errors"] == []
    assert all(s["status"] == "SUCCESS" and not s["is_sample"] for s in result["scans"].values())
    assert not any(f["is_sample"] for f in result["findings"])


@pytest.mark.parametrize("target, text", [("8.8.8.8", "AUTHORIZED_TARGETS"), ("scanme.nmap.org", "AUTHORIZED_TARGETS"),
                                          ("-oN /tmp/x", "format"), ("", "format")])
def test_unauthorized_or_invalid_target_is_rejected_before_any_scan(monkeypatch, target, text):
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("no tool may start"))
    monkeypatch.setattr(tool_utils, "run_ssh", lambda *a, **k: pytest.fail("no ssh may start"))
    for scanner, name in ((target_scanner, "scan_target"), (vulnerability_scanner, "scan_nuclei"),
                          (vulnerability_scanner, "scan_nikto"), (host_auditor, "audit_host")):
        monkeypatch.setattr(scanner, name, lambda *a, **k: pytest.fail("no scanner may be called"))
    for sample_mode in (True, False):
        result = orchestrator.run_assessment(target, sample_mode=sample_mode)
        assert set(result) == RESULT_KEYS and result["authorized"] is False
        assert result["findings"] == [] and text in result["errors"][0]
        assert all(s["status"] == "SKIPPED" for s in result["scans"].values())


@pytest.mark.parametrize("broken", ["nuclei", "nikto", "lynis"])
def test_one_tool_failing_does_not_stop_or_erase_the_others(monkeypatch, broken):
    fake_lab(monkeypatch, broken=(broken,))
    result = orchestrator.run_assessment(LAB_HOST, sample_mode=False)
    assert result["scans"][broken]["status"] == "FAILED" and result["scans"][broken]["error"]
    assert any(e.startswith(f"{broken}:") for e in result["errors"])
    others = [t for t in schemas.TOOLS if t != broken]
    assert all(result["scans"][t]["status"] == "SUCCESS" and result["scans"][t]["findings"] for t in others)
    assert {f["source"] for f in result["findings"]} == set(others)
    assert result["ml"]["status"] == "SUCCESS"


def test_nmap_failure_skips_nikto_but_nuclei_and_lynis_still_run(monkeypatch):
    fake_lab(monkeypatch, broken=("nmap",))
    result = orchestrator.run_assessment(LAB_HOST, sample_mode=False)
    scans = result["scans"]
    assert scans["nmap"]["status"] == "FAILED"
    assert scans["nikto"]["status"] == "SKIPPED" and "web ports are unknown" in scans["nikto"]["error"]
    assert scans["nuclei"]["status"] == "SUCCESS" and scans["lynis"]["status"] == "SUCCESS"
    assert {f["source"] for f in result["findings"]} == {"nuclei", "lynis"}


def test_nikto_not_applicable_when_no_web_port(monkeypatch):
    started = fake_lab(monkeypatch, nmap="nmap_no_open_ports.xml")
    result = orchestrator.run_assessment(LAB_HOST, sample_mode=False)
    assert result["scans"]["nikto"]["status"] == "NOT_APPLICABLE" and "nikto" not in started
    assert result["scans"]["nmap"]["status"] == "SUCCESS" and result["scans"]["nmap"]["findings"] == []
    assert not any(e.startswith("nikto") for e in result["errors"])    # not applicable is not an error


def test_scanner_crash_becomes_failed_result(monkeypatch):
    fake_lab(monkeypatch)
    monkeypatch.setattr(vulnerability_scanner, "scan_nuclei", lambda *a, **k: 1 / 0)
    result = orchestrator.run_assessment(LAB_HOST, sample_mode=False)
    assert result["scans"]["nuclei"]["status"] == "FAILED" and "Unexpected error" in result["scans"]["nuclei"]["error"]
    assert result["scans"]["lynis"]["status"] == "SUCCESS"


def test_options_switch_tools_off(monkeypatch):
    started = fake_lab(monkeypatch)
    result = orchestrator.run_assessment(LAB_HOST, False, {"run_nuclei": False, "run_nikto": False, "run_lynis": False})
    assert started == ["nmap"]
    assert [result["scans"][t]["status"] for t in schemas.TOOLS] == ["SUCCESS", "SKIPPED", "SKIPPED", "SKIPPED"]


def test_missing_model_keeps_findings_and_reports_ml_error(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ACTION_MODEL_PATH", tmp_path / "missing.joblib")
    result = orchestrator.run_assessment("127.0.0.1", sample_mode=True)
    assert result["ml"]["status"] == "FAILED" and any("ML unavailable" in e for e in result["errors"])
    assert len(result["findings"]) == 18
    assert all(f["ml_priority"] == "" and f["ml_action"] == "" and f["recommendation"] for f in result["findings"])
