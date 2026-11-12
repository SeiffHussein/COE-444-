"""Nmap, Nuclei and Nikto: success, empty-success, missing tool, timeout, malformed output,
non-zero exit - all with the external tool mocked."""

from __future__ import annotations

import json
import subprocess

import pytest

from modules import target_scanner, tool_utils, vulnerability_scanner
from tests.conftest import LAB_HOST, completed, fixture_text
from tests.test_contract import assert_finding

WEB_URLS = [f"http://{LAB_HOST}:80"]


def fake_tool(monkeypatch, stdout="", stderr="", returncode=0, nikto_report=None):
    """Replace tool_utils.run_tool. Records the argument lists it was called with."""
    calls = []

    def run_tool(args, timeout=None):
        calls.append(args)
        if nikto_report is not None and "-output" in args:      # Nikto writes its report to a file
            with open(args[args.index("-output") + 1], "w", encoding="utf-8") as fh:
                fh.write(nikto_report)
        return completed(stdout, stderr, returncode)
    monkeypatch.setattr(tool_utils, "run_tool", run_tool)
    return calls


def tool_missing(monkeypatch):
    monkeypatch.setattr(tool_utils.shutil, "which", lambda name: None)


def tool_times_out(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="tool", timeout=1)
    monkeypatch.setattr(tool_utils.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(subprocess, "run", timeout)


def assert_failed(result, tool, text):
    assert result["tool"] == tool and result["status"] == "FAILED"
    assert text.lower() in result["error"].lower()
    assert result["findings"] == []


# ====================================================================== Nmap
def test_nmap_success(monkeypatch):
    calls = fake_tool(monkeypatch, stdout=fixture_text("nmap_scan.xml"))
    result = target_scanner.scan_target(LAB_HOST)
    assert result["status"] == "SUCCESS" and result["tool"] == "nmap" and result["is_sample"] is False
    assert result["started_at"] and result["finished_at"]
    assert [(f["port"], f["service"]) for f in result["findings"]] == [(22, "ssh"), (80, "http"), (443, "https")]
    for f in result["findings"]:
        assert_finding(f)
        assert f["severity"] == "Info" and f["original_severity"] == ""   # discovery, not a vulnerability
        assert f["cve"] == "" and f["is_sample"] is False
    assert "OpenSSH 9.6p1" in result["findings"][0]["evidence"]
    args = calls[0]
    assert args[0] == "nmap" and "-sV" in args and args[-1] == LAB_HOST
    assert args[args.index("-oX") + 1] == "-" and "--top-ports" in args


def test_nmap_empty_success(monkeypatch):
    fake_tool(monkeypatch, stdout=fixture_text("nmap_no_open_ports.xml"))
    result = target_scanner.scan_target(LAB_HOST)
    assert result["status"] == "SUCCESS" and result["findings"] == [] and result["error"] == ""


def test_nmap_missing_tool(monkeypatch):
    tool_missing(monkeypatch)
    assert_failed(target_scanner.scan_target(LAB_HOST), "nmap", "not installed")


def test_nmap_timeout(monkeypatch):
    tool_times_out(monkeypatch)
    assert_failed(target_scanner.scan_target(LAB_HOST), "nmap", "timed out")


@pytest.mark.parametrize("output", ["", "this is not xml", "<html><body>oops</body></html>", "<nmaprun><host>"])
def test_nmap_malformed_output(monkeypatch, output):
    fake_tool(monkeypatch, stdout=output)
    assert_failed(target_scanner.scan_target(LAB_HOST), "nmap", "parse")


def test_nmap_nonzero_exit(monkeypatch):
    fake_tool(monkeypatch, stderr="Failed to resolve target", returncode=1)
    assert_failed(target_scanner.scan_target(LAB_HOST), "nmap", "exit 1")


def test_nmap_host_down_is_failed_not_clean(monkeypatch):
    fake_tool(monkeypatch, stdout='<nmaprun><runstats><hosts up="0" down="1" total="1"/></runstats></nmaprun>')
    assert_failed(target_scanner.scan_target(LAB_HOST), "nmap", "did not respond")


def test_find_web_urls():
    findings = target_scanner._parse_nmap_xml(fixture_text("nmap_scan.xml"), LAB_HOST)
    assert target_scanner.find_web_urls(findings) == [f"http://{LAB_HOST}:80", f"https://{LAB_HOST}:443"]
    assert target_scanner.find_web_urls(findings[:1]) == []            # ssh only


# ====================================================================== Nuclei
def test_nuclei_success(monkeypatch):
    calls = fake_tool(monkeypatch, stdout=fixture_text("nuclei_results.jsonl"))
    result = vulnerability_scanner.scan_nuclei(LAB_HOST, WEB_URLS)
    assert result["status"] == "SUCCESS" and len(result["findings"]) == 4
    cve = result["findings"][0]
    assert_finding(cve)
    assert cve["check_id"] == "CVE-2021-41773" and cve["cve"] == "CVE-2021-41773"
    assert cve["title"].startswith("Apache 2.4.49")
    assert cve["original_severity"] == "critical" and cve["severity"] == "Critical"
    assert cve["evidence"].startswith(f"http://{LAB_HOST}/cgi-bin/") and cve["port"] == 80
    headers = result["findings"][1]
    assert headers["cve"] == "" and headers["original_severity"] == "info"   # no CVE invented
    assert result["findings"][2]["port"] == 443 and result["findings"][3]["port"] == 22
    args = calls[0]
    assert args[0] == "nuclei" and args[args.index("-u") + 1] == WEB_URLS[0]
    assert "-jsonl" in args and "-rate-limit" in args


def test_nuclei_scans_bare_target_without_web_urls(monkeypatch):
    calls = fake_tool(monkeypatch)
    vulnerability_scanner.scan_nuclei(LAB_HOST, [])
    assert calls[0][calls[0].index("-u") + 1] == LAB_HOST


def test_nuclei_empty_success(monkeypatch):
    fake_tool(monkeypatch, stdout="")
    result = vulnerability_scanner.scan_nuclei(LAB_HOST, WEB_URLS)
    assert result["status"] == "SUCCESS" and result["findings"] == []


def test_nuclei_missing_tool(monkeypatch):
    tool_missing(monkeypatch)
    assert_failed(vulnerability_scanner.scan_nuclei(LAB_HOST, WEB_URLS), "nuclei", "not installed")


def test_nuclei_timeout(monkeypatch):
    tool_times_out(monkeypatch)
    assert_failed(vulnerability_scanner.scan_nuclei(LAB_HOST, WEB_URLS), "nuclei", "timed out")


@pytest.mark.parametrize("output", ["[ERR] could not load templates", '{"unexpected": true}\n{broken'])
def test_nuclei_malformed_output(monkeypatch, output):
    fake_tool(monkeypatch, stdout=output)
    assert_failed(vulnerability_scanner.scan_nuclei(LAB_HOST, WEB_URLS), "nuclei", "malformed")


def test_nuclei_nonzero_exit(monkeypatch):
    fake_tool(monkeypatch, stderr="no templates provided for scan", returncode=2)
    assert_failed(vulnerability_scanner.scan_nuclei(LAB_HOST, WEB_URLS), "nuclei", "exit 2")


# ====================================================================== Nikto
def test_nikto_success(monkeypatch):
    calls = fake_tool(monkeypatch, nikto_report=fixture_text("nikto_results.json"))
    result = vulnerability_scanner.scan_nikto(LAB_HOST, WEB_URLS)
    assert result["status"] == "SUCCESS" and len(result["findings"]) == 4
    for f in result["findings"]:
        assert_finding(f)
        assert f["source"] == "nikto" and f["port"] == 80 and f["service"] == "http"
        assert f["original_severity"] == "" and f["cve"] == ""          # Nikto gives neither
    assert [f["severity"] for f in result["findings"]] == ["Low", "Medium", "Medium", "Low"]
    assert result["findings"][0]["check_id"] == "999957"
    args = calls[0]
    assert args[:3] == ["nikto", "-h", WEB_URLS[0]] and "-maxtime" in args
    assert args[args.index("-Format") + 1] == "json"


def test_nikto_not_applicable_without_web_port(monkeypatch):
    calls = fake_tool(monkeypatch)
    for urls in ([], None):
        result = vulnerability_scanner.scan_nikto(LAB_HOST, urls)
        assert result["status"] == "NOT_APPLICABLE" and result["findings"] == []
        assert "no HTTP/HTTPS port" in result["error"]
    assert calls == []                                                  # Nikto was never started


def test_nikto_empty_success(monkeypatch):
    fake_tool(monkeypatch, nikto_report=json.dumps([{"host": LAB_HOST, "port": "80", "vulnerabilities": []}]))
    result = vulnerability_scanner.scan_nikto(LAB_HOST, WEB_URLS)
    assert result["status"] == "SUCCESS" and result["findings"] == []


def test_nikto_missing_tool(monkeypatch):
    tool_missing(monkeypatch)
    assert_failed(vulnerability_scanner.scan_nikto(LAB_HOST, WEB_URLS), "nikto", "not installed")


def test_nikto_timeout(monkeypatch):
    tool_times_out(monkeypatch)
    assert_failed(vulnerability_scanner.scan_nikto(LAB_HOST, WEB_URLS), "nikto", "timed out")


@pytest.mark.parametrize("report", ["{not json", '"just a string"', "[1, 2]"])
def test_nikto_malformed_output(monkeypatch, report):
    fake_tool(monkeypatch, nikto_report=report)
    assert_failed(vulnerability_scanner.scan_nikto(LAB_HOST, WEB_URLS), "nikto", "malformed")


def test_nikto_nonzero_exit_without_report(monkeypatch):
    fake_tool(monkeypatch, stderr="+ ERROR: Host maximum execution time reached", returncode=1, nikto_report="")
    assert_failed(vulnerability_scanner.scan_nikto(LAB_HOST, WEB_URLS), "nikto", "exit 1")


def test_nikto_one_url_fails_other_findings_survive(monkeypatch):
    def run_tool(args, timeout=None):
        report = fixture_text("nikto_results.json") if ":80" in args[2] else "{broken"
        with open(args[args.index("-output") + 1], "w", encoding="utf-8") as fh:
            fh.write(report)
        return completed()
    monkeypatch.setattr(tool_utils, "run_tool", run_tool)
    result = vulnerability_scanner.scan_nikto(LAB_HOST, [f"http://{LAB_HOST}:80", f"https://{LAB_HOST}:443"])
    assert result["status"] == "FAILED" and ":443" in result["error"]
    assert len(result["findings"]) == 4


# ====================================================================== all scanners
@pytest.mark.parametrize("scan", [
    lambda t, s: target_scanner.scan_target(t, sample_mode=s),
    lambda t, s: vulnerability_scanner.scan_nuclei(t, WEB_URLS, sample_mode=s),
    lambda t, s: vulnerability_scanner.scan_nikto(t, WEB_URLS, sample_mode=s),
])
def test_scanners_reject_bad_and_unauthorized_targets(monkeypatch, scan):
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("tool must not start"))
    for sample_mode in (False, True):
        assert "AUTHORIZED_TARGETS" in scan("8.8.8.8", sample_mode)["error"]
        assert scan("8.8.8.8", sample_mode)["status"] == "FAILED"
        assert "format" in scan("-oN /tmp/x", sample_mode)["error"]


@pytest.mark.parametrize("scan, tool", [
    (lambda: target_scanner.scan_target("127.0.0.1", sample_mode=True), "nmap"),
    (lambda: vulnerability_scanner.scan_nuclei("127.0.0.1", WEB_URLS, sample_mode=True), "nuclei"),
    (lambda: vulnerability_scanner.scan_nikto("127.0.0.1", WEB_URLS, sample_mode=True), "nikto"),
])
def test_sample_mode_returns_labelled_fixtures_without_running_tools(monkeypatch, scan, tool):
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("tool must not start"))
    result = scan()
    assert result["tool"] == tool and result["status"] == "SUCCESS" and result["is_sample"] is True
    assert result["findings"]
    for f in result["findings"]:
        assert_finding(f)
        assert f["is_sample"] is True and f["description"].startswith("SAMPLE DATA")
        assert f["target"] == "127.0.0.1" and "192.0.2.10" not in f["evidence"]
