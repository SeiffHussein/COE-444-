"""Contract v2: finding format, ScanResult wrapper, target format + authorization."""

from __future__ import annotations

import subprocess

import pytest

import config
import schemas
from modules import tool_utils
from tests.conftest import LAB_HOST


def assert_finding(f: dict) -> None:
    assert tuple(f) == schemas.FINDING_FIELDS
    assert f["severity"] in schemas.SEVERITIES
    assert f["ml_priority"] in ("",) + schemas.ML_PRIORITIES
    assert f["ml_action"] in ("",) + schemas.ML_ACTIONS
    assert f["port"] is None or isinstance(f["port"], int)
    assert isinstance(f["remediation_supported"], bool) and isinstance(f["is_sample"], bool)
    assert f["id"] and f["target"] and f["source"] and f["title"]


# ------------------------------------------------------------------ finding
def test_finding_defaults_are_unknown_not_invented():
    f = schemas.new_finding("10.0.0.1", "nmap", "Open port 22/tcp")
    assert_finding(f)
    assert f["severity"] == "Info" and len(f["id"]) == 8
    assert f["port"] is None
    assert f["original_severity"] == f["service"] == f["cve"] == f["check_id"] == ""
    assert f["ml_priority"] == f["ml_action"] == f["recommendation"] == ""
    assert f["remediation_supported"] is False and f["is_sample"] is False


def test_label_sets_match_the_contract():
    assert set(schemas.ML_PRIORITIES) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert set(schemas.ML_ACTIONS) == {
        "REVIEW_SERVICE", "PATCH_OR_UPDATE", "HARDEN_SSH", "HARDEN_WEB_SERVER",
        "REVIEW_TLS", "INVESTIGATE_FINDING", "NO_ACTION_INFORMATIONAL"}
    assert schemas.SCAN_STATUSES == ("SUCCESS", "FAILED", "SKIPPED", "NOT_APPLICABLE")


@pytest.mark.parametrize("bad", [
    {"severity": "urgent"}, {"ml_priority": "P1"}, {"ml_action": "rm -rf /"},
    {"port": 70000}, {"port": "ssh"}, {"is_sample": "yes"}, {"remediation_supported": 1},
])
def test_finding_rejects_invalid_values(bad):
    with pytest.raises(ValueError):
        schemas.new_finding("h", "nmap", "t", **bad)


def test_finding_rejects_empty_required_and_unknown_fields():
    with pytest.raises(ValueError):
        schemas.new_finding("", "nmap", "t")
    with pytest.raises(TypeError):
        schemas.validate_finding({"target": "h", "source": "x", "title": "t", "cvss": "9.8"})
    assert_finding(schemas.validate_finding({"target": "h", "source": "x", "title": "t"}))


def test_severity_normalization_and_port_conversion():
    assert schemas.new_finding("h", "nmap", "t", severity="high", port="22")["severity"] == "High"
    assert schemas.new_finding("h", "nmap", "t", port="22")["port"] == 22
    assert schemas.normalize_severity("informational") == "Info"
    assert schemas.normalize_severity("WARNING") == "Medium"
    assert schemas.normalize_severity("suggestion") == "Low"
    assert schemas.normalize_severity(None) == "Info"


def test_extract_cve_only_copies_what_is_there():
    assert schemas.extract_cve("see cve-2021-41773 and CVE-2021-41773, CVE-2023-1234") == "CVE-2021-41773, CVE-2023-1234"
    assert schemas.extract_cve("Apache looks outdated") == ""
    assert schemas.extract_cve(None) == ""


# ------------------------------------------------------------------ scan result
def test_scan_result_shape_and_validation():
    f = schemas.new_finding("h", "nmap", "t")
    result = schemas.new_scan_result("nmap", "SUCCESS", [f], duration_s=1.234)
    assert tuple(result) == schemas.SCAN_RESULT_FIELDS
    assert result["findings"] == [f] and result["duration_s"] == 1.23 and result["is_sample"] is False


def test_failed_scan_must_carry_an_error():
    with pytest.raises(ValueError):
        schemas.new_scan_result("nmap", "FAILED", [], error="")
    assert schemas.new_scan_result("nmap", "FAILED", [], error="nmap missing")["error"] == "nmap missing"


@pytest.mark.parametrize("kwargs", [{"tool": "metasploit", "status": "SUCCESS"}, {"tool": "nmap", "status": "OK"}])
def test_scan_result_rejects_unknown_tool_or_status(kwargs):
    with pytest.raises(ValueError):
        schemas.new_scan_result(**kwargs)


def test_scan_result_rejects_bad_findings_and_missing_keys():
    with pytest.raises((ValueError, TypeError)):
        schemas.new_scan_result("nmap", "SUCCESS", [{"title": "no target"}])
    with pytest.raises(TypeError):
        schemas.validate_scan_result({"tool": "nmap", "status": "SUCCESS"})


# ------------------------------------------------------------------ target format
@pytest.mark.parametrize("target", ["127.0.0.1", "192.168.1.10", "192.168.1.0/24", "::1", "localhost", "scanme.nmap.org"])
def test_validate_target_accepts(target):
    assert tool_utils.validate_target(target) is True


@pytest.mark.parametrize("target", ["", "   ", "-oN /tmp/x", "10.0.0.0/8", "999.1.1.1", "host; rm -rf /",
                                    "http://example.com", "a b", "host:80", "$(whoami)", "x" * 300, None, 123])
def test_validate_target_rejects(target):
    assert tool_utils.validate_target(target) is False


# ------------------------------------------------------------------ authorization
def test_authorization_is_separate_from_format():
    assert tool_utils.validate_target("scanme.nmap.org") is True       # well formed ...
    assert tool_utils.is_authorized("scanme.nmap.org") is False        # ... but not allowed
    assert tool_utils.is_authorized(LAB_HOST) and tool_utils.is_authorized(" 127.0.0.1 ")
    assert tool_utils.is_authorized("192.0.2.0/24") is False           # no range matching
    assert tool_utils.is_authorized(None) is False
    assert tool_utils.check_target(LAB_HOST) == ""
    assert "AUTHORIZED_TARGETS" in tool_utils.check_target("8.8.8.8")
    assert "format" in tool_utils.check_target("bad target!")


def test_empty_vm_ip_is_never_authorized(monkeypatch):
    monkeypatch.setattr(config, "AUTHORIZED_TARGETS", ["127.0.0.1", ""])
    assert tool_utils.is_authorized("") is False


# ------------------------------------------------------------------ run_tool / run_ssh
def test_run_tool_requires_argument_list():
    with pytest.raises(ValueError):
        tool_utils.run_tool("nmap 127.0.0.1")  # type: ignore[arg-type]


def test_run_tool_missing_tool_and_timeout(monkeypatch):
    monkeypatch.setattr(tool_utils.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="not installed"):
        tool_utils.run_tool(["nmap", "127.0.0.1"])

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=1)
    monkeypatch.setattr(tool_utils.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(RuntimeError, match="timed out"):
        tool_utils.run_tool(["nmap", "127.0.0.1"], timeout=1)


def test_run_ssh_builds_safe_argument_list(monkeypatch):
    seen = {}
    monkeypatch.setattr(tool_utils, "run_tool", lambda args, timeout=None: seen.update(args=args, timeout=timeout))
    tool_utils.run_ssh(LAB_HOST, "sudo -n sshd -T")
    args = seen["args"]
    assert args[0] == "ssh" and args[-2] == f"labadmin@{LAB_HOST}" and args[-1] == "sudo -n sshd -T"
    assert args[args.index("-i") + 1] == "/nonexistent/test_key"
    assert "BatchMode=yes" in args and f"ConnectTimeout={config.SSH_CONNECT_TIMEOUT}" in args


def test_run_ssh_refuses_unauthorized_host_and_missing_user(monkeypatch):
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("ssh must not start"))
    with pytest.raises(RuntimeError, match="AUTHORIZED_TARGETS"):
        tool_utils.run_ssh("8.8.8.8", "id")
    monkeypatch.setattr(config, "SSH_USER", "")
    with pytest.raises(RuntimeError, match="not configured"):
        tool_utils.run_ssh(LAB_HOST, "id")
