"""Lynis over SSH: every remote call is mocked (tool_utils.run_ssh)."""

from __future__ import annotations

import subprocess

import pytest

from modules import host_auditor, tool_utils
from tests.conftest import LAB_HOST, completed, fixture_text
from tests.test_contract import assert_finding


def fake_ssh(monkeypatch, audit=None, report=None):
    """Replace tool_utils.run_ssh with canned answers for the two Lynis commands."""
    calls = []

    def run_ssh(host, command, timeout=None):
        calls.append((host, command))
        if command == host_auditor.LYNIS_AUDIT_COMMAND:
            return audit or completed("Lynis audit finished")
        if command == host_auditor.LYNIS_REPORT_COMMAND:
            return report or completed(fixture_text("lynis_report.dat"))
        raise AssertionError(f"unexpected remote command: {command}")
    monkeypatch.setattr(tool_utils, "run_ssh", run_ssh)
    return calls


def assert_failed(result, text):
    assert result["tool"] == "lynis" and result["status"] == "FAILED"
    assert text.lower() in result["error"].lower() and result["findings"] == []


def test_lynis_success(monkeypatch):
    calls = fake_ssh(monkeypatch)
    result = host_auditor.audit_host(LAB_HOST)
    assert result["status"] == "SUCCESS" and result["is_sample"] is False
    assert [c[1] for c in calls] == ["sudo -n lynis audit system --quick --no-colors",
                                     "sudo -n cat /var/log/lynis-report.dat"]
    assert all(host == LAB_HOST for host, _ in calls)
    findings = result["findings"]
    for f in findings:
        assert_finding(f)
        assert f["source"] == "lynis" and f["target"] == LAB_HOST and f["cve"] == "" and f["port"] is None
    warnings = [f for f in findings if f["original_severity"] == "warning"]
    suggestions = [f for f in findings if f["original_severity"] == "suggestion"]
    info = [f for f in findings if f["original_severity"] == "info"]
    assert len(warnings) == 2 and all(f["severity"] == "Medium" for f in warnings)
    assert len(suggestions) == 4 and all(f["severity"] == "Low" for f in suggestions)
    assert [f["check_id"] for f in warnings] == ["FIRE-4512", "PKGS-7392"]
    # informational output is kept apart from warnings/suggestions
    assert len(info) == 1 and info[0]["severity"] == "Info" and "63" in info[0]["title"] and info[0]["check_id"] == ""
    root = next(f for f in findings if "PermitRootLogin" in f["title"])
    assert root["check_id"] == "SSH-7408" and root["service"] == "ssh"
    assert root["evidence"].startswith("suggestion[]=SSH-7408|")


def test_lynis_empty_success(monkeypatch):
    fake_ssh(monkeypatch, report=completed("lynis_version=3.0.9\nos=Linux\n"))
    result = host_auditor.audit_host(LAB_HOST)
    assert result["status"] == "SUCCESS" and result["findings"] == []


def test_lynis_auth_failure(monkeypatch):
    fake_ssh(monkeypatch, audit=completed(stderr="labadmin@192.0.2.10: Permission denied (publickey).", returncode=255))
    assert_failed(host_auditor.audit_host(LAB_HOST), "authentication failed")


@pytest.mark.parametrize("stderr", ["ssh: connect to host 192.0.2.10 port 22: Connection timed out",
                                    "ssh: connect to host 192.0.2.10 port 22: No route to host",
                                    "ssh: connect to host 192.0.2.10 port 22: Connection refused"])
def test_lynis_unreachable_host(monkeypatch, stderr):
    fake_ssh(monkeypatch, audit=completed(stderr=stderr, returncode=255))
    assert_failed(host_auditor.audit_host(LAB_HOST), "unreachable")


def test_lynis_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=1)
    monkeypatch.setattr(tool_utils.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(subprocess, "run", timeout)
    assert_failed(host_auditor.audit_host(LAB_HOST), "timed out")


def test_lynis_ssh_binary_missing(monkeypatch):
    monkeypatch.setattr(tool_utils.shutil, "which", lambda name: None)
    assert_failed(host_auditor.audit_host(LAB_HOST), "'ssh' is not installed")


def test_lynis_not_installed_on_vm(monkeypatch):
    fake_ssh(monkeypatch, audit=completed(stderr="sudo: lynis: command not found", returncode=1))
    assert_failed(host_auditor.audit_host(LAB_HOST), "not installed on the VM")


def test_lynis_sudo_needs_password(monkeypatch):
    fake_ssh(monkeypatch, audit=completed(stderr="sudo: a password is required", returncode=1))
    assert_failed(host_auditor.audit_host(LAB_HOST), "sudoers")


def test_lynis_report_unreadable(monkeypatch):
    fake_ssh(monkeypatch, report=completed(stderr="cat: /var/log/lynis-report.dat: No such file or directory", returncode=1))
    assert_failed(host_auditor.audit_host(LAB_HOST), "could not read")


@pytest.mark.parametrize("text", ["", "garbage without structure", "<html>captive portal</html>", "foo=bar\n"])
def test_lynis_malformed_report(monkeypatch, text):
    fake_ssh(monkeypatch, report=completed(text))
    assert_failed(host_auditor.audit_host(LAB_HOST), "malformed")


def test_lynis_rejects_unauthorized_target_and_unconfigured_ssh(monkeypatch):
    import config
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("ssh must not start"))
    assert_failed(host_auditor.audit_host("8.8.8.8"), "AUTHORIZED_TARGETS")
    monkeypatch.setattr(config, "SSH_USER", "")
    assert_failed(host_auditor.audit_host(LAB_HOST), "not configured")


def test_lynis_sample_mode(monkeypatch):
    monkeypatch.setattr(tool_utils, "run_ssh", lambda *a, **k: pytest.fail("ssh must not start"))
    result = host_auditor.audit_host("127.0.0.1", sample_mode=True)
    assert result["status"] == "SUCCESS" and result["is_sample"] is True and len(result["findings"]) == 7
    assert all(f["is_sample"] and f["target"] == "127.0.0.1" for f in result["findings"])
