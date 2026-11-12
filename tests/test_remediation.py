"""Recommendations and every guard of the one automatic fix. The VM is simulated by FakeVM."""

from __future__ import annotations

import pytest

import config
import schemas
from modules import host_auditor, remediation, tool_utils
from tests.conftest import LAB_HOST, completed, fixture_text

R = remediation


class FakeVM:
    """Pretends to be the lab VM: answers the constant remote commands and remembers state."""

    def __init__(self, root_login="yes", sshd_config="sshd_config_with_include.txt", dropin_exists=False,
                 validate_ok=True, services="active\ninactive\n", reload_ok=True,
                 fix_takes_effect=True, login_after_ok=True, uid="1000"):
        self.root_login, self.sshd_config = root_login, fixture_text(sshd_config)
        self.dropin, self.old_dropin = ("old" if dropin_exists else None), dropin_exists
        self.validate_ok, self.services, self.reload_ok = validate_ok, services, reload_ok
        self.fix_takes_effect, self.login_after_ok, self.uid = fix_takes_effect, login_after_ok, uid
        self.reloaded, self.commands = [], []

    def __call__(self, host, command, timeout=None):
        assert host == LAB_HOST
        self.commands.append(command)
        if command == R.CMD_EFFECTIVE_CONFIG:
            value = "no" if (self.dropin == "new" and self.fix_takes_effect) else self.root_login
            return completed(fixture_text("sshd_T_root_yes.txt").replace("permitrootlogin yes", f"permitrootlogin {value}"))
        if command == R.CMD_CONNECT_TEST:
            if self.reloaded and not self.login_after_ok:
                return completed(stderr="ssh: connect to host 192.0.2.10 port 22: Connection refused", returncode=255)
            return completed(f"coe444-ok\n{self.uid}\n")
        if command == R.CMD_READ_SSHD_CONFIG:
            return completed(self.sshd_config)
        if command == R.CMD_DROPIN_EXISTS:
            return completed("present\n" if self.dropin else "absent\n")
        if command.startswith(f"mkdir -p {R.BACKUP_DIR} && cp -p {R.DROPIN_PATH} "):
            return completed()
        if command == R.CMD_WRITE_DROPIN:
            self.dropin = "new"
            return completed()
        if command == R.CMD_VALIDATE:
            return completed() if self.validate_ok else completed(stderr="sshd_config line 1: bad option", returncode=255 - 1)
        if command == R.CMD_REMOVE_DROPIN:
            self.dropin = None
            return completed()
        if command.startswith(f"cat {R.BACKUP_DIR}/") and command.endswith(f"| sudo -n tee {R.DROPIN_PATH} > /dev/null"):
            self.dropin = "old"
            return completed()
        if command == R.CMD_ACTIVE_SERVICES:
            return completed(self.services, returncode=0 if "active\n" in self.services else 3)
        if command in ("sudo -n systemctl reload ssh", "sudo -n systemctl reload sshd"):
            if self.reload_ok:
                self.reloaded.append(command.split()[-1])
            return completed() if self.reload_ok else completed(stderr="Job for ssh.service failed", returncode=1)
        raise AssertionError(f"unexpected remote command: {command}")

    @property
    def changed(self) -> bool:
        return any(c == R.CMD_WRITE_DROPIN for c in self.commands)


@pytest.fixture
def root_finding():
    findings = host_auditor._parse_lynis_report(fixture_text("lynis_report.dat"), LAB_HOST)
    return next(f for f in R.add_recommendations(findings) if f["remediation_supported"])


@pytest.fixture
def vm(monkeypatch):
    """Install a FakeVM and switch remediation on. Tests may replace attributes."""
    fake = FakeVM()
    monkeypatch.setattr(tool_utils, "run_ssh", lambda host, command, timeout=None: fake(host, command, timeout))
    monkeypatch.setattr(config, "ALLOW_AUTO_REMEDIATION", True)
    return fake


def failed_steps(outcome):
    return [s["name"] for s in outcome["steps"] if not s["ok"]]


# ====================================================================== recommendations
def test_only_the_root_login_finding_is_remediation_supported():
    findings = R.add_recommendations(host_auditor._parse_lynis_report(fixture_text("lynis_report.dat"), LAB_HOST))
    supported = [f for f in findings if f["remediation_supported"]]
    assert len(supported) == 1 and "PermitRootLogin (set YES to NO)" in supported[0]["title"]
    assert all(f["recommendation"] for f in findings)


@pytest.mark.parametrize("title, expected", [
    ("Consider hardening SSH configuration: PermitRootLogin (set YES to NO)", True),
    ("Consider hardening SSH configuration: PermitRootLogin (set YES to (FORCED-COMMANDS-ONLY|NO|PROHIBIT-PASSWORD|WITHOUT-PASSWORD))", True),
    ("Consider hardening SSH configuration: PermitRootLogin (YES --> NO)", True),
    ("SSH root login is allowed", True),
    ("Consider hardening SSH configuration: PermitRootLogin (set WITHOUT-PASSWORD to NO)", False),
    ("Consider hardening SSH configuration: MaxAuthTries (set 6 to 3)", False),
    ("Open port 22/tcp (ssh)", False),
])
def test_is_root_login_finding(title, expected):
    assert R.is_root_login_finding(schemas.new_finding(LAB_HOST, "lynis", title)) is expected


@pytest.mark.parametrize("title, ml_action, severity, expected", [
    ("Apache/2.4.49 appears to be outdated", "", "Medium", "Update the software"),
    ("/backup/: Directory indexing found.", "", "Medium", "directory listing"),
    ("Open port 22/tcp (ssh)", "REVIEW_SERVICE", "Info", "Confirm this service is needed"),
    ("Something unusual", "REVIEW_TLS", "Low", "Review the TLS setup"),          # falls back to the ML action
    ("Something unusual", "", "High", "Fix as soon as possible"),                # falls back to severity
])
def test_recommendation_mapping(title, ml_action, severity, expected):
    finding = schemas.new_finding("h", "nikto", title, severity=severity, ml_action=ml_action)
    assert expected in R.recommend_fix(finding)


def test_recommendation_is_text_separate_from_ml_label_and_runs_nothing(monkeypatch):
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("nothing may run"))
    finding = schemas.new_finding("h", "nuclei", "Unknown issue", ml_action="PATCH_OR_UPDATE")
    advice = R.recommend_fix(finding)
    assert advice and advice != "PATCH_OR_UPDATE" and " " in advice
    assert R.add_recommendations([finding])[0]["ml_action"] == "PATCH_OR_UPDATE"
    assert R.recommend_fix({}) and R.recommend_fix(None)  # type: ignore[arg-type]


# ====================================================================== parsers
def test_parse_permit_root_login():
    assert R.parse_permit_root_login(fixture_text("sshd_T_root_yes.txt")) == "yes"
    assert R.parse_permit_root_login(fixture_text("sshd_T_root_no.txt")) == "no"
    assert R.parse_permit_root_login("") == "" and R.parse_permit_root_login("port 22\n") == ""


def test_include_line_check():
    assert R.include_precedes_permit_root_login(fixture_text("sshd_config_with_include.txt")) is True
    assert R.include_precedes_permit_root_login(fixture_text("sshd_config_no_include.txt")) is False   # commented out
    assert R.include_precedes_permit_root_login("PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n") is False
    assert R.include_precedes_permit_root_login("") is False


# ====================================================================== the fix: happy path
def test_fix_applies_and_verifies(vm, root_finding):
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert set(outcome) == {"finding_id", "applied", "verified", "backup_path", "steps", "message", "simulated"}
    assert outcome["applied"] is True and outcome["verified"] is True and outcome["simulated"] is False
    assert outcome["finding_id"] == root_finding["id"] and outcome["backup_path"] == ""
    assert failed_steps(outcome) == [] and [s["step"] for s in outcome["steps"]] == sorted(s["step"] for s in outcome["steps"])
    assert vm.dropin == "new" and vm.reloaded == ["ssh"]
    # order: evidence -> login test -> include check -> write -> validate -> reload -> verify
    order = [vm.commands.index(c) for c in (R.CMD_EFFECTIVE_CONFIG, R.CMD_CONNECT_TEST, R.CMD_READ_SSHD_CONFIG,
                                            R.CMD_WRITE_DROPIN, R.CMD_VALIDATE, "sudo -n systemctl reload ssh")]
    assert order == sorted(order)
    assert vm.commands[-2:] == [R.CMD_EFFECTIVE_CONFIG, R.CMD_CONNECT_TEST]
    assert "PermitRootLogin no" in R.CMD_WRITE_DROPIN and R.DROPIN_PATH.endswith("00-coe444-permitrootlogin.conf")


def test_fix_backs_up_existing_dropin(vm, root_finding):
    vm.dropin = "old"
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] and outcome["verified"]
    assert outcome["backup_path"].startswith("~/coe444-backups/00-coe444-permitrootlogin.conf.") \
        and outcome["backup_path"].endswith(".bak")
    backup = next(i for i, c in enumerate(vm.commands) if c.startswith("mkdir -p"))
    assert backup < vm.commands.index(R.CMD_WRITE_DROPIN)


def test_fix_reloads_sshd_when_that_is_the_active_service(vm, root_finding):
    vm.services = "inactive\nactive\n"
    assert R.apply_fix(root_finding, confirmed=True)["verified"] is True
    assert vm.reloaded == ["sshd"]


# ====================================================================== the fix: every guard
def test_guard_no_approval(vm, root_finding):
    for confirmed in (False, None, "yes", 1):
        outcome = R.apply_fix(root_finding, confirmed=confirmed)
        assert outcome["applied"] is False and "not approved" in outcome["message"]
    assert vm.commands == []                                           # the VM was never contacted


def test_guard_config_switch_off(vm, root_finding, monkeypatch):
    monkeypatch.setattr(config, "ALLOW_AUTO_REMEDIATION", False)
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and "switched off" in outcome["message"] and vm.commands == []


def test_guard_unauthorized_target(vm, root_finding):
    outcome = R.apply_fix({**root_finding, "target": "8.8.8.8"}, confirmed=True)
    assert outcome["applied"] is False and "not authorized" in outcome["message"] and vm.commands == []


def test_guard_bad_evidence_wrong_finding(vm):
    other = schemas.new_finding(LAB_HOST, "nmap", "Open port 22/tcp (ssh)", port=22, service="ssh")
    for finding in (other, {}, None, "PermitRootLogin yes"):
        outcome = R.apply_fix(finding, confirmed=True)  # type: ignore[arg-type]
        assert outcome["applied"] is False and "not the SSH root-login finding" in outcome["message"]
    assert vm.commands == []


def test_guard_sample_finding_cannot_be_applied(vm, root_finding):
    outcome = R.apply_fix({**root_finding, "is_sample": True}, confirmed=True)
    assert outcome["applied"] is False and "sample" in outcome["message"].lower() and vm.commands == []


@pytest.mark.parametrize("value", ["no", "prohibit-password", ""])
def test_guard_bad_evidence_vm_does_not_permit_root_login(vm, root_finding, value):
    vm.root_login = value
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and "does not currently permit root login" in outcome["message"]
    assert vm.commands == [R.CMD_EFFECTIVE_CONFIG] and not vm.changed


def test_guard_session_must_be_non_root(vm, root_finding):
    vm.uid = "0"
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and "non-root SSH session" in outcome["message"] and not vm.changed


def test_guard_ssh_not_working_before_change(root_finding, monkeypatch):
    monkeypatch.setattr(config, "ALLOW_AUTO_REMEDIATION", True)
    monkeypatch.setattr(tool_utils, "run_ssh", lambda *a, **k: completed(stderr="Permission denied (publickey).", returncode=255))
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and "authentication failed" in outcome["message"]


def test_guard_missing_include_line(vm, root_finding):
    vm.sshd_config = fixture_text("sshd_config_no_include.txt")
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and "does not include sshd_config.d" in outcome["message"]
    assert not vm.changed and vm.reloaded == []


def test_guard_sshd_t_failure_removes_dropin_and_does_not_reload(vm, root_finding):
    vm.validate_ok = False
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and outcome["verified"] is False
    assert "NOT reloaded" in outcome["message"] and "drop-in removed" in outcome["message"]
    assert vm.changed and vm.dropin is None                            # written, then removed
    assert vm.reloaded == [] and not any("reload" in c for c in vm.commands)


def test_guard_sshd_t_failure_restores_previous_dropin(vm, root_finding):
    vm.dropin, vm.validate_ok = "old", False
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and "restored from backup" in outcome["message"]
    assert vm.dropin == "old" and vm.reloaded == []


@pytest.mark.parametrize("change", [{"services": "inactive\ninactive\n"}, {"reload_ok": False}])
def test_guard_reload_failure_rolls_back(vm, root_finding, change):
    vars(vm).update(change)
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is False and "could not be reloaded" in outcome["message"]
    assert vm.dropin is None and vm.reloaded == []


def test_verification_failure_value_unchanged(vm, root_finding):
    vm.fix_takes_effect = False                                        # e.g. another file overrides ours
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is True and outcome["verified"] is False
    assert "verification FAILED" in outcome["message"]
    assert "Verify effective value (sudo sshd -T)" in failed_steps(outcome)


def test_verification_failure_fresh_login_broken(vm, root_finding):
    vm.login_after_ok = False
    outcome = R.apply_fix(root_finding, confirmed=True)
    assert outcome["applied"] is True and outcome["verified"] is False
    assert "Check the VM manually" in outcome["message"]


def test_no_finding_text_ever_reaches_a_command(vm, root_finding):
    evil = {**root_finding, "title": root_finding["title"] + " $(touch /tmp/pwned); rm -rf /",
            "evidence": "`reboot`", "ml_action": "HARDEN_SSH", "recommendation": "sudo rm -rf /"}
    R.apply_fix(evil, confirmed=True)
    assert not any(word in c for c in vm.commands for word in ("pwned", "reboot", "rm -rf", "HARDEN_SSH"))


# ====================================================================== simulation
def test_simulation_touches_nothing(monkeypatch, root_finding):
    monkeypatch.setattr(tool_utils, "run_ssh", lambda *a, **k: pytest.fail("simulation must not connect"))
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("simulation must not run tools"))
    for finding in (root_finding, {**root_finding, "is_sample": True}):
        outcome = R.apply_fix(finding, confirmed=False, simulate=True)
        assert outcome["simulated"] is True and outcome["applied"] is False and outcome["verified"] is False
        assert "SIMULATION" in outcome["message"] and [s["step"] for s in outcome["steps"]] == [1, 2, 3, 4, 5, 6, 7]
        assert all(s["detail"].startswith("SIMULATED") for s in outcome["steps"])


def test_simulation_still_checks_finding_and_authorization(root_finding):
    assert "not authorized" in R.apply_fix({**root_finding, "target": "8.8.8.8"}, simulate=True)["message"]
    other = schemas.new_finding(LAB_HOST, "nmap", "Open port 80/tcp (http)")
    assert "not the SSH root-login finding" in R.apply_fix(other, simulate=True)["message"]
