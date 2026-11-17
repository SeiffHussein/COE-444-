"""
demo_tests.py - presentation demo of the key safety and correctness scenarios.

Run with:   python demo_tests.py

Prints one row per scenario:  Test / Scenario / Expected / Actual / PASS|FAIL
PASS is computed by comparing the actual value with the expected value.

Nothing here touches a real system: external tools and SSH are replaced by
the labelled fixtures in tests/fixtures/, and the ML models are trained into
a temporary folder.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import config
from modules import (host_auditor, ml_classifier, nvd, orchestrator, remediation, reporting,
                     target_scanner, tool_utils, vulnerability_scanner)
from schemas import ML_PRIORITIES, new_finding

LAB_HOST = config.FIXTURE_HOST


def fixture(name: str) -> str:
    return (config.FIXTURES_DIR / name).read_text(encoding="utf-8")


def done(stdout: str = "", stderr: str = "", returncode: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


def fake_tools(broken: tuple = (), nmap_fixture: str = "nmap_scan.xml"):
    """Stand-in for tool_utils.run_tool that answers with fixtures."""
    def run_tool(args, timeout=None):
        tool = args[0]
        if tool in broken:
            raise RuntimeError(f"'{tool}' is not installed or not on PATH.")
        if tool == "nmap":
            return done(fixture(nmap_fixture))
        if tool == "nuclei":
            return done(fixture("nuclei_results.jsonl"))
        if tool == "nikto":
            Path(args[args.index("-output") + 1]).write_text(fixture("nikto_results.json"), encoding="utf-8")
            return done()
        raise RuntimeError(f"unexpected tool {tool}")
    return run_tool


class FakeVM:
    """Stand-in for the lab VM (answers the constant SSH commands)."""

    def __init__(self, include_line=True, sshd_t_ok=True):
        self.include_line, self.sshd_t_ok = include_line, sshd_t_ok
        self.dropin_written, self.reloaded, self.commands = False, False, []

    def __call__(self, host, command, timeout=None):
        R = remediation
        self.commands.append(command)
        if command == host_auditor.LYNIS_AUDIT_COMMAND:
            return done("audit finished")
        if command == host_auditor.LYNIS_REPORT_COMMAND:
            return done(fixture("lynis_report.dat"))
        if command == R.CMD_EFFECTIVE_CONFIG:
            return done(fixture("sshd_T_root_no.txt" if self.dropin_written else "sshd_T_root_yes.txt"))
        if command == R.CMD_CONNECT_TEST:
            return done("coe444-ok\n1000\n")
        if command == R.CMD_READ_SSHD_CONFIG:
            return done(fixture("sshd_config_with_include.txt" if self.include_line else "sshd_config_no_include.txt"))
        if command == R.CMD_DROPIN_EXISTS:
            return done("absent\n")
        if command == R.CMD_WRITE_DROPIN:
            self.dropin_written = True
            return done()
        if command == R.CMD_REMOVE_DROPIN:
            self.dropin_written = False
            return done()
        if command == R.CMD_VALIDATE:
            return done() if self.sshd_t_ok else done(stderr="sshd_config: bad configuration option", returncode=1)
        if command == R.CMD_ACTIVE_SERVICES:
            return done("active\ninactive\n")
        if command == "sudo -n systemctl reload ssh":
            self.reloaded = True
            return done()
        raise RuntimeError(f"unexpected remote command: {command}")


def root_login_finding() -> dict:
    findings = host_auditor._parse_lynis_report(fixture("lynis_report.dat"), LAB_HOST)
    return next(f for f in remediation.add_recommendations(findings) if f["remediation_supported"])


def real_assessment(**fake_tool_options) -> dict:
    with mock.patch.object(tool_utils, "run_tool", fake_tools(**fake_tool_options)), \
         mock.patch.object(tool_utils, "run_ssh", FakeVM()):
        return orchestrator.run_assessment(LAB_HOST, sample_mode=False)


# ---------------------------------------------------------------- scenarios
# Each scenario returns the ACTUAL value; it is compared with the EXPECTED value below.
def t01():
    result = orchestrator.run_assessment("8.8.8.8", sample_mode=False)
    return f"authorized={result['authorized']}, findings={len(result['findings'])}, " \
           f"tools started={sum(s['status'] != 'SKIPPED' for s in result['scans'].values())}"


def t02():
    return f"format ok={tool_utils.validate_target('-oN /tmp/x; rm -rf /')}"


def t03():
    result = orchestrator.run_assessment("127.0.0.1", sample_mode=True)
    return ", ".join(f"{tool}={scan['status']}" for tool, scan in result["scans"].items()) \
        + f", all labelled sample={all(f['is_sample'] for f in result['findings'])}"


def t04():
    with mock.patch.object(tool_utils, "run_tool", fake_tools()):
        result = target_scanner.scan_target(LAB_HOST)
    return f"{result['status']}, ports={[f['port'] for f in result['findings']]}, " \
           f"severities={sorted({f['severity'] for f in result['findings']})}"


def t05():
    with mock.patch.object(tool_utils, "tool_available", lambda name: False):
        result = target_scanner.scan_target(LAB_HOST)
    return f"{result['status']}, has error text={bool(result['error'])}"


def t06():
    result = real_assessment(nmap_fixture="nmap_no_open_ports.xml")
    return f"nikto={result['scans']['nikto']['status']}"


def t07():
    result = real_assessment(broken=("nuclei",))
    return f"nuclei={result['scans']['nuclei']['status']}, other tools with findings=" \
           f"{sorted({f['source'] for f in result['findings']})}"


def t08():
    with mock.patch.object(tool_utils, "run_ssh",
                           lambda *a, **k: done(stderr="Permission denied (publickey).", returncode=255)):
        result = host_auditor.audit_host(LAB_HOST)
    return f"{result['status']}: {result['error'][:25]}"


def t09():
    finding = next(f for f in real_assessment()["findings"] if f["cve"])
    return f"{finding['original_severity']} -> {finding['severity']}, ml_priority is a valid label=" \
           f"{finding['ml_priority'] in ML_PRIORITIES}, ml_action={finding['ml_action']}"


def t10():
    with mock.patch.object(config, "PRIORITY_MODEL_PATH", Path("does-not-exist.joblib")):
        result = orchestrator.run_assessment("127.0.0.1", sample_mode=True)
    return f"ml={result['ml']['status']}, findings kept={len(result['findings'])}, " \
           f"predictions={sum(bool(f['ml_priority']) for f in result['findings'])}"


def t11():
    result = orchestrator.run_assessment("127.0.0.1", sample_mode=True)
    result["findings"][0]["title"] = "<script>alert(1)</script>"
    with tempfile.TemporaryDirectory() as folder:
        page = Path(reporting.generate_html_report(result, f"{folder}/r.html")).read_text(encoding="utf-8")
    return f"raw script tag in report={'<script>' in page}, escaped={'&lt;script&gt;' in page}"


def _fix(vm: FakeVM, confirmed: bool, **changes) -> str:
    finding = {**root_login_finding(), **changes}
    with mock.patch.object(tool_utils, "run_ssh", vm), mock.patch.object(config, "ALLOW_AUTO_REMEDIATION", True):
        outcome = remediation.apply_fix(finding, confirmed=confirmed)
    return f"applied={outcome['applied']}, verified={outcome['verified']}, " \
           f"file written={vm.dropin_written}, reloaded={vm.reloaded}"


def t12():
    return _fix(FakeVM(), confirmed=False)


def t13():
    return _fix(FakeVM(), confirmed=True, target="8.8.8.8")


def t14():
    return _fix(FakeVM(include_line=False), confirmed=True)


def t15():
    return _fix(FakeVM(sshd_t_ok=False), confirmed=True)


def t16():
    return _fix(FakeVM(), confirmed=True)


def t17():
    vm = FakeVM()
    with mock.patch.object(tool_utils, "run_ssh", vm):
        outcome = remediation.apply_fix(root_login_finding(), simulate=True)
    return f"simulated={outcome['simulated']}, applied={outcome['applied']}, commands sent to VM={len(vm.commands)}"


def t18():
    known = new_finding(LAB_HOST, "nuclei", "SonicOS buffer overflow", cve="CVE-2022-22274", severity="Critical")
    unknown = new_finding(LAB_HOST, "nuclei", "Apache path traversal", cve="CVE-2021-41773", severity="Critical")
    (known, unknown), status = nvd.enrich_findings([known, unknown])
    return f"known CVE -> {known['cvss_score']} {known['nvd_severity']}, CVE not in index -> " \
           f"{unknown['cvss_score']} '{unknown['nvd_severity']}', found {status['matched']} of {status['cve_findings']}"


def t20():
    result = orchestrator.run_assessment("127.0.0.1", sample_mode=True)
    action = {f["title"]: f["ml_action"] for f in result["findings"]}
    picks = [("Open port 22/tcp (ssh)", "port 22"), ("Self Signed SSL Certificate", "self-signed cert"),
             ("Consider hardening SSH configuration: PermitRootLogin (set YES to NO)", "root login")]
    trained_on = "real" if "real Nuclei and Lynis" in ml_classifier.model_metrics()["action"]["training_data"] else "other"
    return f"trained on {trained_on} checks, " + ", ".join(f"{label} -> {action[title]}" for title, label in picks)


def t19():
    metrics = ml_classifier.model_metrics()["priority"]
    result = orchestrator.run_assessment("127.0.0.1", sample_mode=True)
    info = [f for f in result["findings"] if f["severity"] == "Info"]
    rest = [f for f in result["findings"] if f["severity"] != "Info"]
    return f"trained on real NVD data={'real NVD' in metrics['training_data']}, " \
           f"Info findings rated={sum(bool(f['ml_priority']) for f in info)} of {len(info)}, " \
           f"other findings rated={sum(bool(f['ml_priority']) for f in rest)} of {len(rest)}"


SCENARIOS = [
    ("T01", "Unauthorized target 8.8.8.8 is rejected before scanning", "authorized=False, findings=0, tools started=0", t01),
    ("T02", "Target text with tool options / shell characters", "format ok=False", t02),
    ("T03", "Sample mode: all four tools return labelled fixtures",
     "nmap=SUCCESS, nuclei=SUCCESS, nikto=SUCCESS, lynis=SUCCESS, all labelled sample=True", t03),
    ("T04", "Nmap XML parsed; open ports are Info, not vulnerabilities", "SUCCESS, ports=[22, 80, 443], severities=['Info']", t04),
    ("T05", "Nmap not installed -> FAILED (never an empty success)", "FAILED, has error text=True", t05),
    ("T06", "No web port discovered -> Nikto is not applicable", "nikto=NOT_APPLICABLE", t06),
    ("T07", "Nuclei fails; the other tools' findings survive",
     "nuclei=FAILED, other tools with findings=['lynis', 'nikto', 'nmap']", t07),
    ("T08", "Lynis over SSH: key rejected by the VM", "FAILED: Could not run Lynis. SSH ", t08),
    ("T09", "Nuclei CVE finding: severity normalized + ML labels",
     "critical -> Critical, ml_priority is a valid label=True, ml_action=PATCH_OR_UPDATE", t09),
    ("T10", "ML model file missing -> findings unchanged, no fake prediction", "ml=FAILED, findings kept=18, predictions=0", t10),
    ("T11", "HTML report escapes scanner-controlled text", "raw script tag in report=False, escaped=True", t11),
    ("T12", "Fix without approval -> nothing happens", "applied=False, verified=False, file written=False, reloaded=False", t12),
    ("T13", "Fix for an unauthorized target -> refused", "applied=False, verified=False, file written=False, reloaded=False", t13),
    ("T14", "sshd_config has no Include line -> stop before writing", "applied=False, verified=False, file written=False, reloaded=False", t14),
    ("T15", "sshd -t fails -> drop-in removed, no reload", "applied=False, verified=False, file written=False, reloaded=False", t15),
    ("T16", "Approved fix on simulated VM -> applied and verified", "applied=True, verified=True, file written=True, reloaded=True", t16),
    ("T17", "Simulation mode sends nothing to the VM", "simulated=True, applied=False, commands sent to VM=0", t17),
    ("T18", "NVD lookup: official CVSS for a known CVE, nothing invented for an unknown one",
     "known CVE -> 9.8 CRITICAL, CVE not in index -> None '', found 1 of 2", t18),
    ("T19", "Priority model: trained on real NVD data; informational findings are not rated",
     "trained on real NVD data=True, Info findings rated=0 of 6, other findings rated=12 of 12", t19),
    ("T20", "Action model: trained on real Nuclei/Lynis checks, sensible actions for key findings",
     "trained on real checks, port 22 -> REVIEW_SERVICE, self-signed cert -> REVIEW_TLS, root login -> HARDEN_SSH", t20),
]


def main() -> int:
    """Run every scenario and print the table. Returns the number of failures."""
    with tempfile.TemporaryDirectory() as model_folder, \
         mock.patch.object(config, "AUTHORIZED_TARGETS", ["127.0.0.1", LAB_HOST]), \
         mock.patch.object(config, "SSH_USER", "demo-user"), \
         mock.patch.object(config, "PRIORITY_MODEL_PATH", Path(model_folder) / "priority.joblib"), \
         mock.patch.object(config, "ACTION_MODEL_PATH", Path(model_folder) / "action.joblib"), \
         mock.patch.object(config, "NVD_INDEX_PATH", Path(model_folder) / "nvd_cves.csv.gz"), \
         mock.patch("subprocess.run", side_effect=AssertionError("demo must not run real programs")):
        nvd.build_index([config.FIXTURES_DIR / "nvd_feed_sample.json"])    # real 82-CVE excerpt of the NVD feed
        ml_classifier.train_models()
        rows = []
        for test_id, scenario, expected, run in SCENARIOS:
            try:
                actual = run()
            except Exception as exc:                       # a crash is a FAIL, shown honestly
                actual = f"ERROR: {exc}"
            rows.append((test_id, scenario, expected, actual, "PASS" if actual == expected else "FAIL"))

    print(f"{config.APP_NAME} - demo tests (fixtures and a simulated VM; no real system is touched)\n")
    for test_id, scenario, expected, actual, verdict in rows:
        print(f"Test:     {test_id}\nScenario: {scenario}\nExpected: {expected}\nActual:   {actual}\nResult:   {verdict}\n")
    passed = sum(row[4] == "PASS" for row in rows)
    print(f"TOTAL: {len(rows)} scenarios - {passed} PASS - {len(rows) - passed} FAIL")
    return len(rows) - passed


if __name__ == "__main__":
    raise SystemExit(1 if main() else 0)
