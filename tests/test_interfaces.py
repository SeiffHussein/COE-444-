"""
tests/test_interfaces.py - interface tests every member must keep passing.

Run from the repository root:   python -m pytest -q

These tests never scan real systems and never apply fixes: they use sample
mode, mocks and temporary folders only. Members may ADD tests for their module
(at the bottom, in their own section); do not delete or weaken existing ones.
"""

from __future__ import annotations

import csv
import importlib
import subprocess
from unittest import mock

import pytest

import schemas
from modules import (host_auditor, ml_classifier, remediation, reporting, target_scanner,
                     tool_utils, vulnerability_scanner)


# ------------------------------------------------------------------ safety: no subprocess in tests
@pytest.fixture(autouse=True)
def block_subprocess(monkeypatch):
    """Fail loudly if any test would launch an external program."""
    def _blocked(*args, **kwargs):
        raise AssertionError(f"Tests must not run external programs: {args!r}")
    monkeypatch.setattr(subprocess, "run", _blocked)
    monkeypatch.setattr(subprocess, "Popen", _blocked)


def _assert_finding(f: dict) -> None:
    assert set(f) == set(schemas.FINDING_FIELDS)
    assert f["severity"] in schemas.SEVERITIES
    assert f["ml_priority"] in ("",) + schemas.ML_PRIORITIES
    assert f["id"] and f["target"] and f["source"] and f["title"]
    assert all(isinstance(v, str) for v in f.values())


# ------------------------------------------------------------------ imports
@pytest.mark.parametrize("name", [
    "config", "schemas", "app", "modules.target_scanner", "modules.vulnerability_scanner",
    "modules.host_auditor", "modules.ml_classifier", "modules.remediation", "modules.reporting",
    "modules.tool_utils",
])
def test_modules_import_without_side_effects(name):
    # The autouse fixture makes any scan/subprocess during import fail this test.
    importlib.reload(importlib.import_module(name))


# ------------------------------------------------------------------ schemas
def test_finding_has_agreed_fields_and_defaults():
    f = schemas.Finding(target="10.0.0.1", source="nmap", title="Open port 22/tcp").to_dict()
    assert tuple(f) == tuple(schemas.FINDING_FIELDS) or set(f) == set(schemas.FINDING_FIELDS)
    assert f["severity"] == "Info"
    assert f["description"] == f["evidence"] == f["ml_priority"] == f["recommendation"] == ""
    assert len(f["id"]) == 8
    _assert_finding(f)


def test_finding_rejects_bad_severity_and_normalizes_case():
    assert schemas.new_finding("h", "nmap", "t", severity="high")["severity"] == "High"
    with pytest.raises(ValueError):
        schemas.Finding(target="h", source="nmap", title="t", severity="urgent")
    with pytest.raises(ValueError):
        schemas.Finding(target="", source="nmap", title="t")
    assert schemas.normalize_severity("informational") == "Info"
    assert schemas.normalize_severity("WARNING") == "Medium"
    assert schemas.normalize_severity(None) == "Info"


def test_validate_finding_fills_defaults_and_rejects_unknown_keys():
    clean = schemas.validate_finding({"target": "h", "source": "x", "title": "t"})
    _assert_finding(clean)
    with pytest.raises(TypeError):
        schemas.validate_finding({"target": "h", "source": "x", "title": "t", "cvss": "9.8"})


# ------------------------------------------------------------------ target validation
@pytest.mark.parametrize("target", ["127.0.0.1", "192.168.1.10", "192.168.1.0/24", "::1",
                                    "localhost", "scanme.nmap.org"])
def test_validate_target_accepts(target):
    assert target_scanner.validate_target(target) is True


@pytest.mark.parametrize("target", ["", "   ", "-oN /tmp/x", "10.0.0.0/8", "999.1.1.1",
                                    "host; rm -rf /", "http://example.com", "a b", "host:80",
                                    "$(whoami)", "x" * 300, None, 123])
def test_validate_target_rejects(target):
    assert target_scanner.validate_target(target) is False


def test_scanners_reject_invalid_target():
    with pytest.raises(ValueError):
        target_scanner.scan_target("bad target!", sample_mode=True)
    with pytest.raises(ValueError):
        vulnerability_scanner.scan_vulnerabilities("-p 1-65535", sample_mode=True)


# ------------------------------------------------------------------ sample modes
def test_sample_modes_return_labelled_findings():
    results = (target_scanner.scan_target("127.0.0.1", sample_mode=True)
               + vulnerability_scanner.scan_vulnerabilities("127.0.0.1", sample_mode=True)
               + host_auditor.audit_host(sample_mode=True))
    assert results
    for f in results:
        _assert_finding(f)
        assert schemas.is_sample(f), "sample data must be labelled with schemas.sample_source()"


def test_real_mode_reports_missing_tool_cleanly(monkeypatch):
    monkeypatch.setattr(tool_utils.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError):
        tool_utils.run_tool(["nmap", "127.0.0.1"])
    # Until implemented, real mode raises NotImplementedError (a RuntimeError);
    # once implemented, a missing tool must still raise RuntimeError.
    with pytest.raises(RuntimeError):
        target_scanner.scan_target("127.0.0.1", sample_mode=False)


def test_run_tool_requires_argument_list():
    with pytest.raises(ValueError):
        tool_utils.run_tool("nmap 127.0.0.1")  # type: ignore[arg-type]


# ------------------------------------------------------------------ normalisation
def test_normalize_findings_returns_shared_structure():
    raw = [
        {"name": "Test issue", "severity": "HIGH", "description": "d", "matched-at": "http://h/"},
        {"msg": "Nikto style", "url": "http://h/x"},
        {"no_title_here": True},      # skipped
        "not a dict",                 # skipped
    ]
    out = vulnerability_scanner.normalize_findings(raw, "h", "nuclei")
    assert len(out) == 2
    for f in out:
        _assert_finding(f)
        assert f["source"] == "nuclei" and f["target"] == "h"
    assert out[0]["severity"] == "High"
    assert vulnerability_scanner.normalize_findings([], "h", "nuclei") == []
    assert vulnerability_scanner.normalize_findings(None, "h", "nuclei") == []  # type: ignore[arg-type]


# ------------------------------------------------------------------ ML
def test_classifier_handles_empty_list():
    assert ml_classifier.classify_findings([]) == []


def test_dataset_and_features_match():
    X, y = ml_classifier.load_dataset()
    assert list(X.columns) == ml_classifier.FEATURE_COLUMNS
    assert set(y.unique()) <= set(schemas.ML_PRIORITIES)
    assert len(X) >= 100
    feats = ml_classifier.extract_features(
        schemas.new_finding("h", "nuclei (sample)", "Apache RCE CVE-2021-41773", severity="Critical"))
    assert list(feats) == ml_classifier.FEATURE_COLUMNS
    assert feats == {"severity_score": 4, "is_network": 1, "is_web": 1, "has_cve": 1, "exploit_keyword": 1}


def test_classifier_preserves_original_fields_when_implemented():
    findings = vulnerability_scanner.scan_vulnerabilities("127.0.0.1", sample_mode=True)
    try:
        out = ml_classifier.classify_findings(findings)
    except NotImplementedError:
        pytest.skip("classify_findings not implemented yet (Member 4)")
    assert len(out) == len(findings)
    for before, after in zip(findings, out):
        assert after["ml_priority"] in schemas.ML_PRIORITIES
        for key in ("id", "title", "severity", "description", "evidence"):
            assert after[key] == before[key]


# ------------------------------------------------------------------ remediation
def test_recommend_fix_returns_text_without_applying():
    f = schemas.new_finding("h", "nmap", "Open port 23/tcp (telnet)", severity="Medium")
    with mock.patch.object(tool_utils, "run_tool") as run:
        advice = remediation.recommend_fix(f)
        result = remediation.apply_fix(f, confirmed=True)
    assert isinstance(advice, str) and advice
    assert result["applied"] is False and result["finding_id"] == f["id"]
    run.assert_not_called()
    assert remediation.recommend_fix({}) != ""


# ------------------------------------------------------------------ reporting
def test_reports_write_small_report(tmp_path):
    findings = [schemas.new_finding("h", "nikto", "<script>alert(1)</script>", severity="Low",
                                    description="a & b")]
    csv_path = reporting.generate_csv_report(findings, str(tmp_path / "sub" / "r.csv"))
    html_path = reporting.generate_html_report(findings, str(tmp_path / "sub" / "r.html"))
    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["title"] == "<script>alert(1)</script>"
    page = open(html_path, encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_reports_handle_empty_findings(tmp_path):
    csv_path = reporting.generate_csv_report([], str(tmp_path / "e.csv"))
    html_path = reporting.generate_html_report([], str(tmp_path / "e.html"))
    assert open(csv_path, encoding="utf-8").read().startswith("id,target,source")
    assert "No findings" in open(html_path, encoding="utf-8").read()


# ------------------------------------------------------------------ end-to-end (sample mode)
def test_sample_pipeline_end_to_end(tmp_path):
    import app
    findings, messages = app.run_assessment("127.0.0.1", list(app.SCAN_OPTIONS), sample_mode=True)
    assert findings
    for f in findings:
        _assert_finding(f)
        assert f["recommendation"]
    assert reporting.generate_html_report(findings, str(tmp_path / "e2e.html"))
    # Severity order: first finding is the most serious.
    scores = [schemas.SEVERITY_SCORES[f["severity"]] for f in findings]
    assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------- Member 2 tests
import json as _json
from types import SimpleNamespace as _NS


def test_parse_nuclei_jsonl_flattens_info():
    from modules import vulnerability_scanner as vs
    line = _json.dumps({
        "template-id": "git-config",
        "info": {"name": "Git Config Exposure", "severity": "medium", "description": "Exposed .git/config"},
        "matched-at": "http://lab.local/.git/config",
    })
    rows = vs._parse_nuclei_jsonl(line + "\nnot json\n\n")
    findings = vs.normalize_findings(rows, "lab.local", "nuclei")
    assert len(findings) == 1
    assert findings[0]["title"] == "Git Config Exposure"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["source"] == "nuclei"
    assert "git/config" in findings[0]["evidence"]


def test_parse_nikto_json_dict_and_list():
    from modules import vulnerability_scanner as vs
    host = {"host": "lab.local", "vulnerabilities": [
        {"id": "1", "method": "GET", "url": "/admin/", "msg": "Admin login page found"},
        {"id": "2", "method": "GET", "url": "/", "msg": "Server banner has changed"},
    ]}
    for payload in (host, [host]):
        rows = vs._parse_nikto_json(_json.dumps(payload))
        findings = vs.normalize_findings(rows, "lab.local", "nikto")
        assert [f["severity"] for f in findings] == ["Medium", "Low"]


def test_scan_one_tool_missing_adds_info_finding(monkeypatch):
    from modules import vulnerability_scanner as vs
    monkeypatch.setattr(vs, "tool_available", lambda name: name == "nuclei")
    line = _json.dumps({"template-id": "x", "info": {"name": "Test Finding", "severity": "high"}})
    monkeypatch.setattr(vs, "run_tool", lambda args: _NS(returncode=0, stdout=line, stderr=""))
    findings = vs.scan_vulnerabilities("127.0.0.1")
    titles = [f["title"] for f in findings]
    assert "Test Finding" in titles
    assert "Nikto check skipped" in titles


def test_scan_both_tools_missing_raises(monkeypatch):
    import pytest
    from modules import vulnerability_scanner as vs
    monkeypatch.setattr(vs, "tool_available", lambda name: False)
    with pytest.raises(RuntimeError):
        vs.scan_vulnerabilities("127.0.0.1")