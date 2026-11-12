"""Dashboard: importing runs nothing; the page works in sample mode (Streamlit's test runner)."""

from __future__ import annotations

import importlib

import pytest

import config
from modules import orchestrator, tool_utils

MODULES = ["config", "schemas", "app", "demo_tests", "modules.tool_utils", "modules.target_scanner",
           "modules.vulnerability_scanner", "modules.host_auditor", "modules.ml_classifier",
           "modules.remediation", "modules.reporting", "modules.orchestrator"]


@pytest.mark.parametrize("name", MODULES)
def test_import_runs_nothing(monkeypatch, name):
    # subprocess is blocked for every test (conftest); these make any scan attempt fail too.
    monkeypatch.setattr(tool_utils, "run_tool", lambda *a, **k: pytest.fail("import must not run tools"))
    monkeypatch.setattr(tool_utils, "run_ssh", lambda *a, **k: pytest.fail("import must not use ssh"))
    monkeypatch.setattr(orchestrator, "run_assessment", lambda *a, **k: pytest.fail("import must not scan"))
    importlib.reload(importlib.import_module(name))


@pytest.fixture
def page():
    from streamlit.testing.v1 import AppTest
    return AppTest.from_file(str(config.BASE_DIR / "app.py"), default_timeout=30)


def test_page_load_runs_no_assessment(page, monkeypatch):
    monkeypatch.setattr(orchestrator, "run_assessment", lambda *a, **k: pytest.fail("page load must not scan"))
    page.run()
    assert not page.exception
    assert "result" not in page.session_state
    assert any("Authorized use only" in w.value for w in page.warning)
    assert any("SAMPLE MODE is active" in i.value for i in page.info)


def test_sample_assessment_in_the_dashboard(page, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "REPORTS_DIR", tmp_path)
    page.run()
    next(b for b in page.button if b.label == "Run assessment").click().run()
    assert not page.exception
    result = page.session_state["result"]
    assert result["is_sample"] and len(result["findings"]) == 18
    assert next(m for m in page.metric if m.label == "Total findings").value == "18"
    assert any("Tool status" in s.value for s in page.subheader)

    # simulate the one supported fix
    next(b for b in page.button if b.label == "Simulate fix").click().run()
    assert not page.exception
    assert page.session_state["result"]["remediation"]["simulated"] is True
    assert any("SIMULATION ONLY" in i.value for i in page.info)

    # export
    next(b for b in page.button if b.label == "Generate CSV and HTML reports").click().run()
    assert not page.exception
    reports = page.session_state["reports"]
    assert [r["ok"] for r in reports] == [True, True] and len(list(tmp_path.iterdir())) == 2
    assert sum("report saved" in s.value for s in page.success) == 2


def test_unauthorized_target_disables_the_run_button(page):
    page.run()
    page.text_input[0].set_value("8.8.8.8").run()
    assert next(b for b in page.button if b.label == "Run assessment").disabled
    assert any("NOT in AUTHORIZED_TARGETS" in m.value for m in page.markdown)


def test_dashboard_survives_tool_and_model_failures(page, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "PRIORITY_MODEL_PATH", tmp_path / "missing.joblib")
    monkeypatch.setattr(tool_utils, "tool_available", lambda name: False)      # no tool installed
    page.run()
    page.toggle[0].set_value(False).run()                                       # real mode
    next(b for b in page.button if b.label == "Run assessment").click().run()
    assert not page.exception
    result = page.session_state["result"]
    assert result["scans"]["nmap"]["status"] == "FAILED" and result["findings"] == []
    assert any("not installed" in e.value for e in page.error)
