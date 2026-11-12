"""
tests/conftest.py - shared safety net and helpers for every test.

* No test may start a real program: subprocess is blocked for all tests.
* The lab configuration is replaced by harmless test values.
* ML models are trained once into a temporary folder (never into models/).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import config
from modules import ml_classifier

FIXTURES = Path(__file__).parent / "fixtures"
LAB_HOST = "192.0.2.10"          # documentation-only address used in the fixtures


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def completed(stdout: str = "", stderr: str = "", returncode: int = 0) -> SimpleNamespace:
    """Stand-in for subprocess.CompletedProcess."""
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


@pytest.fixture(autouse=True)
def block_subprocess(monkeypatch):
    """Fail loudly if any test would launch an external program."""
    def _blocked(*args, **kwargs):
        raise AssertionError(f"Tests must not run external programs: {args!r}")
    monkeypatch.setattr(subprocess, "run", _blocked)
    monkeypatch.setattr(subprocess, "Popen", _blocked)


@pytest.fixture(scope="session")
def trained_model_dir(tmp_path_factory):
    """Train both models once, into a temporary folder."""
    folder = tmp_path_factory.mktemp("models")
    original = (config.PRIORITY_MODEL_PATH, config.ACTION_MODEL_PATH)
    config.PRIORITY_MODEL_PATH, config.ACTION_MODEL_PATH = folder / "priority.joblib", folder / "action.joblib"
    try:
        metrics = ml_classifier.train_models()
    finally:
        config.PRIORITY_MODEL_PATH, config.ACTION_MODEL_PATH = original
    return SimpleNamespace(folder=folder, metrics=metrics)


@pytest.fixture(autouse=True)
def lab_config(monkeypatch, trained_model_dir):
    """Known test configuration: two authorized targets, SSH set up, remediation off."""
    monkeypatch.setattr(config, "AUTHORIZED_TARGETS", ["127.0.0.1", LAB_HOST])
    monkeypatch.setattr(config, "SSH_USER", "labadmin")
    monkeypatch.setattr(config, "SSH_KEY_PATH", "/nonexistent/test_key")
    monkeypatch.setattr(config, "ALLOW_AUTO_REMEDIATION", False)
    monkeypatch.setattr(config, "PRIORITY_MODEL_PATH", trained_model_dir.folder / "priority.joblib")
    monkeypatch.setattr(config, "ACTION_MODEL_PATH", trained_model_dir.folder / "action.joblib")
