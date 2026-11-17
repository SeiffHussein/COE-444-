"""Action dataset: label rules, reading the Nuclei and Lynis libraries, the committed dataset file."""

from __future__ import annotations

import collections
import gzip

import pytest

import config
import schemas
from modules import action_data
from tests.conftest import FIXTURES

LIBRARIES = FIXTURES / "check_libraries"


# ====================================================================== label rules
@pytest.mark.parametrize("folder, tags, severity, has_cve, expected", [
    ("http/cves", {"cve", "apache"}, "critical", True, "PATCH_OR_UPDATE"),
    ("network/cves", {"ssh"}, "high", True, "PATCH_OR_UPDATE"),                 # a CVE wins over everything
    ("ssl/c2", {"c2", "malware", "ssl", "tls"}, "info", False, "INVESTIGATE_FINDING"),
    ("network/honeypot", {"ssh", "honeypot"}, "info", False, "INVESTIGATE_FINDING"),
    ("ssl", {"ssl", "tls", "self-signed"}, "low", False, "REVIEW_TLS"),
    ("javascript/misconfiguration", {"ssh", "misconfig"}, "low", False, "HARDEN_SSH"),
    ("http/exposures", {"ssh", "exposure"}, "medium", False, "HARDEN_SSH"),
    ("network/detection", {"ssh", "detect"}, "info", False, "REVIEW_SERVICE"),  # SSH detected, nothing wrong
    ("http/exposed-panels", {"panel"}, "info", False, "REVIEW_SERVICE"),
    ("http/technologies", {"tech", "detect"}, "info", False, "NO_ACTION_INFORMATIONAL"),
    ("http/misconfiguration", {"misconfig"}, "info", False, "HARDEN_WEB_SERVER"),
    ("http/vulnerabilities", {"vuln"}, "info", False, "INVESTIGATE_FINDING"),   # severity alone never decides
    ("http/default-logins", {"default-login"}, "high", False, "INVESTIGATE_FINDING"),
])
def test_nuclei_action_rule(folder, tags, severity, has_cve, expected):
    assert action_data.nuclei_action(folder, tags, severity, has_cve) == expected


def test_lynis_action_rule():
    assert action_data.lynis_action("ssh") == "HARDEN_SSH"
    assert action_data.lynis_action("webservers") == "HARDEN_WEB_SERVER"
    assert action_data.lynis_action("ports_packages") == "PATCH_OR_UPDATE"
    assert action_data.lynis_action("firewalls") == "INVESTIGATE_FINDING"
    assert set(action_data.LYNIS_GROUP_ACTIONS.values()) <= set(schemas.ML_ACTIONS)


# ====================================================================== reading the libraries
def test_read_nuclei_fixture_templates():
    rows = {r["check_id"]: r for r in action_data.read_nuclei(LIBRARIES / "nuclei-templates")}
    assert set(rows) == {"CVE-2021-41773", "apache-detect", "self-signed-ssl", "demo-c2"}   # cloud + broken skipped
    cve = rows["CVE-2021-41773"]
    assert cve["action"] == "PATCH_OR_UPDATE" and cve["category"] == "http/cves" and cve["source"] == "nuclei"
    assert cve["title"] == "Apache 2.4.49 - Path Traversal"
    assert cve["description"].startswith("A path traversal flaw") and "\n" not in cve["description"]
    assert rows["apache-detect"]["action"] == "NO_ACTION_INFORMATIONAL"
    assert rows["self-signed-ssl"]["action"] == "REVIEW_TLS" and rows["self-signed-ssl"]["category"] == "ssl"
    assert rows["demo-c2"]["action"] == "INVESTIGATE_FINDING" and rows["demo-c2"]["category"] == "ssl/c2"
    assert all(tuple(r) == action_data.DATASET_COLUMNS for r in rows.values())


def test_read_lynis_fixture_messages():
    rows = action_data.read_lynis(LIBRARIES / "lynis")
    found = {(r["check_id"], r["title"], r["category"], r["tags"], r["action"]) for r in rows}
    assert found == {
        ("SSH-7408", "Consider hardening SSH configuration", "ssh", "suggestion", "HARDEN_SSH"),
        ("FIRE-4512", "iptables module(s) loaded, but no rules active", "firewalls", "warning", "INVESTIGATE_FINDING"),
        ("FIRE-4590", "Consider avoid target if possible", "firewalls", "suggestion", "INVESTIGATE_FINDING"),
    }   # duplicates, too-short messages and the .template file are left out; ${...} placeholders removed
    assert len(rows) == 3


def test_build_dataset_is_reproducible(tmp_path):
    first, second = tmp_path / "a.csv.gz", tmp_path / "b.csv.gz"
    counts = action_data.build_dataset(LIBRARIES / "nuclei-templates", LIBRARIES / "lynis", first)
    action_data.build_dataset(LIBRARIES / "nuclei-templates", LIBRARIES / "lynis", second)
    assert first.read_bytes() == second.read_bytes() and sum(counts.values()) == 7
    assert set(counts) == set(schemas.ML_ACTIONS)


def test_build_dataset_fails_clearly_for_missing_or_empty_folders(tmp_path):
    with pytest.raises(RuntimeError, match="Nuclei folder not found"):
        action_data.build_dataset(tmp_path / "nope", LIBRARIES / "lynis", tmp_path / "x.csv.gz")
    (tmp_path / "empty").mkdir()
    with pytest.raises(RuntimeError, match="No checks found in the Lynis folder"):
        action_data.build_dataset(LIBRARIES / "nuclei-templates", tmp_path / "empty", tmp_path / "x.csv.gz")


@pytest.mark.parametrize("content", [b"not gzip", gzip.compress(b"a,b\n1,2\n")])
def test_load_dataset_rejects_bad_files(monkeypatch, tmp_path, content):
    path = tmp_path / "bad.csv.gz"
    path.write_bytes(content)
    monkeypatch.setattr(config, "ACTION_DATASET_PATH", path)
    with pytest.raises(RuntimeError):
        action_data.load_dataset()


def test_row_text():
    assert action_data.row_text("SSH Weak MAC", "Weak MACs are enabled.") == "SSH Weak MAC. Weak MACs are enabled"
    assert action_data.row_text("Consider hardening SSH configuration", "") == "Consider hardening SSH configuration"


# ====================================================================== the committed dataset
def test_committed_dataset_is_valid(monkeypatch):
    """data/action_training.csv.gz loads, uses only valid labels and covers every action from real checks."""
    monkeypatch.setattr(config, "ACTION_DATASET_PATH", config.BASE_DIR / "data" / "action_training.csv.gz")
    rows = action_data.load_dataset()
    assert len(rows) > 10_000
    counts = collections.Counter(r["action"] for r in rows)
    assert set(counts) == set(schemas.ML_ACTIONS) and min(counts.values()) >= 10
    assert {r["source"] for r in rows} == {"nuclei", "lynis"}
    assert all(r["title"] for r in rows)
    assert not any(r["category"].split("/")[0] in ("cloud", "code", "file", "dast") for r in rows)
