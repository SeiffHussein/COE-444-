"""NVD: feed parsing, index, CVE lookup, severity model, and every 'data missing' case.

The index and model used here are built in conftest.py from tests/fixtures/nvd_feed_sample.json
(a real 82-CVE excerpt of the NVD feed). Nothing is downloaded.
"""

from __future__ import annotations

import gzip
import json
import zipfile

import pytest

import config
import schemas
from modules import nvd
from tests.conftest import FIXTURES, LAB_HOST

FEED = FIXTURES / "nvd_feed_sample.json"
KNOWN_CVE, KNOWN_SCORE, KNOWN_SEVERITY = "CVE-2022-22274", 9.8, "CRITICAL"     # real values from the feed
REJECTED_CVE, UNRATED_CVE = "CVE-2000-0744", "CVE-2025-39980"


def cve_finding(cve: str, **extra) -> dict:
    return schemas.new_finding(LAB_HOST, "nuclei", "Stack-based buffer overflow in SonicOS",
                               description="A stack-based buffer overflow allows a remote unauthenticated attacker "
                                           "to cause denial of service or code execution.",
                               severity="Critical", cve=cve, **extra)


# ====================================================================== feed -> index
def test_parse_feed_rows():
    rows = {r["cve_id"]: r for r in nvd.parse_feed(nvd.read_feed(FEED))}
    assert len(rows) == 81 and REJECTED_CVE not in rows                  # 82 in the file, 1 rejected
    known = rows[KNOWN_CVE]
    assert tuple(known) == nvd.INDEX_COLUMNS
    assert float(known["cvss_score"]) == KNOWN_SCORE and known["cvss_severity"] == KNOWN_SEVERITY
    assert known["cvss_version"] == "3.1" and known["cvss_vector"].startswith("CVSS:3.1/")
    assert known["description"] and len(known["published"]) == 10
    unrated = rows[UNRATED_CVE]                                          # kept, but nothing invented
    assert unrated["cvss_score"] == unrated["cvss_severity"] == unrated["cvss_vector"] == ""
    assert {r["cvss_severity"] for r in rows.values()} == set(schemas.CVSS_SEVERITIES) | {""}


def test_pick_cvss_prefers_v31_primary_and_reads_v2_severity():
    v31 = lambda score, sev, kind: {"type": kind, "cvssData": {"version": "3.1", "baseScore": score, "baseSeverity": sev,
                                                               "vectorString": "CVSS:3.1/x"}}
    v2 = {"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 9.0, "vectorString": "AV:N"}}
    assert nvd._pick_cvss({"cvssMetricV2": [v2], "cvssMetricV31": [v31(5.0, "MEDIUM", "Secondary"), v31(8.8, "HIGH", "Primary")]}) \
        == ("3.1", "8.8", "HIGH", "CVSS:3.1/x")
    assert nvd._pick_cvss({"cvssMetricV2": [v2]}) == ("2.0", "9.0", "HIGH", "AV:N")
    assert nvd._pick_cvss({}) == ("", "", "", "")
    assert nvd._pick_cvss({"cvssMetricV31": [v31(0.0, "NONE", "Primary")]}) == ("", "", "", "")


def test_read_feed_accepts_json_gz_and_zip(tmp_path):
    text = FEED.read_text(encoding="utf-8")
    (tmp_path / "f.json.gz").write_bytes(gzip.compress(text.encode()))
    with zipfile.ZipFile(tmp_path / "f.json.zip", "w") as archive:
        archive.writestr("nvdcve-2.0-modified.json", text)
    for name in ("f.json.gz", "f.json.zip"):
        assert len(nvd.read_feed(tmp_path / name)["vulnerabilities"]) == 82


@pytest.mark.parametrize("content", ["not json", "[1, 2]", '{"format": "OTHER", "vulnerabilities": []}', '{"format": "NVD_CVE"}'])
def test_read_feed_rejects_bad_files(tmp_path, content):
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(RuntimeError):
        nvd.read_feed(path)
    with pytest.raises(RuntimeError):
        nvd.read_feed(tmp_path / "missing.json")


def test_build_index_is_reproducible_and_loadable(tmp_path, monkeypatch, trained_model_dir):
    assert trained_model_dir.nvd_count == 81
    first, second = tmp_path / "a.csv.gz", tmp_path / "b.csv.gz"
    assert nvd.build_index([FEED], first) == nvd.build_index([FEED, FEED], second) == 81   # duplicates merged
    assert first.read_bytes() == second.read_bytes()
    monkeypatch.setattr(config, "NVD_INDEX_PATH", first)
    index = nvd.load_index()
    assert len(index) == 81 and index[KNOWN_CVE]["cvss_severity"] == KNOWN_SEVERITY


def test_build_index_without_feeds_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "NVD_FEEDS_DIR", tmp_path / "empty")
    with pytest.raises(RuntimeError, match="No NVD feed files"):
        nvd.build_index(index_path=tmp_path / "x.csv.gz")


def test_committed_index_is_valid():
    """The index shipped in data/ loads and holds only well-formed rows."""
    with gzip.open(config.BASE_DIR / "data" / "nvd_cves.csv.gz", "rt", encoding="utf-8", newline="") as fh:
        import csv
        rows = list(csv.DictReader(fh))
    assert len(rows) > 5000 and tuple(rows[0]) == nvd.INDEX_COLUMNS
    assert all(r["cve_id"].startswith("CVE-") and r["cvss_severity"] in ("",) + schemas.CVSS_SEVERITIES for r in rows)
    assert all(0 <= float(r["cvss_score"]) <= 10 for r in rows if r["cvss_score"])


# ====================================================================== lookup
def test_lookup_fills_official_values_only_for_known_cves():
    findings = [cve_finding(KNOWN_CVE), cve_finding("CVE-2021-41773"), cve_finding(UNRATED_CVE),
                schemas.new_finding(LAB_HOST, "nmap", "Open port 22/tcp (ssh)", port=22, service="ssh")]
    enriched, status = nvd.enrich_findings(findings)
    assert status == {"status": "SUCCESS", "error": "", "cve_findings": 3, "matched": 1, "estimated": 3}
    known, unknown, unrated, port = enriched
    assert known["cvss_score"] == KNOWN_SCORE and known["nvd_severity"] == KNOWN_SEVERITY
    for f in (unknown, unrated):                                         # not in index / no rating: nothing invented
        assert f["cvss_score"] is None and f["nvd_severity"] == ""
        assert f["ml_cvss_estimate"] in schemas.CVSS_SEVERITIES
    # a finding without a CVE is never touched - the model is not applied to it
    assert port == findings[3] and port["ml_cvss_estimate"] == ""
    for before, after in zip(findings, enriched):                        # only the three NVD fields change
        changed = {k for k in before if before[k] != after[k]}
        assert changed <= {"cvss_score", "nvd_severity", "ml_cvss_estimate"}
        assert before["cvss_score"] is None                              # input not modified
        schemas.validate_finding(after)


def test_lookup_with_several_cves_uses_the_highest_score():
    index = nvd.load_index()
    low = next(r for r in index.values() if r["cvss_severity"] == "LOW")
    enriched, _ = nvd.enrich_findings([cve_finding(f"{low['cve_id']}, {KNOWN_CVE.lower()}, CVE-1999-0001")])
    assert enriched[0]["cvss_score"] == KNOWN_SCORE and enriched[0]["nvd_severity"] == KNOWN_SEVERITY


def test_no_cve_findings_is_skipped():
    findings = [schemas.new_finding(LAB_HOST, "nmap", "Open port 80/tcp (http)")]
    enriched, status = nvd.enrich_findings(findings)
    assert enriched == findings and status["status"] == "SKIPPED" and status["cve_findings"] == 0
    assert nvd.enrich_findings([])[1]["status"] == "SKIPPED"


@pytest.mark.parametrize("broken", ["missing", "corrupt"])
def test_missing_or_corrupt_index_gives_no_official_values(monkeypatch, tmp_path, broken):
    path = tmp_path / "index.csv.gz"
    if broken == "corrupt":
        path.write_bytes(b"not a gzip file")
    monkeypatch.setattr(config, "NVD_INDEX_PATH", path)
    enriched, status = nvd.enrich_findings([cve_finding(KNOWN_CVE)])
    assert status["status"] == "FAILED" and "NVD lookup unavailable" in status["error"] and status["matched"] == 0
    assert enriched[0]["cvss_score"] is None and enriched[0]["nvd_severity"] == ""
    assert enriched[0]["ml_cvss_estimate"] in schemas.CVSS_SEVERITIES    # the model still works


# ====================================================================== model
def test_severity_model_trains_saves_reloads(trained_model_dir):
    metrics = trained_model_dir.nvd_metrics
    assert metrics["labels"] == list(schemas.CVSS_SEVERITIES)
    assert metrics["train_rows"] + metrics["test_rows"] == 80            # the unrated CVE is not used
    assert 0.0 <= metrics["accuracy"] <= 1.0 and sum(map(sum, metrics["confusion_matrix"])) == metrics["test_rows"]
    bundle = nvd.load_severity_model()
    assert bundle["labels"] == list(schemas.CVSS_SEVERITIES) and nvd.model_metrics() == metrics
    assert set(bundle["model"].predict(["SQL injection allows remote attackers to execute arbitrary commands"])) \
        <= set(schemas.CVSS_SEVERITIES)


@pytest.mark.parametrize("broken", ["missing", "corrupt", "wrong_content"])
def test_missing_or_broken_model_gives_no_estimate(monkeypatch, tmp_path, broken):
    path = tmp_path / "nvd.joblib"
    if broken == "corrupt":
        path.write_bytes(b"not a model")
    elif broken == "wrong_content":
        import joblib
        joblib.dump({"something": "else"}, path)
    monkeypatch.setattr(config, "NVD_MODEL_PATH", path)
    enriched, status = nvd.enrich_findings([cve_finding(KNOWN_CVE)])
    assert status["status"] == "FAILED" and "NVD severity model unavailable" in status["error"] and status["estimated"] == 0
    assert enriched[0]["ml_cvss_estimate"] == ""                         # no estimate is faked
    assert enriched[0]["cvss_score"] == KNOWN_SCORE                      # the lookup still works
    assert nvd.model_metrics() == {}


def test_training_needs_enough_rated_cves(monkeypatch, tmp_path):
    data = json.loads(FEED.read_text(encoding="utf-8"))
    data["vulnerabilities"] = data["vulnerabilities"][:5]
    small = tmp_path / "small.json"
    small.write_text(json.dumps(data))
    monkeypatch.setattr(config, "NVD_INDEX_PATH", tmp_path / "small.csv.gz")
    nvd.build_index([small])
    with pytest.raises(RuntimeError, match="Not enough rated CVEs"):
        nvd.train_severity_model()
