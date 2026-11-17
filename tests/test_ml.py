"""ML: priority model (real NVD data), action model (real scanner checks), save/reload, valid labels,
missing model handled. The action dataset builder is tested in test_action_data.py."""

from __future__ import annotations

import pytest

import json

import config
import schemas
from modules import host_auditor, ml_classifier, nvd, target_scanner, vulnerability_scanner
from tests.conftest import FIXTURES, LAB_HOST, fixture_text


def lab_findings() -> list[dict]:
    return (target_scanner._parse_nmap_xml(fixture_text("nmap_scan.xml"), LAB_HOST)
            + vulnerability_scanner._parse_nuclei_jsonl(fixture_text("nuclei_results.jsonl"), LAB_HOST)
            + vulnerability_scanner._parse_nikto_json(fixture_text("nikto_results.json"), LAB_HOST)
            + host_auditor._parse_lynis_report(fixture_text("lynis_report.dat"), LAB_HOST))


def test_finding_text_drops_the_sample_label():
    finding = schemas.new_finding("h", "nuclei", "SQL injection", description="SAMPLE DATA - not from a real scan. Allows RCE.")
    assert ml_classifier.finding_text(finding) == "SQL injection. Allows RCE"


# ====================================================================== training
def test_priority_model_is_trained_on_real_nvd_rows(trained_model_dir):
    metrics = trained_model_dir.metrics["priority"]
    assert "real NVD" in metrics["training_data"]
    assert metrics["train_rows"] + metrics["test_rows"] == 80          # the 80 rated CVEs of the test index
    assert "real Nuclei and Lynis" in trained_model_dir.metrics["action"]["training_data"]
    bundle = ml_classifier.load_model(config.PRIORITY_MODEL_PATH)
    prediction = bundle["model"].predict(["SQL injection allows remote attackers to execute arbitrary commands"])
    assert set(prediction) <= set(schemas.ML_PRIORITIES)


def test_within_one_level_metric():
    metrics = ml_classifier.evaluate_predictions(
        ["CRITICAL", "CRITICAL", "LOW", "MEDIUM"], ["HIGH", "MEDIUM", "LOW", "MEDIUM"],
        schemas.ML_PRIORITIES, train_rows=10, ordered=True)
    assert metrics["accuracy"] == 0.5 and metrics["within_one_level"] == 0.75   # CRITICAL -> MEDIUM is two off
    assert metrics["recall_per_class"] == {"CRITICAL": 0.0, "HIGH": 0.0, "MEDIUM": 1.0, "LOW": 1.0}
    assert "within_one_level" not in ml_classifier.evaluate_predictions(["A", "B"], ["A", "A"], ("A", "B"), 1)
    assert "right or one level off  0.750" in ml_classifier.format_metrics("priority", metrics)


def test_priority_training_needs_the_nvd_index(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "NVD_INDEX_PATH", tmp_path / "missing.csv.gz")
    with pytest.raises(RuntimeError, match="NVD index"):
        ml_classifier.train_priority_model()
    data = json.loads((FIXTURES / "nvd_feed_sample.json").read_text(encoding="utf-8"))
    data["vulnerabilities"] = data["vulnerabilities"][:5]
    small = tmp_path / "small.json"
    small.write_text(json.dumps(data))
    nvd.build_index([small], tmp_path / "missing.csv.gz")
    with pytest.raises(RuntimeError, match="Not enough rated CVEs"):
        ml_classifier.train_priority_model()


def test_train_save_reload_and_metrics(trained_model_dir):
    for name, labels in (("priority", schemas.ML_PRIORITIES), ("action", schemas.ML_ACTIONS)):
        metrics = trained_model_dir.metrics[name]
        assert 0.0 < metrics["accuracy"] <= 1.0
        for key in ("precision_macro", "recall_macro", "f1_macro"):
            assert 0.0 < metrics[key] <= 1.0
        assert metrics["labels"] == list(labels)
        assert len(metrics["confusion_matrix"]) == len(labels)
        assert sum(map(sum, metrics["confusion_matrix"])) == metrics["test_rows"]
        text = ml_classifier.format_metrics(name, metrics)
        assert "accuracy" in text and "macro F1" in text and "confusion matrix" in text and "training data" in text
        # the saved bundle reloads with the model and the labels
        bundle = ml_classifier.load_model(trained_model_dir.folder / f"{name}.joblib")
        assert bundle["labels"] == list(labels) and bundle["metrics"] == metrics
    action = ml_classifier.load_model(config.ACTION_MODEL_PATH)
    assert trained_model_dir.metrics["action"]["train_rows"] + trained_model_dir.metrics["action"]["test_rows"] == 145
    assert set(action["model"].predict(["SSH weak MAC algorithms enabled", "Grafana login panel"])) <= set(schemas.ML_ACTIONS)


def test_classify_fills_only_ml_fields_with_valid_labels():
    findings = lab_findings()
    classified, status = ml_classifier.classify_findings(findings)
    assert status == {"status": "SUCCESS", "error": ""} and len(classified) == len(findings)
    for before, after in zip(findings, classified):
        assert after["ml_action"] in schemas.ML_ACTIONS
        if before["severity"] == "Info":                               # not a vulnerability -> not rated
            assert after["ml_priority"] == ""
        else:
            assert after["ml_priority"] in schemas.ML_PRIORITIES
        assert {k: v for k, v in after.items() if k not in ("ml_priority", "ml_action")} == \
               {k: v for k, v in before.items() if k not in ("ml_priority", "ml_action")}
        assert before["ml_priority"] == "" and before["ml_action"] == ""    # input not modified
    assert sum(f["ml_priority"] == "" for f in classified) == 6        # 3 open ports, 2 Nuclei info, hardening index
    # Which action each sample finding gets is checked in demo_tests.py, which trains on the full real
    # dataset; the 145-row model used here is too small to judge individual labels.


def test_classify_empty_list():
    findings, status = ml_classifier.classify_findings([])
    assert findings == [] and status["status"] == "SKIPPED"


@pytest.mark.parametrize("broken", ["missing", "corrupt", "wrong_content"])
def test_missing_or_broken_model_returns_findings_unchanged(monkeypatch, tmp_path, broken):
    path = tmp_path / "priority.joblib"
    if broken == "corrupt":
        path.write_bytes(b"this is not a model")
    elif broken == "wrong_content":
        import joblib
        joblib.dump({"something": "else"}, path)
    monkeypatch.setattr(config, "PRIORITY_MODEL_PATH", path)
    findings = lab_findings()
    result, status = ml_classifier.classify_findings(findings)
    assert status["status"] == "FAILED" and "ML unavailable" in status["error"]
    assert result == findings                                           # nothing predicted, nothing faked
    assert all(f["ml_priority"] == "" and f["ml_action"] == "" for f in result)
    assert ml_classifier.model_metrics()["priority"] == {}


def test_missing_action_dataset_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "ACTION_DATASET_PATH", tmp_path / "nope.csv.gz")
    with pytest.raises(RuntimeError, match="Action dataset nope.csv.gz not found"):
        ml_classifier.train_action_model()


def test_only_info_findings_is_still_a_success():
    findings = [f for f in lab_findings() if f["severity"] == "Info"]
    classified, status = ml_classifier.classify_findings(findings)
    assert status["status"] == "SUCCESS" and all(f["ml_priority"] == "" and f["ml_action"] for f in classified)
