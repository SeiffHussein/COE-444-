"""ML: dataset, training, save/reload, valid labels, missing model handled."""

from __future__ import annotations

import pandas as pd
import pytest

import config
import schemas
from modules import host_auditor, ml_classifier, target_scanner, vulnerability_scanner
from tests.conftest import LAB_HOST, fixture_text


def lab_findings() -> list[dict]:
    return (target_scanner._parse_nmap_xml(fixture_text("nmap_scan.xml"), LAB_HOST)
            + vulnerability_scanner._parse_nuclei_jsonl(fixture_text("nuclei_results.jsonl"), LAB_HOST)
            + vulnerability_scanner._parse_nikto_json(fixture_text("nikto_results.json"), LAB_HOST)
            + host_auditor._parse_lynis_report(fixture_text("lynis_report.dat"), LAB_HOST))


def test_dataset_covers_every_tool_and_class():
    df = pd.read_csv(config.SYNTHETIC_DATASET_PATH)
    assert len(df) >= 500
    assert set(df["source_tool"]) == set(schemas.TOOLS)
    assert set(df["priority"]) == set(schemas.ML_PRIORITIES)
    assert set(df["action"]) == set(schemas.ML_ACTIONS)
    assert set(df["category"]) == set(ml_classifier.CATEGORIES)
    X, y_priority, y_action = ml_classifier.load_dataset()
    assert list(X.columns) == ml_classifier.FEATURE_COLUMNS and len(X) == len(y_priority) == len(y_action)


def test_dataset_is_reproducible_and_not_a_copy_of_severity(tmp_path):
    first = ml_classifier.generate_synthetic_dataset(tmp_path / "a.csv").read_text()
    second = ml_classifier.generate_synthetic_dataset(tmp_path / "b.csv").read_text()
    assert first == second                                             # fixed seed
    assert first == config.SYNTHETIC_DATASET_PATH.read_text()         # committed CSV is the generated one
    df = pd.read_csv(tmp_path / "a.csv")
    assert df.groupby("severity_score")["priority"].nunique().max() > 1   # same severity, different priority


def test_label_rules():
    row = {"severity_score": 4, "source_tool": "nuclei", "has_cve": 1, "category": "web",
           "is_misconfiguration": 0, "internet_facing": 0, "asset_criticality": 2}
    assert ml_classifier.priority_rule(row) == "CRITICAL" and ml_classifier.action_rule(row) == "PATCH_OR_UPDATE"
    row = {"severity_score": 0, "source_tool": "nmap", "has_cve": 0, "category": "ssh",
           "is_misconfiguration": 0, "internet_facing": 0, "asset_criticality": 2}
    assert ml_classifier.priority_rule(row) == "LOW" and ml_classifier.action_rule(row) == "REVIEW_SERVICE"
    row = {"severity_score": 1, "source_tool": "lynis", "has_cve": 0, "category": "ssh",
           "is_misconfiguration": 1, "internet_facing": 0, "asset_criticality": 2}
    assert ml_classifier.action_rule(row) == "HARDEN_SSH"


def test_extract_features():
    findings = lab_findings()
    cve = next(f for f in findings if f["cve"])
    assert ml_classifier.extract_features(cve) == {
        "severity_score": 4, "source_tool": "nuclei", "has_cve": 1, "category": "web",
        "is_misconfiguration": 0, "internet_facing": config.ASSET_INTERNET_FACING,
        "asset_criticality": config.ASSET_CRITICALITY}
    root = next(f for f in findings if "PermitRootLogin" in f["title"])
    features = ml_classifier.extract_features(root)
    assert features["category"] == "ssh" and features["is_misconfiguration"] == 1 and features["has_cve"] == 0
    tls = next(f for f in findings if "Self Signed" in f["title"])
    assert ml_classifier.extract_features(tls)["category"] == "tls"
    assert ml_classifier.extract_features({})["category"] == "none"
    assert list(ml_classifier.encode_features([features]).columns) == ml_classifier.FEATURE_COLUMNS


def test_train_save_reload_and_metrics(trained_model_dir):
    for name, labels in (("priority", schemas.ML_PRIORITIES), ("action", schemas.ML_ACTIONS)):
        metrics = trained_model_dir.metrics[name]
        assert 0.6 < metrics["accuracy"] <= 1.0
        for key in ("precision_macro", "recall_macro", "f1_macro"):
            assert 0.0 < metrics[key] <= 1.0
        assert metrics["labels"] == list(labels)
        assert len(metrics["confusion_matrix"]) == len(labels)
        assert sum(map(sum, metrics["confusion_matrix"])) == metrics["test_rows"]
        text = ml_classifier.format_metrics(name, metrics)
        assert "accuracy" in text and "macro F1" in text and "confusion matrix" in text
        # saved bundle reloads with the model, the feature order and the labels
        bundle = ml_classifier.load_model(trained_model_dir.folder / f"{name}.joblib")
        assert bundle["feature_columns"] == ml_classifier.FEATURE_COLUMNS and bundle["labels"] == list(labels)
        X, _, _ = ml_classifier.load_dataset()
        assert set(bundle["model"].predict(X.head(20))) <= set(labels)


def test_classify_fills_only_ml_fields_with_valid_labels():
    findings = lab_findings()
    classified, status = ml_classifier.classify_findings(findings)
    assert status == {"status": "SUCCESS", "error": ""} and len(classified) == len(findings)
    for before, after in zip(findings, classified):
        assert after["ml_priority"] in schemas.ML_PRIORITIES and after["ml_action"] in schemas.ML_ACTIONS
        assert {k: v for k, v in after.items() if k not in ("ml_priority", "ml_action")} == \
               {k: v for k, v in before.items() if k not in ("ml_priority", "ml_action")}
        assert before["ml_priority"] == "" and before["ml_action"] == ""    # input not modified
    by_title = {f["title"]: f for f in classified}
    cve = next(f for f in classified if f["cve"])
    assert cve["ml_priority"] == "CRITICAL" and cve["ml_action"] == "PATCH_OR_UPDATE"
    assert by_title["Open port 22/tcp (ssh)"]["ml_action"] == "REVIEW_SERVICE"
    assert next(f for f in classified if "PermitRootLogin" in f["title"])["ml_action"] == "HARDEN_SSH"


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


def test_missing_dataset_is_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "SYNTHETIC_DATASET_PATH", tmp_path / "nope.csv")
    with pytest.raises(RuntimeError, match="Dataset not found"):
        ml_classifier.train_models()
