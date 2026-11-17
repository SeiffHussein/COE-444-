"""
modules/ml_classifier.py - two small scikit-learn models that ADVISE on findings.

    priority model -> ml_priority  (LOW / MEDIUM / HIGH / CRITICAL)          learns from real NVD CVEs
    action model   -> ml_action    (REVIEW_SERVICE, PATCH_OR_UPDATE, ...)   learns from real scanner checks

The scanners find the issues. The models only suggest how urgent a finding is
and which kind of action fits. An ML action is a label for a human to read -
it is never executed. Both models read TEXT: a finding's title + description.

PRIORITY MODEL
    Training data: the CVE table built from the NVD feeds (modules/nvd.py,
    data/nvd_cves.csv.gz). Input = the English description of a CVE,
    label = the official CVSS severity NVD gave it.
    Method: TF-IDF (a weight for every word, word pair and word triple that
    appears in at least 3 descriptions) -> LinearSVC, a linear model: each
    word gets one learned weight per severity, and the severity with the
    highest total wins. Rare classes get extra weight (class_weight="balanced").

    Limits to state clearly:
      * The model has only ever read CVE descriptions. For findings that are
        not CVEs (a Lynis suggestion, a Nikto message) it is working outside
        what it was trained on, and its rating is much less reliable.
      * NVD has no "informational" class, so the model cannot say "this is not
        a vulnerability". Findings the scanner itself rates Info (open ports,
        service detections, the hardening index) are therefore NOT rated:
        their ml_priority stays empty.

ACTION MODEL
    Training data: data/action_training.csv.gz (modules/action_data.py): about
    11,000 real checks from the Nuclei template library and Lynis. Input =
    check name + description, written by the tools' maintainers. Label = one
    of the seven actions, derived by a documented rule from how the
    maintainers filed the check (folder, tags, CVE id, Lynis test group).
    So the INPUT is real; the LABEL is our rule applied to real categories.
    Method: TF-IDF of words and word pairs + TF-IDF of character fragments
    (3-5 letters, which helps with product names and short titles) -> LinearSVC,
    balanced class weights. SSH and TLS checks are rare in both libraries, so
    those two classes have very few examples.

Command line:
    python -m modules.ml_classifier      train both models (about a minute)
"""

from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, make_pipeline
from sklearn.svm import LinearSVC

import config
from modules import action_data, nvd
from schemas import ML_ACTIONS, ML_PRIORITIES

SAMPLE_NOTE = "SAMPLE DATA - not from a real scan. "     # label added by sample mode; not part of the finding text


def finding_text(finding: dict) -> str:
    """The text both models read for one finding: title + description (sample label removed)."""
    description = str(finding.get("description", "")).replace(SAMPLE_NOTE, "")
    return action_data.row_text(str(finding.get("title", "")), description)


# ---------------------------------------------------------------- training
def evaluate_predictions(y_true, predicted, labels: tuple[str, ...], train_rows: int,
                         ordered: bool = False) -> dict:
    """Accuracy, macro precision/recall/F1, per-class recall and confusion matrix for one model.

    ordered=True (labels run from most to least severe) also reports
    "within_one_level": the share of predictions that are right or one level off.
    """
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, predicted, labels=list(labels), average="macro", zero_division=0)
    per_class = precision_recall_fscore_support(y_true, predicted, labels=list(labels), zero_division=0)[1]
    extra = {}
    if ordered:
        rank = {label: i for i, label in enumerate(labels)}
        near = sum(abs(rank[a] - rank[b]) <= 1 for a, b in zip(y_true, predicted))
        extra["within_one_level"] = round(near / len(y_true), 4)
    return {**extra,
        "recall_per_class": {label: round(float(r), 4) for label, r in zip(labels, per_class)},
        "accuracy": round(float(accuracy_score(y_true, predicted)), 4),
        "precision_macro": round(float(precision), 4),
        "recall_macro": round(float(recall), 4),
        "f1_macro": round(float(f1), 4),
        "labels": list(labels),
        "confusion_matrix": confusion_matrix(y_true, predicted, labels=list(labels)).tolist(),
        "train_rows": int(train_rows),
        "test_rows": int(len(y_true)),
    }


def train_priority_model() -> dict:
    """Train the priority model on REAL NVD data, save it, reload it. Returns its metrics.

    Input = CVE description text, label = NVD's CVSS severity. Evaluated on a
    held-out 25 % of real CVEs the model never saw.

    Raises:
        RuntimeError: NVD index missing, or too few rated CVEs to train on.
    """
    rows = [r for r in nvd.load_index().values() if r["cvss_severity"] in ML_PRIORITIES and r["description"]]
    counts = {label: sum(r["cvss_severity"] == label for r in rows) for label in ML_PRIORITIES}
    if min(counts.values()) < 4:
        raise RuntimeError(f"Not enough rated CVEs in the NVD index to train on: {counts}")
    texts, labels = [r["description"] for r in rows], [r["cvss_severity"] for r in rows]
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=config.ML_TEST_SIZE, random_state=config.RANDOM_SEED, stratify=labels)

    model = make_pipeline(
        # words, word pairs and word triples -> numbers (how characteristic each is for a description)
        TfidfVectorizer(ngram_range=(1, 3), min_df=3, stop_words="english", sublinear_tf=True),
        # one weight per word and severity; rare severities (LOW, CRITICAL) count extra
        LinearSVC(C=0.5, class_weight="balanced", random_state=config.RANDOM_SEED),
    )
    model.fit(X_train, y_train)
    metrics = evaluate_predictions(y_test, model.predict(X_test), ML_PRIORITIES, len(X_train), ordered=True)
    metrics["training_data"] = f"real NVD CVE descriptions ({len(rows)} rated CVEs)"

    path = Path(config.PRIORITY_MODEL_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "labels": list(ML_PRIORITIES), "metrics": metrics}, path, compress=3)
    # Reload from disk and check the saved model really predicts valid labels.
    if not set(joblib.load(path)["model"].predict(X_test[:5])) <= set(ML_PRIORITIES):
        raise RuntimeError(f"Reloaded model at {path} predicted unknown labels.")
    return metrics


def train_action_model() -> dict:
    """Train the action model on the REAL scanner checks, save it, reload it. Returns its metrics.

    Raises:
        RuntimeError: action dataset missing/unreadable, or a class has too few rows to split.
    """
    rows = action_data.load_dataset()
    texts = [action_data.row_text(r["title"], r["description"]) for r in rows]
    labels = [r["action"] for r in rows]
    counts = {label: labels.count(label) for label in ML_ACTIONS}
    if min(counts.values()) < 4:
        raise RuntimeError(f"Not enough checks per action in the action dataset to train on: {counts}")
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=config.ML_TEST_SIZE, random_state=config.RANDOM_SEED, stratify=labels)

    model = make_pipeline(
        FeatureUnion([
            # words and word pairs, as in the priority model
            ("words", TfidfVectorizer(ngram_range=(1, 2), min_df=2, stop_words="english", sublinear_tf=True)),
            # 3-5 letter fragments: helps with product names and very short titles
            ("chars", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True)),
        ]),
        LinearSVC(C=0.5, class_weight="balanced", random_state=config.RANDOM_SEED),
    )
    model.fit(X_train, y_train)
    metrics = evaluate_predictions(y_test, model.predict(X_test), ML_ACTIONS, len(X_train))
    metrics["training_data"] = (f"real Nuclei and Lynis checks ({len(rows)} checks), "
                                "labels from the maintainers' categories via our rule")

    path = Path(config.ACTION_MODEL_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "labels": list(ML_ACTIONS), "metrics": metrics}, path, compress=3)
    if not set(joblib.load(path)["model"].predict(X_test[:5])) <= set(ML_ACTIONS):
        raise RuntimeError(f"Reloaded model at {path} predicted unknown labels.")
    return metrics


def train_models() -> dict:
    """Train and save both models. Returns {"priority": metrics, "action": metrics}.

    Raises:
        RuntimeError: NVD index or action dataset missing/invalid, or a saved
                      model fails its reload check.
    """
    return {"priority": train_priority_model(), "action": train_action_model()}


def format_metrics(name: str, metrics: dict) -> str:
    """Readable text block: accuracy, macro precision/recall/F1, extra metrics and the confusion matrix."""
    labels = metrics["labels"]
    width = max(len(label) for label in labels) + 2
    lines = [
        f"=== {name} model ({metrics['train_rows']} train rows / {metrics['test_rows']} test rows) ===",
        f"training data   {metrics.get('training_data', '')}",
        f"accuracy        {metrics['accuracy']:.3f}",
        f"macro precision {metrics['precision_macro']:.3f}",
        f"macro recall    {metrics['recall_macro']:.3f}",
        f"macro F1        {metrics['f1_macro']:.3f}",
    ]
    if "within_one_level" in metrics:
        lines.append(f"right or one level off  {metrics['within_one_level']:.3f}")
    if "recall_per_class" in metrics:
        lines.append("recall per class " + ", ".join(f"{k} {v:.2f}" for k, v in metrics["recall_per_class"].items()))
    lines += [
        "confusion matrix (rows = true label, columns = predicted label, same order):",
    ]
    for label, row in zip(labels, metrics["confusion_matrix"]):
        lines.append(f"  {label:<{width}}" + " ".join(f"{count:>4}" for count in row))
    return "\n".join(lines)


# ---------------------------------------------------------------- runtime
_loaded_models: dict = {}      # {(path, modified time): bundle} - load each model file once


def load_model(path: str | Path) -> dict:
    """Load one saved model bundle. Raises RuntimeError if missing or unreadable."""
    path = Path(path)
    if not path.exists():
        raise RuntimeError(f"Model file {path.name} is missing. Train it with: python -m modules.ml_classifier")
    key = (str(path), path.stat().st_mtime)
    if key not in _loaded_models:
        try:
            bundle = joblib.load(path)
            bundle["model"], bundle["labels"]
        except Exception as exc:  # corrupt file, wrong library version, wrong content
            raise RuntimeError(f"Model file {path.name} could not be loaded: {exc}") from exc
        for old_key in [k for k in _loaded_models if k[0] == str(path)]:
            del _loaded_models[old_key]             # drop an older version of the same file
        _loaded_models[key] = bundle
    return _loaded_models[key]


def classify_findings(findings: list[dict]) -> tuple[list[dict], dict]:
    """Fill in ml_priority and ml_action for each finding.

    Returns:
        (findings, status). `findings` are copies; only ml_priority / ml_action
        are filled in. status = {"status": "SUCCESS" | "FAILED" | "SKIPPED", "error": str}.

        ml_action is predicted for every finding. ml_priority is predicted for
        findings the scanner rated above Info; Info findings are not
        vulnerabilities, which the NVD-trained model cannot express, so their
        ml_priority stays "".

        If a model is missing or broken, the findings come back UNCHANGED with
        status FAILED and the reason - a prediction is never made up.
        Never raises.
    """
    findings = [dict(f) for f in findings]
    if not findings:
        return findings, {"status": "SKIPPED", "error": "No findings to classify."}
    try:
        priority = load_model(config.PRIORITY_MODEL_PATH)
        action = load_model(config.ACTION_MODEL_PATH)
        actions = action["model"].predict([finding_text(f) for f in findings])
        rated = [i for i, f in enumerate(findings) if f.get("severity", "Info") != "Info"]
        priorities = dict(zip(rated, priority["model"].predict([finding_text(findings[i]) for i in rated]))) if rated else {}
        if not set(priorities.values()) <= set(ML_PRIORITIES) or not set(actions) <= set(ML_ACTIONS):
            raise RuntimeError("A model predicted a label outside the agreed label sets.")
    except Exception as exc:
        return findings, {"status": "FAILED", "error": f"ML unavailable: {exc}"}
    classified = [{**f, "ml_priority": str(priorities.get(i, "")), "ml_action": str(a)}
                  for i, (f, a) in enumerate(zip(findings, actions))]
    return classified, {"status": "SUCCESS", "error": ""}


def model_metrics() -> dict:
    """Metrics stored with the saved models ({} for a model that is not available)."""
    result = {}
    for name, path in (("priority", config.PRIORITY_MODEL_PATH), ("action", config.ACTION_MODEL_PATH)):
        try:
            result[name] = load_model(path).get("metrics", {})
        except RuntimeError:
            result[name] = {}
    return result


if __name__ == "__main__":
    for model_name, model_metrics_ in train_models().items():
        print(format_metrics(model_name, model_metrics_))
        print()
    print(f"Models saved in {config.MODELS_DIR}")
    print("NOTE: both scores are measured on held-out real data. The priority score says how well the model")
    print("      rates CVE descriptions, not other findings. The action score says how well the model")
    print("      recovers OUR labelling rule from the text of real checks; it is not a judgement by a person.")
