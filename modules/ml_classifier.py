"""
modules/ml_classifier.py - two small scikit-learn models that ADVISE on findings.

    priority model -> ml_priority  (LOW / MEDIUM / HIGH / CRITICAL)   trained on REAL NVD data
    action model   -> ml_action    (REVIEW_SERVICE, PATCH_OR_UPDATE, ...)  trained on SYNTHETIC data

The scanners find the issues. The models only suggest how urgent a finding is
and which kind of action fits. An ML action is a label for a human to read -
it is never executed.

PRIORITY MODEL (real data)
    Training data: the CVE table built from the NVD feeds (modules/nvd.py,
    data/nvd_cves.csv.gz). Input = the English description of a CVE,
    label = the official CVSS severity NVD gave it.
    Method: TF-IDF (a weight for every word, word pair and word triple that
    appears in at least 3 descriptions) -> LinearSVC, a linear model: each
    word gets one learned weight per severity, and the severity with the
    highest total wins. Rare classes get extra weight (class_weight="balanced").
    At runtime the input is a finding's title + description.

    Limits to state clearly:
      * The model has only ever read CVE descriptions. For findings that are
        not CVEs (a Lynis suggestion, a Nikto message) it is working outside
        what it was trained on, and its rating is much less reliable.
      * NVD has no "informational" class, so the model cannot say "this is not
        a vulnerability". Findings the scanner itself rates Info (open ports,
        service detections, the hardening index) are therefore NOT rated:
        their ml_priority stays empty.

ACTION MODEL (synthetic data)
    NVD has no "what to do" label, so this model still learns from
    data/synthetic_findings.csv, whose labels come from the rule below. Its
    accuracy only shows that it recovered our own rule.

    Features (one row per finding)
        severity_score        0-4   Info=0 ... Critical=4 (normalized severity)
        source_tool           nmap / nuclei / nikto / lynis          (one-hot encoded)
        has_cve               0/1   the tool reported a CVE id
        category              ssh / web / tls / other / none          (one-hot encoded)
        is_misconfiguration   0/1   a configuration weakness rather than a software flaw
    Label rule (first matching rule wins), then 5 % of rows get a random action:
        has_cve                               -> PATCH_OR_UPDATE
        category tls                          -> REVIEW_TLS
        source_tool nmap                      -> REVIEW_SERVICE
        category ssh and (misconfig or sev>0) -> HARDEN_SSH
        category web and misconfig            -> HARDEN_WEB_SERVER
        severity_score == 0                   -> NO_ACTION_INFORMATIONAL
        otherwise                             -> INVESTIGATE_FINDING

Command line:
    python -m modules.ml_classifier                train both models
    python -m modules.ml_classifier --regenerate   rebuild the synthetic CSV first, then train
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.svm import LinearSVC

import config
from modules import nvd
from schemas import ML_ACTIONS, ML_PRIORITIES, SEVERITY_SCORES, TOOLS

CATEGORIES: tuple[str, ...] = ("ssh", "web", "tls", "other", "none")

# Readable columns stored in the CSV ...
RAW_COLUMNS: list[str] = ["severity_score", "source_tool", "has_cve", "category", "is_misconfiguration"]
# ... and the numeric columns the models actually see (fixed order, saved with the model).
FEATURE_COLUMNS: list[str] = (
    ["severity_score", "has_cve", "is_misconfiguration"]
    + [f"tool_{t}" for t in TOOLS] + [f"cat_{c}" for c in CATEGORIES]
)
ACTION_COLUMN = "action"
SAMPLE_NOTE = "SAMPLE DATA - not from a real scan. "     # label added by sample mode; not part of the finding text

_TLS_WORDS = ("tls", "ssl", "certificate", "cipher")
_MISCONFIG_WORDS = ("misconfig", "header", "permitrootlogin", "root login", "directory indexing",
                    "default file", "hardening", "not present", "self-signed", "self signed",
                    "no rules active")


# ---------------------------------------------------------------- features
def extract_features(finding: dict) -> dict:
    """Turn one finding into the readable feature dict (keys = RAW_COLUMNS)."""
    tool = str(finding.get("source", "")).strip().lower()
    text = " ".join(str(finding.get(k, "")) for k in ("title", "description", "evidence", "check_id")).lower()
    service = str(finding.get("service", "")).lower()
    port = finding.get("port")
    has_cve = int(bool(str(finding.get("cve", "")).strip()))

    if service == "ssh" or port == 22 or "ssh" in text:
        category = "ssh"
    elif any(word in text for word in _TLS_WORDS):
        category = "tls"
    elif service in ("http", "https") or tool == "nikto" or port in (80, 443, 8080, 8443) or "http" in text:
        category = "web"
    elif port is not None or service:
        category = "other"
    else:
        category = "none"

    lynis_item = tool == "lynis" and str(finding.get("original_severity", "")) in ("warning", "suggestion")
    is_misconfiguration = int(not has_cve and (lynis_item or any(w in text for w in _MISCONFIG_WORDS)))

    return {
        "severity_score": SEVERITY_SCORES.get(finding.get("severity", "Info"), 0),
        "source_tool": tool,
        "has_cve": has_cve,
        "category": category,
        "is_misconfiguration": is_misconfiguration,
    }


def finding_text(finding: dict) -> str:
    """The text the priority model reads for one finding: title + description."""
    description = str(finding.get("description", "")).replace(SAMPLE_NOTE, "")
    return f"{finding.get('title', '')}. {description}".strip()


def encode_features(rows: list[dict] | pd.DataFrame) -> pd.DataFrame:
    """One-hot encode readable feature rows into the numeric FEATURE_COLUMNS table."""
    raw = pd.DataFrame(rows, columns=RAW_COLUMNS)
    encoded = raw[["severity_score", "has_cve", "is_misconfiguration"]].astype(int)
    for tool in TOOLS:
        encoded[f"tool_{tool}"] = (raw["source_tool"] == tool).astype(int)
    for category in CATEGORIES:
        encoded[f"cat_{category}"] = (raw["category"] == category).astype(int)
    return encoded[FEATURE_COLUMNS]


# ---------------------------------------------------------------- label rules
def action_rule(row: dict) -> str:
    """The documented action rule (before noise). See module docstring."""
    if row["has_cve"]:
        return "PATCH_OR_UPDATE"
    if row["category"] == "tls":
        return "REVIEW_TLS"
    if row["source_tool"] == "nmap":
        return "REVIEW_SERVICE"
    if row["category"] == "ssh" and (row["is_misconfiguration"] or row["severity_score"] > 0):
        return "HARDEN_SSH"
    if row["category"] == "web" and row["is_misconfiguration"]:
        return "HARDEN_WEB_SERVER"
    if row["severity_score"] == 0:
        return "NO_ACTION_INFORMATIONAL"
    return "INVESTIGATE_FINDING"


# ---------------------------------------------------------------- dataset
def generate_synthetic_dataset(path: str | Path | None = None, n_rows: int | None = None) -> Path:
    """Create the reproducible synthetic dataset for the ACTION model (fixed seed).

    Each row imitates a finding one of the four tools could plausibly produce
    (e.g. Nmap rows are always Info without a CVE). The label comes from
    action_rule() plus a little noise.
    """
    path = Path(path or config.SYNTHETIC_DATASET_PATH)
    n_rows = n_rows or config.SYNTHETIC_ROWS
    rng = random.Random(config.RANDOM_SEED)
    rows = []
    for _ in range(n_rows):
        tool = rng.choices(["nmap", "nuclei", "nikto", "lynis"], weights=[20, 35, 20, 25])[0]
        if tool == "nmap":
            sev, cve, misconfig = 0, 0, 0
            category = rng.choices(["ssh", "web", "other"], weights=[30, 35, 35])[0]
        elif tool == "nuclei":
            sev = rng.choices([0, 1, 2, 3, 4], weights=[30, 25, 20, 15, 10])[0]
            category = rng.choices(["web", "tls", "ssh", "other", "none"], weights=[60, 15, 10, 10, 5])[0]
            cve = int(rng.random() < (0.05 if category == "tls" else 0.10 + 0.12 * sev))
            misconfig = int(not cve and rng.random() < 0.5)
        elif tool == "nikto":
            sev = rng.choices([1, 2, 3], weights=[55, 35, 10])[0]
            category = rng.choices(["web", "tls"], weights=[90, 10])[0]
            cve = int(rng.random() < 0.08)
            misconfig = int(not cve and rng.random() < 0.6)
        else:  # lynis
            sev = rng.choices([0, 1, 2], weights=[10, 60, 30])[0]
            category = rng.choices(["ssh", "web", "other", "none"], weights=[25, 10, 15, 50])[0]
            cve = 0
            misconfig = int(sev > 0 and rng.random() < 0.9)
        row = {
            "severity_score": sev, "source_tool": tool, "has_cve": cve, "category": category,
            "is_misconfiguration": misconfig,
        }
        action = action_rule(row)
        if rng.random() < 0.05:      # noise: any action
            action = rng.choice(ML_ACTIONS)
        rows.append({**row, ACTION_COLUMN: action})

    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows, columns=RAW_COLUMNS + [ACTION_COLUMN]).to_csv(path, index=False)
    return path


def load_dataset() -> tuple[pd.DataFrame, pd.Series]:
    """Load the synthetic dataset of the action model.

    Returns:
        (X, y_action): X has FEATURE_COLUMNS (numeric).

    Raises:
        RuntimeError: dataset missing or missing required columns.
    """
    path = Path(config.SYNTHETIC_DATASET_PATH)
    if not path.exists():
        raise RuntimeError(f"Dataset not found at {path}. "
                           "Recreate it with: python -m modules.ml_classifier --regenerate")
    df = pd.read_csv(path)
    missing = [c for c in RAW_COLUMNS + [ACTION_COLUMN] if c not in df.columns]
    if missing:
        raise RuntimeError(f"Dataset is missing columns: {missing}")
    return encode_features(df[RAW_COLUMNS]), df[ACTION_COLUMN]


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
    """Train the action model on the SYNTHETIC dataset, save it, reload it. Returns its metrics."""
    X, y = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.ML_TEST_SIZE, random_state=config.RANDOM_SEED, stratify=y)
    model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=config.RANDOM_SEED)
    model.fit(X_train, y_train)
    metrics = evaluate_predictions(y_test, model.predict(X_test), ML_ACTIONS, len(X_train))
    metrics["training_data"] = f"synthetic findings labelled by our own rule ({len(X)} rows)"

    path = Path(config.ACTION_MODEL_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_columns": FEATURE_COLUMNS,
                 "labels": list(ML_ACTIONS), "metrics": metrics}, path)
    bundle = joblib.load(path)
    if not set(bundle["model"].predict(X_test[bundle["feature_columns"]].head(5))) <= set(ML_ACTIONS):
        raise RuntimeError(f"Reloaded model at {path} predicted unknown labels.")
    return metrics


def train_models() -> dict:
    """Train and save both models. Returns {"priority": metrics, "action": metrics}.

    Raises:
        RuntimeError: NVD index or synthetic dataset missing/invalid, or a
                      saved model fails its reload check.
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
_loaded_models: dict = {}      # {(path, modified time): bundle} - the priority model is large, load it once


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
        table = encode_features([extract_features(f) for f in findings])
        actions = action["model"].predict(table[action["feature_columns"]])
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
    if "--regenerate" in sys.argv:
        print(f"Wrote {generate_synthetic_dataset()}")
    for model_name, model_metrics_ in train_models().items():
        print(format_metrics(model_name, model_metrics_))
        print()
    print(f"Models saved in {config.MODELS_DIR}")
    print("NOTE: the priority score is measured on real NVD CVEs the model did not see. It says how well")
    print("      the model rates CVE descriptions - not how well it rates other kinds of findings.")
    print("      The action score is measured on synthetic data and only shows the model learned our rule.")
