"""
modules/ml_classifier.py - two small scikit-learn models that ADVISE on findings.

    priority model -> ml_priority  (LOW / MEDIUM / HIGH / CRITICAL)
    action model   -> ml_action    (REVIEW_SERVICE, PATCH_OR_UPDATE, HARDEN_SSH, ...)

WHAT THE MODELS DO (and do not do)
    The scanners find the issues. The models only suggest how urgent a finding
    is and which kind of action fits. They are trained on SYNTHETIC data whose
    labels come from rules we wrote ourselves (below), so their accuracy says
    NOTHING about real-world performance. An ML action is a label for a human
    to read - it is never executed.

FEATURES (simple on purpose, one row per finding)
    severity_score        0-4   Info=0 ... Critical=4 (normalized severity)
    source_tool           nmap / nuclei / nikto / lynis          (one-hot encoded)
    has_cve               0/1   the tool reported a CVE id
    category              ssh / web / tls / other / none          (one-hot encoded)
    is_misconfiguration   0/1   a configuration weakness rather than a software flaw
    internet_facing       0/1   asset property, from config.ASSET_INTERNET_FACING
    asset_criticality     1-3   asset property, from config.ASSET_CRITICALITY

LABEL RULES used to build the synthetic dataset
    Priority:  points = 2*severity_score + 2*has_cve + 2*internet_facing
                        + (asset_criticality - 1)
                        + 1 if (is_misconfiguration and severity_score >= 2)
               CRITICAL if points >= 10, HIGH if >= 7, MEDIUM if >= 4, else LOW
               then 8 % of rows are moved one level up or down (noise).
    Action (first matching rule wins):
               has_cve                               -> PATCH_OR_UPDATE
               category tls                          -> REVIEW_TLS
               source_tool nmap                      -> REVIEW_SERVICE
               category ssh and (misconfig or sev>0) -> HARDEN_SSH
               category web and misconfig            -> HARDEN_WEB_SERVER
               severity_score == 0                   -> NO_ACTION_INFORMATIONAL
               otherwise                             -> INVESTIGATE_FINDING
               then 5 % of rows get a random action (noise).

Command line:
    python -m modules.ml_classifier                train both models from the CSV
    python -m modules.ml_classifier --regenerate   rebuild the CSV first, then train
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

import config
from schemas import ML_ACTIONS, ML_PRIORITIES, SEVERITY_SCORES, TOOLS

CATEGORIES: tuple[str, ...] = ("ssh", "web", "tls", "other", "none")

# Readable columns stored in the CSV ...
RAW_COLUMNS: list[str] = ["severity_score", "source_tool", "has_cve", "category",
                          "is_misconfiguration", "internet_facing", "asset_criticality"]
# ... and the numeric columns the models actually see (fixed order, saved with the model).
FEATURE_COLUMNS: list[str] = (
    ["severity_score", "has_cve", "is_misconfiguration", "internet_facing", "asset_criticality"]
    + [f"tool_{t}" for t in TOOLS] + [f"cat_{c}" for c in CATEGORIES]
)
PRIORITY_COLUMN, ACTION_COLUMN = "priority", "action"

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
        "internet_facing": int(config.ASSET_INTERNET_FACING),
        "asset_criticality": int(config.ASSET_CRITICALITY),
    }


def encode_features(rows: list[dict] | pd.DataFrame) -> pd.DataFrame:
    """One-hot encode readable feature rows into the numeric FEATURE_COLUMNS table."""
    raw = pd.DataFrame(rows, columns=RAW_COLUMNS)
    encoded = raw[["severity_score", "has_cve", "is_misconfiguration",
                   "internet_facing", "asset_criticality"]].astype(int)
    for tool in TOOLS:
        encoded[f"tool_{tool}"] = (raw["source_tool"] == tool).astype(int)
    for category in CATEGORIES:
        encoded[f"cat_{category}"] = (raw["category"] == category).astype(int)
    return encoded[FEATURE_COLUMNS]


# ---------------------------------------------------------------- label rules
def priority_rule(row: dict) -> str:
    """The documented priority rule (before noise). See module docstring."""
    points = (2 * row["severity_score"] + 2 * row["has_cve"] + 2 * row["internet_facing"]
              + (row["asset_criticality"] - 1)
              + (1 if row["is_misconfiguration"] and row["severity_score"] >= 2 else 0))
    if points >= 10:
        return "CRITICAL"
    if points >= 7:
        return "HIGH"
    if points >= 4:
        return "MEDIUM"
    return "LOW"


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
    """Create the reproducible synthetic dataset (fixed seed config.RANDOM_SEED).

    Each row imitates a finding one of the four tools could plausibly produce
    (e.g. Nmap rows are always Info without a CVE). Labels come from
    priority_rule() / action_rule() plus a little noise.
    """
    path = Path(path or config.SYNTHETIC_DATASET_PATH)
    n_rows = n_rows or config.SYNTHETIC_ROWS
    rng = random.Random(config.RANDOM_SEED)
    low_to_high = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
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
            "internet_facing": int(rng.random() < 0.3),
            "asset_criticality": rng.choices([1, 2, 3], weights=[25, 50, 25])[0],
        }
        priority, action = priority_rule(row), action_rule(row)
        if rng.random() < 0.08:      # noise: one level up or down
            index = low_to_high.index(priority) + rng.choice([-1, 1])
            priority = low_to_high[min(max(index, 0), 3)]
        if rng.random() < 0.05:      # noise: any action
            action = rng.choice(ML_ACTIONS)
        rows.append({**row, PRIORITY_COLUMN: priority, ACTION_COLUMN: action})

    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows, columns=RAW_COLUMNS + [PRIORITY_COLUMN, ACTION_COLUMN]).to_csv(path, index=False)
    return path


def load_dataset() -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Load the synthetic dataset.

    Returns:
        (X, y_priority, y_action): X has FEATURE_COLUMNS (numeric).

    Raises:
        RuntimeError: dataset missing or missing required columns.
    """
    path = Path(config.SYNTHETIC_DATASET_PATH)
    if not path.exists():
        raise RuntimeError(f"Dataset not found at {path}. "
                           "Recreate it with: python -m modules.ml_classifier --regenerate")
    df = pd.read_csv(path)
    missing = [c for c in RAW_COLUMNS + [PRIORITY_COLUMN, ACTION_COLUMN] if c not in df.columns]
    if missing:
        raise RuntimeError(f"Dataset is missing columns: {missing}")
    return encode_features(df[RAW_COLUMNS]), df[PRIORITY_COLUMN], df[ACTION_COLUMN]


# ---------------------------------------------------------------- training
def _train_one(X: pd.DataFrame, y: pd.Series, labels: tuple[str, ...], model_path: Path) -> dict:
    """Train, evaluate, save and reload one RandomForest. Returns its metrics."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=config.ML_TEST_SIZE, random_state=config.RANDOM_SEED, stratify=y)
    model = RandomForestClassifier(n_estimators=100, max_depth=8, random_state=config.RANDOM_SEED)
    model.fit(X_train, y_train)

    predicted = model.predict(X_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, predicted, labels=list(labels), average="macro", zero_division=0)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, predicted)), 4),
        "precision_macro": round(float(precision), 4),
        "recall_macro": round(float(recall), 4),
        "f1_macro": round(float(f1), 4),
        "labels": list(labels),
        "confusion_matrix": confusion_matrix(y_test, predicted, labels=list(labels)).tolist(),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
    }

    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_columns": FEATURE_COLUMNS,
                 "labels": list(labels), "metrics": metrics}, model_path)

    # Reload from disk and check the saved model really predicts valid labels.
    bundle = joblib.load(model_path)
    check = bundle["model"].predict(X_test[bundle["feature_columns"]].head(5))
    if not set(check) <= set(labels):
        raise RuntimeError(f"Reloaded model at {model_path} predicted unknown labels: {set(check)}")
    return metrics


def train_models() -> dict:
    """Train and save both models. Returns {"priority": metrics, "action": metrics}.

    Raises:
        RuntimeError: dataset missing/invalid or a saved model fails its reload check.
    """
    X, y_priority, y_action = load_dataset()
    return {
        "priority": _train_one(X, y_priority, ML_PRIORITIES, config.PRIORITY_MODEL_PATH),
        "action": _train_one(X, y_action, ML_ACTIONS, config.ACTION_MODEL_PATH),
    }


def format_metrics(name: str, metrics: dict) -> str:
    """Readable text block: accuracy, macro precision/recall/F1 and the confusion matrix."""
    labels = metrics["labels"]
    width = max(len(label) for label in labels) + 2
    lines = [
        f"=== {name} model ({metrics['train_rows']} train rows / {metrics['test_rows']} test rows) ===",
        f"accuracy        {metrics['accuracy']:.3f}",
        f"macro precision {metrics['precision_macro']:.3f}",
        f"macro recall    {metrics['recall_macro']:.3f}",
        f"macro F1        {metrics['f1_macro']:.3f}",
        "confusion matrix (rows = true label, columns = predicted label, same order):",
    ]
    for label, row in zip(labels, metrics["confusion_matrix"]):
        lines.append(f"  {label:<{width}}" + " ".join(f"{count:>4}" for count in row))
    return "\n".join(lines)


# ---------------------------------------------------------------- runtime
def load_model(path: str | Path) -> dict:
    """Load one saved model bundle. Raises RuntimeError if missing or unreadable."""
    path = Path(path)
    if not path.exists():
        raise RuntimeError(f"Model file {path.name} is missing. Train it with: python -m modules.ml_classifier")
    try:
        bundle = joblib.load(path)
        bundle["model"], bundle["feature_columns"], bundle["labels"]
    except Exception as exc:  # corrupt file, wrong library version, wrong content
        raise RuntimeError(f"Model file {path.name} could not be loaded: {exc}") from exc
    return bundle


def classify_findings(findings: list[dict]) -> tuple[list[dict], dict]:
    """Fill in ml_priority and ml_action for each finding.

    Returns:
        (findings, status). `findings` are copies; only ml_priority / ml_action
        are filled in. status = {"status": "SUCCESS" | "FAILED" | "SKIPPED", "error": str}.

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
        priorities = priority["model"].predict(table[priority["feature_columns"]])
        actions = action["model"].predict(table[action["feature_columns"]])
        if not set(priorities) <= set(ML_PRIORITIES) or not set(actions) <= set(ML_ACTIONS):
            raise RuntimeError("A model predicted a label outside the agreed label sets.")
    except Exception as exc:
        return findings, {"status": "FAILED", "error": f"ML unavailable: {exc}"}
    classified = [{**f, "ml_priority": str(p), "ml_action": str(a)}
                  for f, p, a in zip(findings, priorities, actions)]
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
    print("NOTE: these scores are measured on SYNTHETIC data labelled by our own rules.")
    print("      They say nothing about real-world performance.")
