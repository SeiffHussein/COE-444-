"""
modules/nvd.py - real vulnerability data from the NVD (National Vulnerability Database).

Source: the NVD "JSON 2.0" CVE data feeds, https://nvd.nist.gov/vuln/data-feeds
(public data published by NIST). The feed files are downloaded by hand - this
module never contacts the internet.

1. BUILD AN INDEX   build_index(feed files) -> data/nvd_cves.csv.gz
       One row per CVE: id, published date, CVSS version/score/severity/vector,
       CWE and the English description. Rejected CVEs are left out.
       This table is also the TRAINING DATA of the priority model
       (modules/ml_classifier.py).

2. LOOK UP          enrich_findings(findings)
       For every finding whose scanner reported a CVE id, copy the OFFICIAL
       CVSS score and severity from the index (cvss_score, nvd_severity).
       A CVE that is not in the index gets nothing - a score is never invented.

Command line:
    python -m modules.nvd FEED.json.zip ...     rebuild the index from feed files
    (then retrain the priority model:  python -m modules.ml_classifier)
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import sys
import zipfile
from pathlib import Path

import config
from schemas import CVSS_SEVERITIES

INDEX_COLUMNS: tuple[str, ...] = ("cve_id", "published", "cvss_version", "cvss_score",
                                  "cvss_severity", "cvss_vector", "cwe", "description")
MAX_DESCRIPTION_CHARS = 1000
# Which CVSS rating to use when a CVE has several: v3.1 is the most common today.
_CVSS_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")

_index_cache: dict = {}       # {(path, modified time): {cve_id: row}}


# ====================================================================== 1. build the index
def read_feed(path: str | Path) -> dict:
    """Read one NVD feed file (.json, .json.gz or .zip containing one .json).

    Raises:
        RuntimeError: file missing, unreadable or not an NVD CVE 2.0 feed.
    """
    path = Path(path)
    try:
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                names = [n for n in archive.namelist() if n.endswith(".json")]
                if len(names) != 1:
                    raise RuntimeError(f"{path.name}: expected exactly one .json file inside the zip.")
                text = archive.read(names[0]).decode("utf-8")
        elif path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                text = fh.read()
        else:
            text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"Could not read NVD feed {path.name}: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != "NVD_CVE" or not isinstance(data.get("vulnerabilities"), list):
        raise RuntimeError(f"{path.name} is not an NVD CVE JSON 2.0 feed.")
    return data


def parse_feed(data: dict) -> list[dict]:
    """Turn a loaded feed into index rows (keys = INDEX_COLUMNS). Rejected CVEs are skipped."""
    rows = []
    for item in data["vulnerabilities"]:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or not cve.get("id") or cve.get("vulnStatus") == "Rejected":
            continue
        description = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
        version, score, severity, vector = _pick_cvss(cve.get("metrics") or {})
        cwes = sorted({d.get("value", "") for w in cve.get("weaknesses") or [] for d in w.get("description") or []
                       if str(d.get("value", "")).startswith("CWE-")})
        rows.append({
            "cve_id": str(cve["id"]).upper(),
            "published": str(cve.get("published") or "")[:10],
            "cvss_version": version, "cvss_score": score, "cvss_severity": severity, "cvss_vector": vector,
            "cwe": " ".join(cwes),
            "description": " ".join(str(description).split())[:MAX_DESCRIPTION_CHARS],
        })
    return rows


def _pick_cvss(metrics: dict) -> tuple[str, str, str, str]:
    """Choose one CVSS rating: preferred version first, NVD's own ("Primary") rating first."""
    for key in _CVSS_PREFERENCE:
        entries = [e for e in metrics.get(key) or [] if isinstance(e.get("cvssData"), dict)]
        if not entries:
            continue
        entry = sorted(entries, key=lambda e: e.get("type") != "Primary")[0]
        data = entry["cvssData"]
        severity = str(data.get("baseSeverity") or entry.get("baseSeverity") or "").upper()   # v2 keeps it outside
        if severity in CVSS_SEVERITIES and data.get("baseScore") is not None:
            return str(data.get("version", "")), str(data["baseScore"]), severity, str(data.get("vectorString", ""))
    return "", "", "", ""


def build_index(feed_paths: list[str | Path] | None = None, index_path: str | Path | None = None) -> int:
    """Build the compact CVE index from feed files. Returns the number of CVEs written.

    Args:
        feed_paths: feed files; default = every file in config.NVD_FEEDS_DIR.
                    If a CVE appears in several feeds, the last file wins.
    Raises:
        RuntimeError: no feed files, or a file is not a valid feed.
    """
    if feed_paths is None:
        folder = Path(config.NVD_FEEDS_DIR)
        feed_paths = sorted(p for p in folder.glob("*") if p.suffix in (".json", ".gz", ".zip")) if folder.exists() else []
    if not feed_paths:
        raise RuntimeError(f"No NVD feed files given and none found in {config.NVD_FEEDS_DIR}.")
    by_id: dict[str, dict] = {}
    for path in feed_paths:
        for row in parse_feed(read_feed(path)):
            by_id[row["cve_id"]] = row
    index_path = Path(index_path or config.NVD_INDEX_PATH)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=INDEX_COLUMNS)
    writer.writeheader()
    writer.writerows(by_id[cve_id] for cve_id in sorted(by_id))
    # No file name or time in the gzip header -> the same input always gives the same file.
    with open(index_path, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as fh:
        fh.write(buffer.getvalue().encode("utf-8"))
    return len(by_id)


def load_index() -> dict[str, dict]:
    """Load the CVE index as {cve_id: row}. Raises RuntimeError if missing or unreadable."""
    path = Path(config.NVD_INDEX_PATH)
    if not path.exists():
        raise RuntimeError(f"NVD index {path.name} not found. Build it with: python -m modules.nvd FEED_FILE")
    key = (str(path), path.stat().st_mtime)
    if key not in _index_cache:
        try:
            with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
            if rows and set(rows[0]) != set(INDEX_COLUMNS):
                raise ValueError("unexpected columns")
        except (OSError, EOFError, ValueError, csv.Error) as exc:
            raise RuntimeError(f"NVD index {path.name} could not be read: {exc}") from exc
        _index_cache.clear()
        _index_cache[key] = {row["cve_id"]: row for row in rows}
    return _index_cache[key]


# ====================================================================== 2. look up
def enrich_findings(findings: list[dict]) -> tuple[list[dict], dict]:
    """Add official NVD values to findings that carry a CVE id. Never raises.

    Returns:
        (findings, status). `findings` are copies; only cvss_score and
        nvd_severity may be filled in, and only for findings with a CVE.
        status = {"status": "SUCCESS" | "FAILED" | "SKIPPED", "error": str,
                  "cve_findings": int, "matched": int}
        Index missing or unreadable -> FAILED, findings unchanged.
    """
    findings = [dict(f) for f in findings]
    with_cve = [f for f in findings if str(f.get("cve", "")).strip()]
    status = {"status": "SKIPPED", "error": "", "cve_findings": len(with_cve), "matched": 0}
    if not with_cve:
        status["error"] = "No finding carries a CVE id."
        return findings, status
    try:
        index = load_index()
    except RuntimeError as exc:
        status.update(status="FAILED", error=f"NVD lookup unavailable: {exc}")
        return findings, status
    for finding in with_cve:
        rated = [index[c] for c in _cve_ids(finding) if c in index and index[c]["cvss_severity"]]
        if rated:                                       # several CVEs on one finding -> the highest score
            worst = max(rated, key=lambda row: float(row["cvss_score"]))
            finding["cvss_score"], finding["nvd_severity"] = float(worst["cvss_score"]), worst["cvss_severity"]
            status["matched"] += 1
    status["status"] = "SUCCESS"
    return findings, status


def _cve_ids(finding: dict) -> list[str]:
    return [c.strip().upper() for c in str(finding.get("cve", "")).split(",") if c.strip()]


if __name__ == "__main__":
    if not sys.argv[1:]:
        raise SystemExit("Usage: python -m modules.nvd FEED_FILE [FEED_FILE ...]")
    print(f"Index built: {build_index(list(sys.argv[1:]))} CVEs -> {config.NVD_INDEX_PATH}")
    print("Now retrain the priority model on it:  python -m modules.ml_classifier")
