"""
modules/action_data.py - build the REAL training data for the action model.

The action model (ml_action) learns from the public check libraries of two of
the project's own scanners. Each row is one real check, written by that
tool's maintainers:

    Nuclei   community templates   https://github.com/projectdiscovery/nuclei-templates   (MIT licence)
    Lynis    warning / suggestion  https://github.com/CISOfy/lynis                         (GPLv3)
             messages

The INPUT (check name + description) is real. The LABEL is not written by a
person for this project: it is derived from how the maintainers filed the
check (Nuclei: folder, tags, CVE id; Lynis: the test group), using the rule
in nuclei_action() / lynis_action() below. So the model learns to recognise,
from the text alone, which kind of check produced a finding.

Not used, on purpose:
    Nikto's check database - its licence forbids use outside the Nikto package.
    Nmap's service list    - its licence restricts redistribution.

Command line (needs PyYAML and local clones of the two repositories):
    python -m modules.action_data PATH/TO/nuclei-templates PATH/TO/lynis
    -> data/action_training.csv.gz   (then retrain: python -m modules.ml_classifier)
"""

from __future__ import annotations

import csv
import gzip
import io
import re
import sys
from pathlib import Path

import config
from schemas import ML_ACTIONS

DATASET_COLUMNS: tuple[str, ...] = ("source", "check_id", "category", "tags", "title", "description", "action")
MAX_DESCRIPTION_CHARS = 600

# Template families the app actually runs: web (-u http://...), network services and TLS.
# Cloud, code, file, DAST, OSINT and token checks are never run by this project, so they are left out.
NUCLEI_FOLDERS: tuple[str, ...] = (
    "http/cves", "http/cnvd", "http/vulnerabilities", "http/misconfiguration", "http/exposures",
    "http/exposed-panels", "http/default-logins", "http/technologies", "http/iot", "http/miscellaneous",
    "network", "ssl", "javascript",
)

# Lynis test group (the file include/tests_<group>) -> action. Groups not listed -> INVESTIGATE_FINDING.
LYNIS_GROUP_ACTIONS: dict[str, str] = {
    "ssh": "HARDEN_SSH",
    "webservers": "HARDEN_WEB_SERVER", "php": "HARDEN_WEB_SERVER", "squid": "HARDEN_WEB_SERVER",
    "crypto": "REVIEW_TLS",
    "ports_packages": "PATCH_OR_UPDATE",
    "insecure_services": "REVIEW_SERVICE",
}


# ====================================================================== label rules
def nuclei_action(folder: str, tags: set[str], severity: str, has_cve: bool) -> str:
    """Label rule for one Nuclei template, from its folder and tags (first matching line wins).

    Severity on its own never decides the label: Nuclei also rates real
    problems "info", so it says little about what should be done.
    """
    family, sub = (folder.split("/") + [""])[:2]
    if has_cve:
        return "PATCH_OR_UPDATE"            # a known, published flaw: update the software
    if sub == "c2" or tags & {"c2", "malware", "backdoor", "ransomware", "honeypot"}:
        return "INVESTIGATE_FINDING"        # possible compromise or decoy: a person must look
    if folder == "ssl":
        return "REVIEW_TLS"                 # certificate, protocol and cipher checks
    if "ssh" in tags and (family in ("javascript", "network") or "exposure" in tags) and sub != "detection":
        return "HARDEN_SSH"                 # weak SSH algorithms, password logins, exposed SSH key files
    if sub in ("detection", "enumeration", "exposed-panels", "fortinet") or "panel" in tags:
        return "REVIEW_SERVICE"             # a reachable service or admin page: should it be reachable?
    if folder in ("http/technologies", "network/jarm"):
        return "NO_ACTION_INFORMATIONAL"    # software was identified, nothing is wrong with it
    if folder in ("http/misconfiguration", "http/exposures"):
        return "HARDEN_WEB_SERVER"          # web server settings and files that should not be public
    return "INVESTIGATE_FINDING"            # vulnerabilities without a CVE id, default logins, IoT, ...


def lynis_action(group: str) -> str:
    """Label rule for one Lynis message: decided by the test group the maintainers put it in."""
    return LYNIS_GROUP_ACTIONS.get(group, "INVESTIGATE_FINDING")


# ====================================================================== readers
def read_nuclei(templates_dir: str | Path) -> list[dict]:
    """One row per Nuclei template in NUCLEI_FOLDERS. Unreadable templates are skipped."""
    import yaml                                               # only needed to rebuild the dataset

    root = Path(templates_dir)
    rows = []
    for folder in NUCLEI_FOLDERS:
        for path in sorted((root / folder).rglob("*.yaml")):
            try:
                template = yaml.safe_load(path.read_text(encoding="utf-8"))
                info = template["info"]
                name = " ".join(str(info["name"]).split())
            except Exception:
                continue
            tags = {t.strip().lower() for t in str(info.get("tags") or "").split(",") if t.strip()}
            severity = str(info.get("severity") or "").lower()
            classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
            cve_ids = classification.get("cve-id") or []
            has_cve = bool(cve_ids) or str(template.get("id", "")).upper().startswith("CVE-")
            sub = path.relative_to(root).parts
            category = "/".join(sub[:2]) if len(sub) > 2 else sub[0]
            rows.append({
                "source": "nuclei", "check_id": str(template.get("id", "")), "category": category,
                "tags": ",".join(sorted(tags)), "title": name,
                "description": " ".join(str(info.get("description") or "").split())[:MAX_DESCRIPTION_CHARS],
                "action": nuclei_action(category, tags, severity, has_cve),
            })
    return rows


_REGISTER = re.compile(r"Register --test-no ([A-Z0-9]+-[0-9]+)")
_MESSAGE = re.compile(r'Report(Warning|Suggestion) "\$\{TEST_NO\}" "([^"]+)"')
_VARIABLE = re.compile(r"\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*")


def read_lynis(lynis_dir: str | Path) -> list[dict]:
    """One row per distinct Lynis warning/suggestion message in include/tests_<group>."""
    rows, seen = [], set()
    for path in sorted(Path(lynis_dir, "include").glob("tests_*")):
        group = path.name[len("tests_"):]
        if group.endswith(".template"):
            continue
        test_id = ""
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            registered = _REGISTER.search(line)
            if registered:
                test_id = registered.group(1)
            message = _MESSAGE.search(line)
            if not message:
                continue
            text = " ".join(_VARIABLE.sub(" ", message.group(2)).split()).strip(" :,()")
            if len(text) < 10 or (test_id, text) in seen:
                continue
            seen.add((test_id, text))
            rows.append({
                "source": "lynis", "check_id": test_id, "category": group, "tags": message.group(1).lower(),
                "title": text, "description": "", "action": lynis_action(group),
            })
    return rows


# ====================================================================== dataset file
def build_dataset(nuclei_dir: str | Path, lynis_dir: str | Path, out_path: str | Path | None = None) -> dict:
    """Read both libraries and write the gzip CSV. Returns {action: row count}.

    Raises:
        RuntimeError: a library folder is missing or yields no rows.
    """
    rows = []
    for name, reader, folder in (("Nuclei", read_nuclei, nuclei_dir), ("Lynis", read_lynis, lynis_dir)):
        if not Path(folder).is_dir():
            raise RuntimeError(f"{name} folder not found: {folder}")
        found = reader(folder)
        if not found:
            raise RuntimeError(f"No checks found in the {name} folder {folder}.")
        rows += found
    out_path = Path(out_path or config.ACTION_DATASET_PATH)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=DATASET_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    with open(out_path, "wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as fh:
        fh.write(buffer.getvalue().encode("utf-8"))
    return {action: sum(r["action"] == action for r in rows) for action in ML_ACTIONS}


def load_dataset() -> list[dict]:
    """Load the action training rows. Raises RuntimeError if missing or unreadable."""
    path = Path(config.ACTION_DATASET_PATH)
    if not path.exists():
        raise RuntimeError(f"Action dataset {path.name} not found. "
                           "Rebuild it with: python -m modules.action_data NUCLEI_DIR LYNIS_DIR")
    try:
        with gzip.open(path, "rt", encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
    except (OSError, EOFError, csv.Error) as exc:
        raise RuntimeError(f"Action dataset {path.name} could not be read: {exc}") from exc
    if not rows or set(rows[0]) != set(DATASET_COLUMNS):
        raise RuntimeError(f"Action dataset {path.name} has unexpected columns.")
    return rows


def row_text(title: str, description: str) -> str:
    """The text the action model reads: the same shape for training rows and for findings."""
    return f"{title}. {description}".strip(" .") if description else title


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: python -m modules.action_data PATH/TO/nuclei-templates PATH/TO/lynis")
    counts = build_dataset(sys.argv[1], sys.argv[2])
    print(f"Wrote {config.ACTION_DATASET_PATH}: {sum(counts.values())} checks")
    for action, count in counts.items():
        print(f"  {action:<24}{count:>6}")
    print("Now retrain the action model:  python -m modules.ml_classifier")
