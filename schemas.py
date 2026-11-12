"""
schemas.py - THE shared data contract (version 2) for the whole project.

Two plain-dict shapes are exchanged between modules:

1. FINDING - one security finding. Built with new_finding() / Finding.to_dict().

    Field                  Type        Default   Meaning
    ---------------------  ----------  --------  ------------------------------------------
    id                     str         auto      8-char hex identifier
    target                 str         required  host / IP the finding is about
    source                 str         required  tool name: "nmap", "nuclei", "nikto", "lynis"
    title                  str         required  short name of the finding
    severity               str         "Info"    NORMALIZED severity, one of SEVERITIES
    original_severity      str         ""        the tool's own wording ("" = tool gave none)
    description            str         ""        plain-language explanation
    evidence               str         ""        supporting detail (raw line, URL, ...)
    port                   int | None  None      TCP port, if the tool reported one
    service                str         ""        service name, if the tool reported one
    cve                    str         ""        CVE id(s), only if the tool reported them
    check_id               str         ""        tool's own id (Nuclei template, Lynis test)
    ml_priority            str         ""        "" or one of ML_PRIORITIES (ml_classifier only)
    ml_action              str         ""        "" or one of ML_ACTIONS    (ml_classifier only)
    recommendation         str         ""        human-readable advice (remediation only)
    remediation_supported  bool        False     True only for the SSH root-login finding
    is_sample              bool        False     True = fixture data, not a real scan

   Unknown values stay None / "". Nothing is ever invented.

2. SCAN RESULT - what every scanner returns. Built with new_scan_result().

    {"tool", "status", "findings", "error", "started_at", "finished_at",
     "duration_s", "is_sample"}

   status is one of SCAN_STATUSES. A FAILED scan always carries an error text,
   so it can never be mistaken for a clean scan with zero findings.

Rule: later stages ADD information (ml_priority, ml_action, recommendation,
remediation_supported); they never overwrite what a scanner reported.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field

# ---------------------------------------------------------------- label sets
# Allowed severities, ordered from most to least serious.
SEVERITIES: tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Info")

# Numeric score per severity (used for sorting and as an ML feature).
SEVERITY_SCORES: dict[str, int] = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# ML priority labels (most urgent first), written into Finding.ml_priority.
ML_PRIORITIES: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# ML action categories, written into Finding.ml_action. These are LABELS for a
# human to read. They are never executed and never treated as commands.
ML_ACTIONS: tuple[str, ...] = (
    "REVIEW_SERVICE", "PATCH_OR_UPDATE", "HARDEN_SSH", "HARDEN_WEB_SERVER",
    "REVIEW_TLS", "INVESTIGATE_FINDING", "NO_ACTION_INFORMATIONAL",
)

TOOLS: tuple[str, ...] = ("nmap", "nuclei", "nikto", "lynis")

# Scanner outcome. NOT_APPLICABLE = the tool had nothing to scan (e.g. Nikto
# when no web port was found). SKIPPED = the tool was not run on purpose.
SCAN_STATUSES: tuple[str, ...] = ("SUCCESS", "FAILED", "SKIPPED", "NOT_APPLICABLE")

# Common tool wording -> our severity. Used by normalize_severity().
_SEVERITY_ALIASES: dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "warning": "Medium",      # Lynis warnings
    "low": "Low",
    "suggestion": "Low",      # Lynis suggestions
    "info": "Info",
    "informational": "Info",
    "information": "Info",
    "unknown": "Info",
    "none": "Info",
    "": "Info",
}

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def normalize_severity(value: object) -> str:
    """Map any tool's severity wording to one of SEVERITIES.

    Unrecognised values become "Info" (never raises). The tool's own wording
    should be kept separately in Finding.original_severity.
    """
    text = str(value or "").strip().lower()
    return _SEVERITY_ALIASES.get(text, "Info")


def extract_cve(text: object) -> str:
    """Return the CVE ids that literally appear in `text`, e.g. "CVE-2021-41773".

    Several ids are joined with ", ". Returns "" when the text has none -
    a CVE is only ever copied from tool output, never guessed.
    """
    found: list[str] = []
    for match in _CVE_PATTERN.findall(str(text or "")):
        cve = match.upper()
        if cve not in found:
            found.append(cve)
    return ", ".join(found)


def _new_id() -> str:
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------- finding
@dataclass
class Finding:
    """One security finding in the shared project format. See module docstring."""

    target: str
    source: str
    title: str
    severity: str = "Info"
    original_severity: str = ""
    description: str = ""
    evidence: str = ""
    port: int | None = None
    service: str = ""
    cve: str = ""
    check_id: str = ""
    ml_priority: str = ""
    ml_action: str = ""
    recommendation: str = ""
    remediation_supported: bool = False
    is_sample: bool = False
    id: str = field(default_factory=_new_id)

    def __post_init__(self) -> None:
        # Accept "high"/"HIGH" etc. but reject anything that is not a real severity.
        matched = next((s for s in SEVERITIES if s.lower() == str(self.severity).strip().lower()), None)
        if matched is None:
            raise ValueError(
                f"Invalid severity {self.severity!r}; use one of {SEVERITIES} "
                "(tip: schemas.normalize_severity() converts tool wording)."
            )
        self.severity = matched
        if self.ml_priority not in ("",) + ML_PRIORITIES:
            raise ValueError(f"Invalid ml_priority {self.ml_priority!r}; use '' or one of {ML_PRIORITIES}.")
        if self.ml_action not in ("",) + ML_ACTIONS:
            raise ValueError(f"Invalid ml_action {self.ml_action!r}; use '' or one of {ML_ACTIONS}.")
        for name in ("target", "source", "title"):
            if not str(getattr(self, name) or "").strip():
                raise ValueError(f"Finding.{name} must not be empty.")
        self.port = _clean_port(self.port)
        for name in ("remediation_supported", "is_sample"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"Finding.{name} must be True or False.")
        # Every remaining field is text ("" when unknown).
        for name in TEXT_FIELDS:
            value = getattr(self, name)
            setattr(self, name, "" if value is None else str(value))

    def to_dict(self) -> dict:
        """Return the finding as a plain dict with exactly FINDING_FIELDS as keys."""
        data = asdict(self)
        return {name: data[name] for name in FINDING_FIELDS}


def _clean_port(value: object) -> int | None:
    """Return a valid TCP port as int, or None for unknown. Rejects bad values."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("Finding.port must be an integer 1-65535 or None.")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Finding.port must be an integer 1-65535 or None, got {value!r}.") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"Finding.port must be 1-65535, got {port}.")
    return port


# Canonical field order (use this for CSV columns and tables).
FINDING_FIELDS: tuple[str, ...] = (
    "id", "target", "source", "title", "severity", "original_severity",
    "description", "evidence", "port", "service", "cve", "check_id",
    "ml_priority", "ml_action", "recommendation", "remediation_supported", "is_sample",
)
TEXT_FIELDS: tuple[str, ...] = tuple(
    name for name in FINDING_FIELDS if name not in ("port", "remediation_supported", "is_sample")
)


def new_finding(target: str, source: str, title: str, **optional) -> dict:
    """Build a validated finding dict in one call.

    Example:
        new_finding("10.0.0.5", "nmap", "Open port 22/tcp (ssh)",
                    port=22, service="ssh", evidence="22/tcp open ssh OpenSSH 9.6p1")

    Raises:
        ValueError: a value is invalid or a required field is empty.
        TypeError: an unknown field name is passed.
    """
    return Finding(target=target, source=source, title=title, **optional).to_dict()


def validate_finding(finding: dict) -> dict:
    """Check that a dict follows the shared format and return a cleaned copy.

    Missing optional fields get their defaults; unknown keys are rejected.

    Raises:
        ValueError / TypeError: the dict does not fit the format.
    """
    if not isinstance(finding, dict):
        raise TypeError("A finding must be a dict.")
    unknown = set(finding) - set(FINDING_FIELDS)
    if unknown:
        raise TypeError(f"Unknown finding field(s): {sorted(unknown)}")
    return Finding(**finding).to_dict()


def is_sample(finding: dict) -> bool:
    """True if the finding is fixture data rather than a real scan result."""
    return bool(finding.get("is_sample", False))


def sort_by_severity(findings: list[dict]) -> list[dict]:
    """Return findings sorted Critical -> Info (stable; does not modify the input)."""
    return sorted(findings, key=lambda f: -SEVERITY_SCORES.get(f.get("severity", "Info"), 0))


# ---------------------------------------------------------------- scan result
SCAN_RESULT_FIELDS: tuple[str, ...] = (
    "tool", "status", "findings", "error", "started_at", "finished_at", "duration_s", "is_sample",
)


def new_scan_result(tool: str, status: str, findings: list[dict] | None = None, error: str = "",
                    started_at: str = "", finished_at: str = "", duration_s: float = 0.0,
                    is_sample: bool = False) -> dict:
    """Build a validated ScanResult dict - the ONE return shape of every scanner.

    Raises:
        ValueError: unknown tool/status, a FAILED result without an error text,
                    or findings that do not follow the finding format.
    """
    return validate_scan_result({
        "tool": tool, "status": status, "findings": list(findings or []), "error": error or "",
        "started_at": started_at, "finished_at": finished_at,
        "duration_s": duration_s, "is_sample": is_sample,
    })


def validate_scan_result(result: dict) -> dict:
    """Check a ScanResult dict and return a cleaned copy (findings validated too).

    Raises:
        ValueError / TypeError: the dict does not fit the format.
    """
    if not isinstance(result, dict):
        raise TypeError("A scan result must be a dict.")
    if set(result) != set(SCAN_RESULT_FIELDS):
        raise TypeError(f"A scan result needs exactly these keys: {SCAN_RESULT_FIELDS}")
    if result["tool"] not in TOOLS:
        raise ValueError(f"Unknown tool {result['tool']!r}; use one of {TOOLS}.")
    if result["status"] not in SCAN_STATUSES:
        raise ValueError(f"Unknown status {result['status']!r}; use one of {SCAN_STATUSES}.")
    if not isinstance(result["findings"], list):
        raise TypeError("ScanResult.findings must be a list.")
    error = str(result["error"] or "")
    if result["status"] == "FAILED" and not error.strip():
        raise ValueError("A FAILED scan result must explain what went wrong in 'error'.")
    if not isinstance(result["is_sample"], bool):
        raise ValueError("ScanResult.is_sample must be True or False.")
    return {
        "tool": result["tool"],
        "status": result["status"],
        "findings": [validate_finding(f) for f in result["findings"]],
        "error": error,
        "started_at": str(result["started_at"] or ""),
        "finished_at": str(result["finished_at"] or ""),
        "duration_s": round(float(result["duration_s"] or 0.0), 2),
        "is_sample": result["is_sample"],
    }
