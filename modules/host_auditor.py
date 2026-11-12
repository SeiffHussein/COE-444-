"""
modules/host_auditor.py - Lynis host audit, run REMOTELY on the lab VM over SSH.

Lynis audits the machine it runs on, so it must run on the VM itself. We use
the system `ssh` binary (tool_utils.run_ssh: key-based, BatchMode, timeouts) to

    1. run   sudo -n lynis audit system --quick --no-colors
    2. read  sudo -n cat /var/log/lynis-report.dat

and parse the report file locally. Both remote commands are constants. The
audit only READS the VM; nothing here changes any setting.

Report lines we use:
    warning[]=TEST-ID|text|details|solution|      -> severity Medium
    suggestion[]=TEST-ID|text|details|solution|   -> severity Low
    hardening_index=NN                            -> one separate Info finding
Every other line is plain informational output and is ignored.
"""

from __future__ import annotations

import config
from modules import tool_utils
from schemas import new_finding, normalize_severity

LYNIS_AUDIT_COMMAND = "sudo -n lynis audit system --quick --no-colors"
LYNIS_REPORT_COMMAND = "sudo -n cat /var/log/lynis-report.dat"


def audit_host(target: str, sample_mode: bool = False) -> dict:
    """Audit the VM at `target` with Lynis over SSH.

    Returns:
        ScanResult dict. FAILED with a clear error for: target not allowed,
        SSH not configured, authentication failure, unreachable host, timeout,
        sudo needing a password, Lynis not installed, unreadable or malformed
        report. Never raises.
    """
    target = target.strip() if isinstance(target, str) else target
    reason = tool_utils.check_target(target)
    if reason:
        return tool_utils.not_run("lynis", "FAILED", reason, sample_mode)

    if sample_mode:
        return tool_utils.timed_scan(
            "lynis",
            lambda: tool_utils.as_sample(
                _parse_lynis_report(tool_utils.load_fixture("lynis_report.dat"), target)),
            is_sample=True)
    return tool_utils.timed_scan("lynis", lambda: _run_lynis(target))


def _run_lynis(target: str) -> list[dict]:
    """Run Lynis on the VM and return findings. Raises RuntimeError on any problem."""
    audit = tool_utils.run_ssh(target, LYNIS_AUDIT_COMMAND, timeout=config.TOOL_TIMEOUTS["lynis"])
    _raise_on_remote_problem(audit, "run Lynis")

    report = tool_utils.run_ssh(target, LYNIS_REPORT_COMMAND)
    _raise_on_remote_problem(report, "read the Lynis report")
    if report.returncode != 0:
        raise RuntimeError("Could not read /var/log/lynis-report.dat on the VM "
                           f"(exit {report.returncode}): {(report.stderr or '').strip()[:200]}")
    return _parse_lynis_report(report.stdout, target)


def _raise_on_remote_problem(result, action: str) -> None:
    """Turn SSH / sudo / missing-tool problems into a clear RuntimeError."""
    connection_error = tool_utils.ssh_error(result)
    if connection_error:
        raise RuntimeError(f"Could not {action}. {connection_error}")
    stderr = (result.stderr or "").strip()
    low = stderr.lower()
    if "sudo:" in low and "password" in low:
        raise RuntimeError(f"Could not {action}: sudo asked for a password. "
                           "Add the passwordless sudoers rule from README > VM preparation.")
    if result.returncode == 127 or "command not found" in low:
        raise RuntimeError(f"Could not {action}: Lynis is not installed on the VM "
                           "(sudo apt install lynis).")
    if "sudo:" in low and result.returncode != 0:
        raise RuntimeError(f"Could not {action}: {stderr[:200]}")


def _parse_lynis_report(report_text: str, target: str) -> list[dict]:
    """Convert the Lynis report file (key=value lines) into findings.

    Raises:
        RuntimeError: the text is not a Lynis report (no lynis_version /
                      report_version line), so a broken read is never
                      reported as "no findings".
    """
    lines = [line.strip() for line in (report_text or "").splitlines()]
    lines = [line for line in lines if line and not line.startswith("#") and "=" in line]
    keys = {line.split("=", 1)[0] for line in lines}
    if not keys & {"lynis_version", "report_version_major"}:
        raise RuntimeError("Lynis report is malformed or empty (no lynis_version line found).")

    findings: list[dict] = []
    for line in lines:
        key, value = line.split("=", 1)
        if key in ("warning[]", "suggestion[]"):
            kind = key[:-2]                                     # "warning" / "suggestion"
            parts = [p.strip() for p in value.split("|")]
            test_id = parts[0] if parts else ""
            text = parts[1] if len(parts) > 1 else ""
            details = parts[2] if len(parts) > 2 and parts[2] not in ("", "-") else ""
            if not text:
                continue
            findings.append(new_finding(
                target, "lynis", (f"{text}: {details}" if details else text)[:200],
                severity=normalize_severity(kind),
                original_severity=kind,
                description=f"Lynis {kind} from test {test_id}." if test_id else f"Lynis {kind}.",
                evidence=line,
                service="ssh" if test_id.startswith("SSH-") else "",
                check_id=test_id,
            ))
        elif key == "hardening_index" and value.strip():
            # Plain informational output, kept apart from warnings/suggestions.
            findings.append(new_finding(
                target, "lynis", f"Lynis hardening index: {value.strip()}/100",
                severity="Info", original_severity="info",
                description="Overall Lynis hardening score for the host (higher is better).",
                evidence=line,
            ))
    return findings
