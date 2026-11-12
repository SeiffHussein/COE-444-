"""
modules/tool_utils.py - the ONE safe way to run external programs.

Everything that starts a process goes through run_tool(): argument lists only,
never a shell, always a timeout. Remote commands on the lab VM go through
run_ssh(), which is run_tool() with the system `ssh` binary.

Also here: target checks used before any tool starts.
    validate_target(target)  -> is the text a well-formed target?   (format)
    is_authorized(target)    -> is it in config.AUTHORIZED_TARGETS? (permission)
They are separate checks and BOTH must pass.

Error contract:
    ValueError    -> bad input (e.g. invalid target, args not a list)
    RuntimeError  -> tool missing, failed to start or timed out
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import time
from datetime import datetime

import config
from schemas import new_scan_result

# RFC 1123 hostname label: letters, digits, hyphens; not starting/ending with "-".
_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


# ---------------------------------------------------------------- target checks
def validate_target(target: object) -> bool:
    """FORMAT check: is `target` a safe, well-formed scan target? Never raises.

    Accepted: IPv4/IPv6 address, hostname, or a small CIDR network (no larger
    than /config.MIN_IPV4_PREFIX). Rejected: empty text, spaces, anything
    starting with "-" (could be read as a tool option), shell characters,
    URLs, ports and over-long names.

    A well-formed target is NOT automatically allowed - see is_authorized().
    """
    if not isinstance(target, str):
        return False
    target = target.strip()
    if not target or len(target) > 253 or target.startswith("-"):
        return False

    # IP address or CIDR network
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            limit = config.MIN_IPV4_PREFIX if net.version == 4 else config.MIN_IPV6_PREFIX
            return net.prefixlen >= limit
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Hostname (only letters, digits, hyphens and dots allowed)
    labels = target.rstrip(".").split(".")
    if all(_HOST_LABEL.match(label) for label in labels):
        # Reject things like "999.1.1.1" that look numeric but are not valid IPs.
        return not all(label.isdigit() for label in labels)
    return False


def is_authorized(target: object) -> bool:
    """PERMISSION check: is `target` listed in config.AUTHORIZED_TARGETS?

    Exact match only (after trimming spaces). Never raises.
    """
    if not isinstance(target, str):
        return False
    return target.strip() in [str(t).strip() for t in config.AUTHORIZED_TARGETS if str(t).strip()]


def check_target(target: object) -> str:
    """Run both checks. Returns "" if the target may be scanned, else the reason."""
    if not validate_target(target):
        return f"Invalid target format: {target!r}."
    if not is_authorized(target):
        return (f"Target {str(target).strip()!r} is not in config.AUTHORIZED_TARGETS. "
                "Only authorized lab targets can be scanned.")
    return ""


# ---------------------------------------------------------------- running tools
def tool_available(name: str) -> bool:
    """Return True if the command-line tool `name` is on the PATH."""
    return shutil.which(name) is not None


def run_tool(args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    """Run an external tool safely and return the completed process.

    Args:
        args: argument list, e.g. ["nmap", "-sV", "-oX", "-", "10.0.0.5"].
              NEVER a single command string and NEVER shell=True.
        timeout: seconds before the tool is killed. Defaults to
                 config.TOOL_TIMEOUTS[args[0]], else config.DEFAULT_TIMEOUT.

    Returns:
        subprocess.CompletedProcess with .returncode, .stdout, .stderr (text).
        A non-zero return code is NOT raised - the caller decides what it means.

    Raises:
        ValueError: args is empty or not a list of strings.
        RuntimeError: the tool is not installed, cannot start or timed out.
    """
    if not args or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("run_tool() needs a non-empty list of strings.")
    tool = args[0]
    if not tool_available(tool):
        raise RuntimeError(f"'{tool}' is not installed or not on PATH. See README > External tools.")
    if timeout is None:
        timeout = config.TOOL_TIMEOUTS.get(tool, config.DEFAULT_TIMEOUT)
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"'{tool}' timed out after {timeout} s.") from exc
    except OSError as exc:
        raise RuntimeError(f"Could not run '{tool}': {exc}") from exc


def run_ssh(host: str, remote_command: str, timeout: int | None = None) -> subprocess.CompletedProcess:
    """Run ONE fixed command on the lab VM over SSH (key-based, non-interactive).

    Args:
        host: VM address. Must be an authorized target.
        remote_command: the command for the VM. Callers pass only constant
            strings written in this code base - never text taken from scanner
            output - because the remote shell interprets it.
        timeout: seconds; defaults to config.TOOL_TIMEOUTS["ssh"].

    Returns:
        CompletedProcess. ssh itself exits 255 on connection/authentication
        problems - use ssh_error() to turn the result into a clear message.

    Raises:
        RuntimeError: host not authorized, SSH user not configured, ssh missing
                      or timed out.
    """
    reason = check_target(host)
    if reason:
        raise RuntimeError(f"SSH refused. {reason}")
    if not config.SSH_USER:
        raise RuntimeError("SSH is not configured: set SSH_USER in config.py (or COE444_SSH_USER).")
    args = [
        "ssh",
        "-i", str(config.SSH_KEY_PATH),
        "-o", "BatchMode=yes",                       # never prompt for a password
        "-o", f"ConnectTimeout={config.SSH_CONNECT_TIMEOUT}",
        f"{config.SSH_USER}@{host.strip()}",
        remote_command,
    ]
    return run_tool(args, timeout=timeout or config.TOOL_TIMEOUTS["ssh"])


def ssh_error(result: subprocess.CompletedProcess) -> str:
    """Return "" if the SSH connection itself worked, else a clear error text.

    Only looks at connection-level problems (ssh exit code 255). The remote
    command's own exit code is left for the caller to interpret.
    """
    if result.returncode != 255:
        return ""
    stderr = (result.stderr or "").strip()
    low = stderr.lower()
    if "permission denied" in low:
        return f"SSH authentication failed (check the user and key): {stderr[:200]}"
    if "host key verification failed" in low:
        return "SSH host key verification failed. Connect once manually to accept the VM's key."
    if any(word in low for word in ("timed out", "no route to host", "connection refused",
                                    "could not resolve", "network is unreachable")):
        return f"VM is unreachable over SSH: {stderr[:200]}"
    return f"SSH connection failed: {stderr[:200] or 'exit code 255'}"


# ---------------------------------------------------------------- scan wrapper
def now_text() -> str:
    """Current local time as text, e.g. "2026-05-01T14:03:22"."""
    return datetime.now().isoformat(timespec="seconds")


def timed_scan(tool: str, scan_function, is_sample: bool = False) -> dict:
    """Run `scan_function()` and wrap the outcome in a ScanResult dict.

    scan_function returns a list of findings on success and raises
    RuntimeError / ValueError on any problem. The problem becomes a FAILED
    result with the error text - never an empty "success".
    """
    started_at, start = now_text(), time.monotonic()
    try:
        findings, status, error = scan_function(), "SUCCESS", ""
    except (RuntimeError, ValueError) as exc:
        findings, status, error = [], "FAILED", str(exc) or exc.__class__.__name__
    return new_scan_result(tool, status, findings, error, started_at, now_text(),
                           time.monotonic() - start, is_sample)


def not_run(tool: str, status: str, reason: str = "", is_sample: bool = False) -> dict:
    """ScanResult for a tool that was not started (SKIPPED / NOT_APPLICABLE / FAILED)."""
    now = now_text()
    return new_scan_result(tool, status, [], reason, now, now, 0.0, is_sample)


def load_fixture(filename: str, target: str = "") -> str:
    """Read a sample-mode fixture, replacing the fixture address with `target`."""
    try:
        text = (config.FIXTURES_DIR / filename).read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Sample fixture {filename} is missing: {exc}") from exc
    return text.replace(config.FIXTURE_HOST, target) if target else text


def as_sample(findings: list[dict]) -> list[dict]:
    """Label findings parsed from a fixture as sample data."""
    return [{**f, "is_sample": True,
             "description": ("SAMPLE DATA - not from a real scan. " + f["description"]).strip()}
            for f in findings]
