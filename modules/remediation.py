"""
modules/remediation.py - recommendations for every finding, and ONE guarded automatic fix.

RECOMMENDATIONS (recommend_fix / add_recommendations)
    Human-readable advice chosen from the finding's own evidence first, then
    from the ML action category, then from the severity. The advice text is
    kept separate from the ML label, and it is only ever TEXT.

THE ONE AUTOMATIC FIX (apply_fix): disable SSH root login on the lab VM
    apply_fix() does nothing unless every step passes, in this order:
        1. finding is real, from an authorized target, and `sudo sshd -T` on
           the VM shows the effective value "permitrootlogin yes"
        2. confirmed=True (explicit dashboard approval) AND config.ALLOW_AUTO_REMEDIATION
        3. a non-root key-based SSH session works before any change
        4. sshd_config really includes sshd_config.d/*.conf before any
           PermitRootLogin line; back up an existing drop-in; write the drop-in
        5. `sudo sshd -t` validates the configuration (failure -> restore, no reload)
        6. reload the SSH service that is actually running (ssh or sshd)
        7. verify `sshd -T` now says "permitrootlogin no" and a fresh non-root
           SSH connection still works
        8. return {finding_id, applied, verified, backup_path, steps, message}
    Any failed step stops the process and is reported honestly.

    Why a drop-in file works: OpenSSH uses the FIRST value it reads for a
    setting, and Ubuntu's sshd_config includes sshd_config.d/*.conf at the top,
    so a file named 00-... is read before everything else.

SAFETY
    * Every remote command below is a constant. Nothing from a finding (scanner
      output is untrusted) is ever placed in a command.
    * No other setting is ever changed. An ML action label is never a command.
    * simulate=True walks the same steps without connecting to or changing anything.
"""

from __future__ import annotations

from datetime import datetime

import config
from modules import tool_utils

DROPIN_PATH = "/etc/ssh/sshd_config.d/00-coe444-permitrootlogin.conf"
DROPIN_CONTENT = "PermitRootLogin no"
BACKUP_DIR = "coe444-backups"            # inside the SSH user's home directory on the VM

# ---- remote commands (constants; the backup name only adds a local timestamp of digits)
CMD_CONNECT_TEST = "echo coe444-ok && id -u"
CMD_EFFECTIVE_CONFIG = "sudo -n sshd -T"
CMD_READ_SSHD_CONFIG = "cat /etc/ssh/sshd_config"
CMD_DROPIN_EXISTS = f"test -e {DROPIN_PATH} && echo present || echo absent"
CMD_WRITE_DROPIN = f"printf '%s\\n' '{DROPIN_CONTENT}' | sudo -n tee {DROPIN_PATH} > /dev/null"
CMD_REMOVE_DROPIN = f"sudo -n rm -f {DROPIN_PATH}"
CMD_VALIDATE = "sudo -n sshd -t"
CMD_ACTIVE_SERVICES = "systemctl is-active ssh sshd"
CMD_RELOAD = "sudo -n systemctl reload {service}"   # service is "ssh" or "sshd" only


# ====================================================================== recommendations
# (keywords to look for in the finding text, advice). First match wins. All lowercase.
RECOMMENDATION_RULES: list[tuple[tuple[str, ...], str]] = [
    (("permitrootlogin", "root login"),
     "Disable direct root login over SSH: set 'PermitRootLogin no', check the configuration with "
     "'sshd -t' and reload the SSH service. Administrators should log in as a normal user and use sudo."),
    (("maxauthtries",),
     "Lower 'MaxAuthTries' in the SSH server configuration (e.g. 3) to slow down password guessing."),
    (("cve-2021-41773", "path traversal"),
     "Upgrade Apache HTTP Server to 2.4.51 or later and make sure directories outside the "
     "web root are protected with 'Require all denied'."),
    (("outdated",),
     "Update the software to the current supported version using the system package manager."),
    (("vulnerable packages",),
     "Install pending security updates (sudo apt update && sudo apt upgrade) and reboot if required."),
    (("iptables", "firewall"),
     "Enable the host firewall (e.g. ufw) and allow only the services that are needed."),
    (("pam module", "password strength"),
     "Install and configure a password-quality module (e.g. libpam-pwquality) and set a minimum length."),
    (("directory indexing", "directory listing"),
     "Disable directory listing on the web server (Apache: 'Options -Indexes'; nginx: 'autoindex off')."),
    (("default file",),
     "Remove default and sample files that ship with the web server."),
    (("x-frame-options", "content-security-policy", "security headers", "header is not present"),
     "Add the missing HTTP security headers (Content-Security-Policy, X-Frame-Options, "
     "X-Content-Type-Options) in the web server configuration."),
    (("self-signed", "self signed", "certificate"),
     "Replace the certificate with one issued by a trusted certificate authority."),
    (("mod_evasive",),
     "Consider rate limiting on the web server (e.g. Apache mod_evasive) to reduce brute-force and DoS risk."),
    (("hardening index",),
     "Work through the Lynis warnings first, then the suggestions, and re-run the audit to compare the score."),
    (("open port",),
     "Confirm this service is needed. If not, stop it or block the port in the firewall; "
     "if it is, keep it patched and restrict who can reach it."),
]

# Fallback advice per ML action category (used when no evidence rule matches).
ACTION_ADVICE: dict[str, str] = {
    "REVIEW_SERVICE": "Review whether this exposed service is needed; close or firewall it if not.",
    "PATCH_OR_UPDATE": "Apply the vendor's security update for the affected software and re-scan.",
    "HARDEN_SSH": "Review the SSH server configuration against a hardening guide (keys only, no root login).",
    "HARDEN_WEB_SERVER": "Harden the web server configuration (security headers, no directory listing, no default files).",
    "REVIEW_TLS": "Review the TLS setup: trusted certificate, modern protocol versions and strong ciphers.",
    "INVESTIGATE_FINDING": "Investigate this finding manually to confirm whether it is a real risk on this host.",
    "NO_ACTION_INFORMATIONAL": "No action required; review to confirm this is expected.",
}

SEVERITY_ADVICE: dict[str, str] = {
    "Critical": "Fix immediately: apply the vendor patch or take the service offline until patched.",
    "High": "Fix as soon as possible: apply the latest security update and restrict access.",
    "Medium": "Plan a fix soon: review the configuration and apply the vendor's hardening guidance.",
    "Low": "Fix when convenient: review the setting and harden it if it is not needed.",
    "Info": "No action required; review to confirm this is expected.",
}


def _finding_text(finding: dict) -> str:
    return " ".join(str(finding.get(k, "")) for k in ("title", "description", "evidence")).lower()


def is_root_login_finding(finding: dict) -> bool:
    """True if the finding's own evidence says SSH root login is permitted.

    Matches the Lynis SSH-7408 detail "PermitRootLogin (set YES to NO)" and
    plain wording such as "root login is allowed". This only marks a CANDIDATE:
    apply_fix() still checks the VM's effective configuration itself.
    """
    if not isinstance(finding, dict):
        return False
    text = _finding_text(finding)
    if "permitrootlogin" in text:
        return "set yes to" in text or "permitrootlogin yes" in text
    return "root login" in text and any(w in text for w in ("allowed", "permitted", "enabled"))


def recommend_fix(finding: dict) -> str:
    """Return human-readable advice for one finding. Never executes anything, never raises.

    Order: evidence keyword rule -> ML action advice -> severity advice.
    """
    if not isinstance(finding, dict):
        return SEVERITY_ADVICE["Info"]
    text = _finding_text(finding)
    for keywords, advice in RECOMMENDATION_RULES:
        if any(keyword in text for keyword in keywords):
            return advice
    if finding.get("ml_action") in ACTION_ADVICE:
        return ACTION_ADVICE[finding["ml_action"]]
    return SEVERITY_ADVICE.get(str(finding.get("severity", "Info")), SEVERITY_ADVICE["Info"])


def add_recommendations(findings: list[dict]) -> list[dict]:
    """Return copies of `findings` with recommendation and remediation_supported filled in.

    remediation_supported is True ONLY for the SSH root-login finding.
    """
    return [{**f,
             "recommendation": f.get("recommendation") or recommend_fix(f),
             "remediation_supported": is_root_login_finding(f)}
            for f in findings]


# ====================================================================== the one automatic fix
def parse_permit_root_login(sshd_t_output: str) -> str:
    """Return the effective PermitRootLogin value from `sshd -T` output ("" if absent)."""
    for line in (sshd_t_output or "").splitlines():
        parts = line.strip().lower().split()
        if len(parts) >= 2 and parts[0] == "permitrootlogin":
            return parts[1]
    return ""


def include_precedes_permit_root_login(sshd_config_text: str) -> bool:
    """True if sshd_config has an active Include of sshd_config.d/*.conf placed
    BEFORE any active PermitRootLogin line (first value read wins)."""
    for line in (sshd_config_text or "").splitlines():
        words = line.strip().split()
        if not words or words[0].startswith("#"):
            continue
        keyword = words[0].lower()
        if keyword == "include" and any("sshd_config.d/" in w and w.endswith(".conf") for w in words[1:]):
            return True
        if keyword == "permitrootlogin":
            return False
    return False


def apply_fix(finding: dict, confirmed: bool = False, simulate: bool = False) -> dict:
    """Disable SSH root login on the VM - only if every guard passes (see module docstring).

    Args:
        finding: the root-login finding (must have remediation_supported evidence).
        confirmed: True only when the user explicitly approved in the dashboard.
        simulate: True -> walk the same steps WITHOUT connecting or changing anything.

    Returns:
        {"finding_id", "applied", "verified", "backup_path", "steps", "message", "simulated"}
        steps = [{"step": int, "name": str, "ok": bool, "detail": str}, ...]
        applied  = the drop-in was written, validated and the service reloaded.
        verified = afterwards `sshd -T` showed "no" and a new SSH login worked.
        Never raises.
    """
    outcome = {"finding_id": str(finding.get("id", "")) if isinstance(finding, dict) else "",
               "applied": False, "verified": False, "backup_path": "",
               "steps": [], "message": "", "simulated": bool(simulate)}

    def step(number: int, name: str, ok: bool, detail: str) -> bool:
        outcome["steps"].append({"step": number, "name": name, "ok": ok, "detail": detail})
        return ok

    def stop(message: str) -> dict:
        outcome["message"] = message
        return outcome

    # ---------------------------------------------------------------- local guards (no connection)
    if not isinstance(finding, dict) or not is_root_login_finding(finding):
        step(1, "Check finding evidence", False, "The finding does not show that SSH root login is permitted.")
        return stop("Stopped: this finding is not the SSH root-login finding. Nothing was changed.")
    host = str(finding.get("target", "")).strip()
    reason = tool_utils.check_target(host)
    if reason:
        step(1, "Check target authorization", False, reason)
        return stop("Stopped: the finding's target is not authorized. Nothing was changed.")

    if simulate:
        return _simulate(outcome, step, host)

    if finding.get("is_sample"):
        step(1, "Check finding evidence", False, "This is a SAMPLE finding, not evidence from a real scan.")
        return stop("Stopped: sample findings can only be simulated. Nothing was changed.")
    if not config.ALLOW_AUTO_REMEDIATION:
        step(2, "Check approval", False, "config.ALLOW_AUTO_REMEDIATION is False.")
        return stop("Stopped: automatic remediation is switched off in config.py. Nothing was changed.")
    if confirmed is not True:
        step(2, "Check approval", False, "No explicit approval was given.")
        return stop("Stopped: the fix was not approved. Nothing was changed.")

    try:
        return _apply_root_login_fix(outcome, step, stop, host)
    except RuntimeError as exc:           # ssh missing, timeout, SSH not configured ...
        step(0, "Run remote command", False, str(exc))
        if outcome["applied"]:
            return stop(f"The change was applied but a later step failed: {exc} Check the VM manually.")
        return stop(f"Stopped: {exc}")


def _remote(host: str, command: str):
    """Run one constant command on the VM; raise RuntimeError on connection problems."""
    result = tool_utils.run_ssh(host, command)
    problem = tool_utils.ssh_error(result)
    if problem:
        raise RuntimeError(problem)
    return result


def _apply_root_login_fix(outcome: dict, step, stop, host: str) -> dict:
    # ---- 1. evidence: effective configuration on the VM
    effective = parse_permit_root_login(_remote(host, CMD_EFFECTIVE_CONFIG).stdout)
    if not step(1, "Check evidence on the VM (sudo sshd -T)", effective == "yes",
                f"Effective value: permitrootlogin {effective or '(not reported)'}"):
        return stop("Stopped: the VM does not currently permit root login "
                    f"(effective value: {effective or 'unknown'}). Nothing was changed.")

    # ---- 2. approval (already checked by the caller before any connection)
    step(2, "Check approval", True, "Explicit approval given and config.ALLOW_AUTO_REMEDIATION is True.")

    # ---- 3. a non-root key-based session works before any change
    test = _remote(host, CMD_CONNECT_TEST)
    lines = test.stdout.split()
    non_root_ok = test.returncode == 0 and "coe444-ok" in lines and lines[-1:] != ["0"]
    if not step(3, "Check non-root SSH access before the change", non_root_ok,
                f"Logged in as {config.SSH_USER} (uid {lines[-1] if lines else '?'})." if non_root_ok
                else "Could not confirm a working NON-root SSH session."):
        return stop("Stopped: a working non-root SSH session is required first, "
                    "otherwise disabling root login could lock you out. Nothing was changed.")

    # ---- 4. Include line, backup, write the drop-in
    main_config = _remote(host, CMD_READ_SSHD_CONFIG)
    include_ok = main_config.returncode == 0 and include_precedes_permit_root_login(main_config.stdout)
    if not step(4, "Check sshd_config includes sshd_config.d/*.conf first", include_ok,
                "Include line found before any PermitRootLogin line." if include_ok
                else "No active 'Include /etc/ssh/sshd_config.d/*.conf' before PermitRootLogin."):
        return stop("Stopped: sshd_config does not include sshd_config.d/*.conf at the top, "
                    "so a drop-in file would not take effect. Nothing was changed.")

    existed = "present" in _remote(host, CMD_DROPIN_EXISTS).stdout
    if existed:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")              # digits and "-" only
        backup = f"{BACKUP_DIR}/00-coe444-permitrootlogin.conf.{stamp}.bak"
        saved = _remote(host, f"mkdir -p {BACKUP_DIR} && cp -p {DROPIN_PATH} {backup}")
        if not step(4, "Back up existing drop-in file", saved.returncode == 0,
                    f"Saved to ~/{backup}" if saved.returncode == 0
                    else f"Backup failed: {saved.stderr.strip()[:200]}"):
            return stop("Stopped: could not back up the existing drop-in file. Nothing was changed.")
        outcome["backup_path"] = f"~/{backup}"

    written = _remote(host, CMD_WRITE_DROPIN)
    if not step(4, "Write drop-in file", written.returncode == 0,
                f"{DROPIN_PATH} now contains '{DROPIN_CONTENT}'." if written.returncode == 0
                else f"Write failed: {written.stderr.strip()[:200]}"):
        return stop("Stopped: could not write the drop-in file. sshd was not reloaded.")

    def roll_back() -> str:
        """Restore the backup (or remove our file). Returns a description."""
        if outcome["backup_path"]:
            backup_file = outcome["backup_path"][2:]                   # strip "~/"
            undo = _remote(host, f"cat {backup_file} | sudo -n tee {DROPIN_PATH} > /dev/null")
            what = "previous drop-in restored from backup"
        else:
            undo = _remote(host, CMD_REMOVE_DROPIN)
            what = "drop-in removed"
        return what if undo.returncode == 0 else f"ROLLBACK FAILED ({undo.stderr.strip()[:150]})"

    # ---- 5. validate before reloading
    valid = _remote(host, CMD_VALIDATE)
    if not step(5, "Validate configuration (sudo sshd -t)", valid.returncode == 0,
                "Configuration is valid." if valid.returncode == 0
                else f"sshd -t failed: {valid.stderr.strip()[:200]}"):
        undone = roll_back()
        step(5, "Roll back", "FAILED" not in undone, undone)
        return stop(f"Stopped: sshd -t rejected the configuration; {undone}. sshd was NOT reloaded.")

    # ---- 6. reload the service that is actually running
    states = _remote(host, CMD_ACTIVE_SERVICES).stdout.split()
    service = next((name for name, state in zip(("ssh", "sshd"), states) if state == "active"), "")
    reloaded = _remote(host, CMD_RELOAD.format(service=service)) if service else None
    if not step(6, "Reload SSH service", bool(reloaded) and reloaded.returncode == 0,
                f"Reloaded '{service}'." if reloaded is not None and reloaded.returncode == 0
                else ("Neither 'ssh' nor 'sshd' is an active service." if not service
                      else f"Reload of '{service}' failed: {reloaded.stderr.strip()[:200]}")):
        undone = roll_back()
        step(6, "Roll back", "FAILED" not in undone, undone)
        return stop(f"Stopped: the SSH service could not be reloaded; {undone}.")
    outcome["applied"] = True

    # ---- 7. verify
    after = parse_permit_root_login(_remote(host, CMD_EFFECTIVE_CONFIG).stdout)
    value_ok = step(7, "Verify effective value (sudo sshd -T)", after == "no",
                    f"Effective value: permitrootlogin {after or '(not reported)'}")
    fresh = _remote(host, CMD_CONNECT_TEST)
    login_ok = step(7, "Verify a fresh non-root SSH connection", fresh.returncode == 0 and "coe444-ok" in fresh.stdout,
                    "New SSH session works." if fresh.returncode == 0 else "New SSH session FAILED.")
    outcome["verified"] = value_ok and login_ok

    # ---- 8. result
    if outcome["verified"]:
        return stop("SSH root login is now disabled (PermitRootLogin no) and verified.")
    return stop("The change was applied but verification FAILED - see the steps and check the VM manually.")


def _simulate(outcome: dict, step, host: str) -> dict:
    """Describe every step without connecting to the VM or changing anything."""
    planned = [
        (1, "Check evidence on the VM", f"Would run '{CMD_EFFECTIVE_CONFIG}' on {host} and require 'permitrootlogin yes'."),
        (2, "Check approval", "Would require the dashboard approval and config.ALLOW_AUTO_REMEDIATION = True."),
        (3, "Check non-root SSH access before the change", "Would open a key-based SSH session as the non-root user."),
        (4, "Check Include line, back up, write drop-in",
         f"Would confirm sshd_config includes sshd_config.d/*.conf, back up any existing file, "
         f"then write '{DROPIN_CONTENT}' to {DROPIN_PATH}."),
        (5, "Validate configuration", f"Would run '{CMD_VALIDATE}'; on failure restore/remove the drop-in and not reload."),
        (6, "Reload SSH service", "Would reload whichever of 'ssh' / 'sshd' is active."),
        (7, "Verify", "Would require 'permitrootlogin no' from sshd -T and a fresh non-root SSH login."),
    ]
    for number, name, detail in planned:
        step(number, name, True, "SIMULATED - " + detail)
    outcome["message"] = "SIMULATION ONLY: no connection was made and nothing was changed on the VM."
    return outcome
