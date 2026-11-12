"""
modules/target_scanner.py - Nmap network discovery.

scan_target() returns a ScanResult (see schemas.py) with one finding per OPEN
port, e.g.

    title    "Open port 22/tcp (ssh)"      severity "Info"
    port     22                            service  "ssh"
    evidence "22/tcp open ssh OpenSSH 9.6p1 Ubuntu 3ubuntu13"

An open port is DISCOVERY information, not a vulnerability, so the severity is
always "Info". Nmap has no severity of its own, so original_severity stays "".
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import config
from modules import tool_utils
from modules.tool_utils import validate_target  # noqa: F401  (re-exported for callers)
from schemas import new_finding


def scan_target(target: str, sample_mode: bool = False) -> dict:
    """Discover open ports and service versions with Nmap.

    Args:
        target: an authorized IP / hostname.
        sample_mode: True -> parse the labelled fixture instead of running Nmap.

    Returns:
        ScanResult dict. FAILED (with an error text) when the target is not
        allowed, Nmap is missing, times out, exits non-zero, returns malformed
        XML or the host does not answer. Never raises.
    """
    target = target.strip() if isinstance(target, str) else target
    reason = tool_utils.check_target(target)
    if reason:
        return tool_utils.not_run("nmap", "FAILED", reason, sample_mode)

    if sample_mode:
        return tool_utils.timed_scan(
            "nmap",
            lambda: tool_utils.as_sample(_parse_nmap_xml(tool_utils.load_fixture("nmap_scan.xml", target), target)),
            is_sample=True)
    return tool_utils.timed_scan("nmap", lambda: _run_nmap(target))


def _run_nmap(target: str) -> list[dict]:
    """Run Nmap and return findings. Raises RuntimeError on any problem."""
    args = [
        "nmap",
        "-sT",                                  # TCP connect scan: needs no root/admin
        "-sV",                                  # service and version detection
        "--top-ports", str(config.NMAP_TOP_PORTS),
        "-oX", "-",                             # XML report on stdout
        target,
    ]
    result = tool_utils.run_tool(args)
    if result.returncode != 0:
        raise RuntimeError(f"Nmap failed (exit {result.returncode}): {(result.stderr or '').strip()[:300]}")
    return _parse_nmap_xml(result.stdout, target)


def _parse_nmap_xml(xml_text: str, target: str) -> list[dict]:
    """Convert Nmap XML (-oX -) into one finding per open port.

    Raises:
        RuntimeError: the XML is malformed, or no host answered (so an
                      unreachable host is never reported as "nothing found").
    """
    try:
        root = ET.fromstring(xml_text or "")
    except ET.ParseError as exc:
        raise RuntimeError(f"Could not parse Nmap XML output: {exc}") from exc
    if root.tag != "nmaprun":
        raise RuntimeError("Could not parse Nmap XML output: missing <nmaprun> element.")

    hosts_up = [h for h in root.findall("host")
                if h.find("status") is not None and h.find("status").get("state") == "up"]
    if not hosts_up:
        raise RuntimeError("Nmap ran but the target did not respond (0 hosts up). "
                           "Check that the VM is running and reachable.")

    findings: list[dict] = []
    for host in hosts_up:
        address = host.find("address")
        host_name = address.get("addr") if address is not None else target
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number, protocol = port.get("portid", ""), port.get("protocol", "tcp")
            service = port.find("service")
            name = _service_name(service)
            version = " ".join(service.get(k, "") for k in ("product", "version")).strip() if service is not None else ""
            label = name or "unknown service"
            findings.append(new_finding(
                host_name, "nmap", f"Open port {number}/{protocol} ({label})",
                severity="Info",
                description=f"Port {number}/{protocol} is open and running {label}"
                            + (f" ({version})." if version else "."),
                evidence=f"{number}/{protocol} open {name} {version}".strip(),
                port=number,
                service=name,
            ))
    return findings


def _service_name(service) -> str:
    """Service name as Nmap reported it; http inside TLS is called https."""
    if service is None:
        return ""
    name = service.get("name", "")
    if name == "http" and service.get("tunnel") == "ssl":
        return "https"
    return name


def find_web_urls(findings: list[dict]) -> list[str]:
    """Return the http(s) URLs of the web ports Nmap discovered.

    Used to decide whether Nikto applies and what Nuclei/Nikto should scan.
    Example result: ["http://192.0.2.10:80", "https://192.0.2.10:443"]
    """
    urls: list[str] = []
    for f in findings:
        service = str(f.get("service", "")).lower()
        if f.get("source") != "nmap" or f.get("port") is None or "http" not in service:
            continue
        scheme = "https" if ("https" in service or "ssl" in service) else "http"
        url = f"{scheme}://{f['target']}:{f['port']}"
        if url not in urls:
            urls.append(url)
    return urls
