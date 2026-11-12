# Test fixtures

Every file in this folder is a **FIXTURE**: hand-written sample tool output for
tests and for the dashboard's sample mode. None of it came from a real system.
The address `192.0.2.10` is a documentation-only address (RFC 5737); sample
mode replaces it with the target typed in the dashboard.

| File | Imitates |
|---|---|
| `nmap_scan.xml` | `nmap -sV -oX -` (ssh, http, https open; one closed port) |
| `nmap_no_open_ports.xml` | host up, nothing open |
| `nuclei_results.jsonl` | `nuclei -jsonl` (one JSON object per line) |
| `nikto_results.json` | `nikto -Format json` |
| `lynis_report.dat` | `/var/log/lynis-report.dat` |
| `sshd_T_root_yes.txt` / `sshd_T_root_no.txt` | `sshd -T` effective configuration |
| `sshd_config_with_include.txt` / `sshd_config_no_include.txt` | `/etc/ssh/sshd_config` |
