# Test fixtures

Every file in this folder is a **FIXTURE** for tests and for the dashboard's
sample mode. The tool outputs are hand-written; none of them came from a real
system. The exceptions are two small real excerpts: `nvd_feed_sample.json`
(public NVD data) and `action_checks_sample.csv` (rows of the action dataset,
taken from the Nuclei templates, MIT licence, and Lynis, GPLv3; see
`data/README.md`).
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
| `nvd_feed_sample.json` | NVD JSON 2.0 feed: 80 real CVEs (20 per severity), one rejected CVE, one CVE without a CVSS rating |
| `action_checks_sample.csv` | 145 rows of `data/action_training.csv.gz`: up to 20 real checks per action plus up to 3 Lynis rows each |
| `check_libraries/` | hand-written files in the Nuclei template and Lynis `include/tests_*` formats, including one broken template and one folder that must be ignored |
