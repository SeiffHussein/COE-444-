# COE 444 Security Assessment Platform

**Automated Network Vulnerability Assessment and Security Reporting Platform** - a COE 444 (Computer Security) university project.

A local Python + Streamlit app that takes an **authorized** lab target, runs Nmap, Nuclei, Nikto and Lynis, converts everything into one finding format, uses two small scikit-learn models to suggest a priority and an action category, shows the results in a dashboard, exports CSV/HTML reports, and can apply exactly **one** approved fix (disabling SSH root login on the lab VM).

> **Authorized use only.** The app refuses every target that is not listed in `config.AUTHORIZED_TARGETS`. Scanning systems without permission is illegal.

This is a student prototype, not a commercial scanner. No database, no Docker, no cloud or paid services.

## Contents

1. [Architecture](#1-architecture)
2. [Setup (macOS and Windows)](#2-setup-macos-and-windows)
3. [External tools](#3-external-tools)
4. [VM preparation](#4-vm-preparation)
5. [Configuration](#5-configuration)
6. [Running: sample mode and real mode](#6-running-sample-mode-and-real-mode)
7. [Tests and the demo script](#7-tests-and-the-demo-script)
8. [Data contract](#8-data-contract)
9. [Machine learning: method and limits](#9-machine-learning-method-and-limits)
10. [NVD data](#10-nvd-data)
11. [Safety design](#11-safety-design)
12. [Known limitations](#12-known-limitations)

---

## 1. Architecture

```
 app.py  (Streamlit dashboard - only calls modules and displays results)
    |
    v
 modules/orchestrator.py   run_assessment(target, sample_mode, options)
    |
    |  1. authorize     tool_utils.validate_target() + is_authorized()   -> reject before any tool starts
    |  2. Nmap          target_scanner.scan_target()                     -> open ports, services
    |  3. Nuclei        vulnerability_scanner.scan_nuclei()              -> template matches, CVEs
    |     Nikto         vulnerability_scanner.scan_nikto()               -> only if Nmap found HTTP/HTTPS
    |  4. Lynis         host_auditor.audit_host()                        -> runs ON the VM over SSH
    |  5. merge         every scanner returned a ScanResult of findings in ONE format (schemas.py)
    |  6. NVD           nvd.enrich_findings()                            -> official CVSS for CVE findings
    |  7. ML            ml_classifier.classify_findings()                -> ml_priority, ml_action
    |  8. advice        remediation.add_recommendations()                -> recommendation text
    v
 combined result dict  ->  dashboard  ->  reporting.generate_csv_report() / generate_html_report()
                                      ->  remediation.apply_fix()   (one guarded fix, after approval)

 All external programs are started by modules/tool_utils.py:
     run_tool([...])        argument list, no shell, timeout
     run_ssh(host, command) the system ssh binary: key-based, BatchMode, ConnectTimeout
```

```
app.py                      dashboard
config.py                   all settings (targets, SSH, timeouts, limits, ML seed)
schemas.py                  the data contract: Finding, ScanResult, label sets
demo_tests.py               presentation demo: Expected / Actual / PASS|FAIL table
modules/
  tool_utils.py             run_tool, run_ssh, validate_target, is_authorized
  target_scanner.py         Nmap  (XML)
  vulnerability_scanner.py  Nuclei (JSONL) and Nikto (JSON)
  host_auditor.py           Lynis over SSH (report file)
  orchestrator.py           the pipeline
  ml_classifier.py          priority model (real NVD data), action model (synthetic data)
  nvd.py                    NVD feed -> CVE table, CVE lookup
  remediation.py            recommendations + the one automatic fix
  reporting.py              CSV / HTML
data/nvd_cves.csv.gz        real CVE data built from the NVD feed (10,555 CVEs): priority model training data
data/synthetic_findings.csv synthetic training data for the action model (600 rows, fixed seed)
models/                     trained models (*.joblib, git-ignored, rebuilt by one command)
reports/                    generated reports (git-ignored)
tests/                      pytest suite; tests/fixtures/ = labelled sample tool output
```

---

## 2. Setup (macOS and Windows)

Requires Python 3.10 or newer. Run everything from the repository root.

**macOS (Terminal)**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m modules.ml_classifier
python -m pytest -q
python -m streamlit run app.py
```

**Windows (PowerShell)**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m modules.ml_classifier
python -m pytest -q
python -m streamlit run app.py
```

If PowerShell blocks the activation script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

`python -m modules.ml_classifier` trains the two ML models into `models/` (about ten seconds). The model files are not stored in Git, so this step is needed once after cloning. Without it the app still works and shows an "ML unavailable" message.

---

## 3. External tools

`pip` installs only Python packages. The scanners are separate programs. Sample mode needs none of them.

| Tool | Runs on | macOS (Homebrew) | Windows |
|---|---|---|---|
| Nmap | your machine | `brew install nmap` | installer from nmap.org |
| Nuclei | your machine | `brew install nuclei` | release binary from the ProjectDiscovery GitHub page |
| Nikto | your machine | `brew install nikto` | needs Perl; easiest inside WSL |
| ssh | your machine | built in | built in (OpenSSH client) |
| Lynis | **the VM** | - | - (see VM preparation) |

After installing:

```bash
nmap --version
nuclei -version
nuclei -update-templates
nikto -Version
```

Run `nuclei -update-templates` once: the app starts Nuclei with update checks disabled so that a scan never downloads anything by itself.

A missing tool does not break the app. That tool is reported as `FAILED` with the reason, and the others still run.

---

## 4. VM preparation

The target is an Ubuntu Server VM that you own, reachable from your machine. All commands below run **on the VM**.

**4.1 SSH access with a key, as a non-root admin user**

On your machine, create a key and copy it to the VM (replace user and address):

```bash
ssh-keygen -t ed25519 -f ~/.ssh/coe444_vm
ssh-copy-id -i ~/.ssh/coe444_vm.pub labadmin@VM_IP
ssh -i ~/.ssh/coe444_vm labadmin@VM_IP
```

Connect once by hand so the VM's host key is accepted. The app uses `BatchMode`, so it never answers prompts. Never commit the key (`.gitignore` blocks the usual names).

**4.2 Web server and Lynis**

```bash
sudo apt update
sudo apt install -y apache2 lynis
```

**4.3 Narrow passwordless sudo rules**

The app runs remote commands non-interactively (`sudo -n`), so the SSH user needs passwordless sudo for exactly the commands below and nothing else. First check where the programs are on your VM:

```bash
command -v lynis sshd cat tee rm systemctl
```

Then create the rule file with `sudo visudo -f /etc/sudoers.d/coe444` (replace `labadmin`, and adjust paths if the command above printed different ones):

```
# Lynis audit (read-only)
labadmin ALL=(root) NOPASSWD: /usr/sbin/lynis audit system --quick --no-colors
labadmin ALL=(root) NOPASSWD: /usr/bin/cat /var/log/lynis-report.dat

# Only needed for the root-login remediation demo
labadmin ALL=(root) NOPASSWD: /usr/sbin/sshd -T, /usr/sbin/sshd -t
labadmin ALL=(root) NOPASSWD: /usr/bin/tee /etc/ssh/sshd_config.d/00-coe444-permitrootlogin.conf
labadmin ALL=(root) NOPASSWD: /usr/bin/rm -f /etc/ssh/sshd_config.d/00-coe444-permitrootlogin.conf
labadmin ALL=(root) NOPASSWD: /usr/bin/systemctl reload ssh, /usr/bin/systemctl reload sshd
```

Check it from your machine. Each command must work without asking for a password:

```bash
ssh -i ~/.ssh/coe444_vm labadmin@VM_IP "sudo -n sshd -T | grep -i permitrootlogin"
```

**4.4 Setting up the root-login demo**

Deliberately allow root login so there is something to find and fix:

```bash
echo "PermitRootLogin yes" | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload ssh
sudo sshd -T | grep -i permitrootlogin
```

The last command must print `permitrootlogin yes`. Also confirm that `sshd_config` includes the drop-in folder near the top (Ubuntu does this by default):

```bash
grep -n "^Include" /etc/ssh/sshd_config
```

To run the demo again, remove the drop-in the fix created (the `PermitRootLogin yes` line then applies again):

```bash
sudo rm -f /etc/ssh/sshd_config.d/00-coe444-permitrootlogin.conf
sudo sshd -t && sudo systemctl reload ssh
```

When you are finished with the project, also delete the `PermitRootLogin yes` line from `/etc/ssh/sshd_config`.

---

## 5. Configuration

Everything is in `config.py`. The lab values can also be set with environment variables, so nothing personal has to be committed.

| Setting | Environment variable | Meaning |
|---|---|---|
| `VM_IP` | `COE444_VM_IP` | VM address. Added to `AUTHORIZED_TARGETS` when set. |
| `SSH_USER` | `COE444_SSH_USER` | non-root admin user on the VM |
| `SSH_KEY_PATH` | `COE444_SSH_KEY` | private key path (default `~/.ssh/coe444_vm`) |
| `ALLOW_AUTO_REMEDIATION` | `COE444_ALLOW_REMEDIATION=1` | master switch for the one fix (default off) |
| `AUTHORIZED_TARGETS` | - | `127.0.0.1` plus `VM_IP`. Nothing else is ever scanned. |
| `NMAP_TOP_PORTS`, `NUCLEI_RATE_LIMIT`, `NIKTO_MAX_TIME`, `TOOL_TIMEOUTS` | - | scan limits and timeouts |
| `RANDOM_SEED`, `SYNTHETIC_ROWS` | - | ML reproducibility |
| `NVD_INDEX_PATH`, `NVD_FEEDS_DIR` | - | the CVE table and the folder for downloaded feeds |

macOS example:

```bash
export COE444_VM_IP=192.168.64.5
export COE444_SSH_USER=labadmin
export COE444_SSH_KEY=~/.ssh/coe444_vm
python -m streamlit run app.py
```

Windows PowerShell example:

```powershell
$env:COE444_VM_IP = "192.168.64.5"
$env:COE444_SSH_USER = "labadmin"
$env:COE444_SSH_KEY = "$HOME\.ssh\coe444_vm"
python -m streamlit run app.py
```

---

## 6. Running: sample mode and real mode

```bash
python -m streamlit run app.py
```

**Sample mode (default).** Leave the toggle on and press **Run assessment**. Every scanner reads a labelled fixture from `tests/fixtures/` through its real parser. No tool runs and no host is contacted. Findings are flagged `is_sample` and the dashboard and reports say "SAMPLE DATA".

**Real mode.**

1. Install the tools (section 3), prepare the VM (section 4), set the lab values (section 5).
2. Enter the VM address. The sidebar shows the format check and the authorization check separately; the button is disabled until both pass.
3. Switch the sample toggle off and press **Run assessment**.
4. The *Tool status* panel shows `SUCCESS`, `FAILED`, `SKIPPED` or `NOT_APPLICABLE` for each tool, with duration and error text.

**Remediation demo.** After a real run with `PermitRootLogin yes` on the VM, the Lynis root-login finding appears in the *Remediation* section.

1. Keep **Simulate only** ticked and press **Simulate fix** to walk through the steps without touching the VM.
2. For the real fix: start the app with `COE444_ALLOW_REMEDIATION=1`, untick *Simulate only*, tick the approval box, press **Apply fix**.
3. The step table shows each check and the verification result.

**Reports.** Press **Generate CSV and HTML reports**. The page shows the saved path of each file (in `reports/`) and whether it succeeded, with download buttons.

---

## 7. Tests and the demo script

```bash
python -m pytest -q
python demo_tests.py
```

- The test suite never touches a real system. `tests/conftest.py` blocks `subprocess` for every test; tools and SSH are replaced by mocks that answer with the fixtures. Models are trained into a temporary folder.
- The NVD tests use a small real excerpt of the feed (82 CVEs) in `tests/fixtures/`.
- Covered: each scanner (success, empty success, missing tool, timeout, malformed output, non-zero exit), Nikto `NOT_APPLICABLE`, unauthorized targets, the schema, both ML models (train, save, reload, valid labels, missing model), recommendation mapping, every remediation guard, report content and HTML escaping, the orchestrator with one tool failing, and the dashboard (import and page load run nothing).
- `demo_tests.py` prints `Test / Scenario / Expected / Actual / Result` for 19 key scenarios and a totals line. `PASS` is computed by comparing the actual value with the expected one.

---

## 8. Data contract

Defined in `schemas.py`. Every module exchanges plain dicts in these shapes.

**Finding**

| Field | Type | Meaning |
|---|---|---|
| `id` | str | 8-character id |
| `target` | str | host the finding is about |
| `source` | str | `nmap`, `nuclei`, `nikto` or `lynis` |
| `title` | str | short name |
| `severity` | str | normalized: `Critical`, `High`, `Medium`, `Low`, `Info` |
| `original_severity` | str | the tool's own wording (`critical`, `warning`, ...); empty if the tool gives none |
| `description` | str | explanation |
| `evidence` | str | raw line, URL or matched location |
| `port` | int or None | port, if the tool reported one |
| `service` | str | service name, if reported |
| `cve` | str | CVE id(s), only if the tool reported them |
| `cvss_score` | float or None | official CVSS base score from NVD, if the CVE is in the local index |
| `nvd_severity` | str | official NVD severity: empty, or `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `check_id` | str | Nuclei template id, Nikto test id or Lynis test id |
| `ml_priority` | str | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`; empty for Info findings, which are not rated |
| `ml_action` | str | empty, or one of the action labels below |
| `recommendation` | str | human-readable advice |
| `remediation_supported` | bool | true only for the SSH root-login finding |
| `is_sample` | bool | true for fixture data |

Unknown values are `None` or `""`. A CVE, port or service is never invented.

**Severity mapping**

| Tool | Tool's wording | Normalized |
|---|---|---|
| Nmap | none (open port = discovery) | `Info` |
| Nuclei | info / low / medium / high / critical | same level |
| Nikto | none | estimated from keywords: `Low`, `Medium` or `High` |
| Lynis | warning / suggestion / hardening index | `Medium` / `Low` / `Info` |

**ScanResult** (returned by every scanner)

```
{"tool", "status", "findings", "error", "started_at", "finished_at", "duration_s", "is_sample"}
```

`status` is `SUCCESS`, `FAILED`, `SKIPPED` or `NOT_APPLICABLE`. A `FAILED` result must carry an error text, so a failed scan can never look like a clean scan with zero findings.

**Combined result** (returned by `orchestrator.run_assessment`)

```
{"scan_id", "target", "is_sample", "authorized", "started_at", "finished_at", "duration_s",
 "scans": {"nmap": ScanResult, "nuclei": ..., "nikto": ..., "lynis": ...},
 "findings": [...], "nvd": {"status", "error", "cve_findings", "matched"},
 "ml": {"status", "error"}, "errors": [...], "remediation": None or outcome}
```

**ML action labels:** `REVIEW_SERVICE`, `PATCH_OR_UPDATE`, `HARDEN_SSH`, `HARDEN_WEB_SERVER`, `REVIEW_TLS`, `INVESTIGATE_FINDING`, `NO_ACTION_INFORMATIONAL`.

---

## 9. Machine learning: method and limits

The scanners find the issues. Two models only add advice: how urgent a finding is (`ml_priority`) and what kind of action fits (`ml_action`). At runtime only those two fields are filled in. If a model file is missing or broken, the findings are returned unchanged with an ML error. A prediction is never faked.

| Model | Predicts | Training data | Input |
|---|---|---|---|
| Priority | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` | **real** NVD CVE records | text of the description |
| Action | one of 7 action labels | **synthetic** findings | 5 simple features |

Train both with `python -m modules.ml_classifier`. It prints accuracy, macro precision/recall/F1 and a confusion matrix for each model, saves them under `models/`, then reloads each file and checks that it predicts valid labels. Both use a stratified 75/25 split and `config.RANDOM_SEED`.

### 9.1 Priority model: real data

- **Data.** The CVE table built from the NVD feed (section 10): 10,270 CVEs that have a CVSS rating.
- **Input and label.** Input is the English description of a CVE. The label is the CVSS severity NVD assigned to it. Nothing is synthetic and we wrote no labelling rule.
- **Method.** TF-IDF turns the text into numbers (a weight for each of the 5,000 most useful words and word pairs). A `RandomForestClassifier` with 100 trees learns which words go with which severity.
- **At runtime.** The model reads a finding's title and description and returns a priority.

Results on 2,568 real CVEs the model did not see during training:

| Accuracy | Macro precision | Macro recall | Macro F1 |
|---|---|---|---|
| 0.672 | 0.600 | 0.549 | 0.565 |

For comparison, always answering the most common class (HIGH) would score 0.45. The model is weakest on the two rare classes, LOW (34 % recall) and CRITICAL (42 % recall). Most mistakes are one level off.

**Limits, stated plainly.**

- The score above is for CVE descriptions. Findings that are not CVEs (Lynis suggestions, Nikto messages) are outside what the model was trained on. In the sample data it rates all of them MEDIUM, which is its fallback answer when it recognises nothing. Treat the priority of a non-CVE finding as a weak hint.
- NVD has no "informational" class, so the model cannot say "this is not a vulnerability". Findings the scanner itself rates Info (open ports, service detections, the hardening index) are therefore **not rated**: their `ml_priority` stays empty.
- The training data is one feed file covering mostly 2026 CVEs. More feeds would likely improve it (section 10).

### 9.2 Action model: synthetic data

NVD has no "what should be done" label, so this model still learns from `data/synthetic_findings.csv`: 600 rows generated with a fixed seed, covering all four tools and every action.

| Feature | Values | Source |
|---|---|---|
| `severity_score` | 0-4 | normalized severity |
| `source_tool` | nmap / nuclei / nikto / lynis | finding |
| `has_cve` | 0/1 | the tool reported a CVE |
| `category` | ssh / web / tls / other / none | port, service and keywords |
| `is_misconfiguration` | 0/1 | Lynis warning/suggestion, or configuration keywords, and no CVE |

Label rule, first match wins, then 5 % of rows get a random action as noise:

1. `has_cve` -> `PATCH_OR_UPDATE`
2. category `tls` -> `REVIEW_TLS`
3. tool `nmap` -> `REVIEW_SERVICE`
4. category `ssh` and (misconfiguration or severity above Info) -> `HARDEN_SSH`
5. category `web` and misconfiguration -> `HARDEN_WEB_SERVER`
6. severity Info -> `NO_ACTION_INFORMATIONAL`
7. otherwise -> `INVESTIGATE_FINDING`

Method: `RandomForestClassifier`, 100 trees, depth 8. On the held-out synthetic rows: accuracy 0.960, macro precision 0.954, macro recall 0.942, macro F1 0.942.

**Limit.** This model learns a rule we wrote, from data we generated. Its score only shows that it recovered that rule through the noise. It says nothing about real-world performance. An action label is never treated as a command.

---

## 10. NVD data

The project uses real vulnerability data from the NVD (National Vulnerability Database, published by NIST): the JSON 2.0 CVE feeds at https://nvd.nist.gov/vuln/data-feeds. The app never contacts NVD itself; feed files are downloaded by hand and processed by `modules/nvd.py`.

**What is in the repo.** `data/nvd_cves.csv.gz` is a compact table built from the NVD "modified" feed of 17 November 2026: 10,555 CVEs (rejected ones removed), of which 10,270 have a CVSS rating. Columns: CVE id, published date, CVSS version, score, severity, vector, CWE, English description. The "modified" feed holds only recently added or changed CVEs, so most entries are from 2026.

The table has two uses:

1. **Training data** for the priority model (section 9.1).
2. **CVE lookup.** When a scanner reports a CVE id, the official CVSS score and severity are copied onto the finding (`cvss_score`, `nvd_severity`). If a finding lists several CVEs, the highest score is used. A CVE that is not in the table gets nothing; a score is never guessed. The tool's own severity is not changed.

For a CVE finding the report therefore shows the official NVD rating (when the CVE is in the table) next to the model's `ml_priority`.

**Adding more data.** For wider lookup coverage and more training data, download yearly feeds (for example `nvdcve-2.0-2021.json.gz`) from the NVD page into `data/nvd_feeds/` (git-ignored), then rebuild the table and retrain:

```bash
python -m modules.nvd data/nvd_feeds/*
python -m modules.ml_classifier
```

`.json`, `.json.gz` and `.zip` files are accepted. If a CVE appears in several files, the last file wins. The accuracy figures in section 9.1 will change with the data used.

---

## 11. Safety design

- **Authorization before anything else.** `validate_target` (format) and `is_authorized` (exact match in `AUTHORIZED_TARGETS`) are separate checks. The orchestrator runs both before any tool starts, every scanner and `run_ssh` check again, and sample mode follows the same rule.
- **One way to start programs.** `run_tool` takes an argument list, never uses a shell and always has a timeout. Target text that starts with `-` or contains spaces or shell characters is rejected.
- **Honest failure.** Every scanner returns a `ScanResult`. Missing tool, timeout, non-zero exit, malformed output and an unreachable host are `FAILED` with a reason, never an empty success. One tool failing does not stop the others.
- **Non-intrusive scans.** Nmap connect scan on the top ports; Nuclei excludes intrusive, DoS, fuzzing and brute-force templates and is rate limited; Nikto excludes its DoS category and has a time limit.
- **Lynis is read-only** and runs through a narrow sudoers rule.
- **Untrusted output.** Scanner text can be controlled by the scanned server. It is HTML-escaped in reports, neutralized in CSV cells that look like formulas, and never placed in a command.
- **Exactly one automatic fix**, disabling SSH root login, behind these guards in `remediation.apply_fix`:
  1. The finding is real (not sample), from an authorized target, and is the root-login finding.
  2. `config.ALLOW_AUTO_REMEDIATION` is on and the dashboard approval was given. Both are checked before the VM is contacted at all.
  3. `sudo sshd -T` on the VM shows the effective value `permitrootlogin yes`.
  4. A non-root key-based SSH session works before any change.
  5. `sshd_config` has an active `Include .../sshd_config.d/*.conf` before any `PermitRootLogin` line. If not, stop. An existing drop-in is backed up with a timestamp to `~/coe444-backups/` on the VM.
  6. The drop-in `/etc/ssh/sshd_config.d/00-coe444-permitrootlogin.conf` is written with only `PermitRootLogin no`. OpenSSH uses the first value it reads, and the `00-` file is read first.
  7. `sudo sshd -t` validates. On failure the drop-in is removed (or the backup restored) and nothing is reloaded.
  8. The active service (`ssh` or `sshd`) is reloaded. If that fails, the change is rolled back.
  9. `sshd -T` must now show `permitrootlogin no` and a fresh non-root SSH login must work.

  The outcome reports `applied`, `verified`, `backup_path`, every step and a message. All remote commands are constants in the code. An ML action label is never a command. `simulate=True` walks the same steps without connecting to anything.
- **No secrets in the repo.** The SSH key is referenced by path only; key file names, `.env`, reports and models are git-ignored.

---

## 12. Known limitations

- Scans are not exhaustive: top 100 TCP ports only, no UDP, non-intrusive templates only. No finding does not mean no vulnerability.
- Nikto gives no severity, so its severity is a keyword estimate. Nmap findings are always `Info`.
- NVD lookup only knows the CVEs in the local table, which currently covers recent CVEs only. Older ones, such as the Apache CVE in the sample data, are not found until more feeds are added (section 10).
- The priority model is right about two times in three on unseen CVEs and is much less reliable for findings that are not CVEs. Informational findings get no priority (section 9.1).
- The action model is trained on synthetic data and is advisory only (section 9.2).
- Lynis needs SSH access and the sudoers rule on the VM; it is not run against `127.0.0.1` unless SSH is set up there.
- The exact Lynis wording for the root-login item differs between Lynis versions. The detection accepts the common forms; check it on your VM's version during the first real run.
- `sshd -T` shows the configuration sshd would load from disk. The fix is verified by that value plus a fresh login, not by attempting a root login.
- Results live in the Streamlit session only. Reports are files in `reports/`.
- One target per assessment. Hostnames and small ranges pass the format check, but only exact entries of `AUTHORIZED_TARGETS` are scanned.
- Nikto on Windows needs Perl or WSL.
