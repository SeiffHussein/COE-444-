# Data files

| File | What it is | Used for | Source and licence |
|---|---|---|---|
| `nvd_cves.csv.gz` | 247,563 CVEs: id, date, CVSS rating, CWE, English description | priority model training data, CVE lookup | NVD JSON 2.0 feeds 2016-2025 + "modified", downloaded 17 November 2026 from https://nvd.nist.gov/vuln/data-feeds. NVD data is published by NIST (US government) and is not subject to copyright in the United States. |
| `action_training.csv.gz` | 11,251 scanner checks: source, check id, category, tags, title, description, action label | action model training data | See below. |

## action_training.csv.gz

Built with `python -m modules.action_data NUCLEI_DIR LYNIS_DIR` on 17 November 2026 from:

- **Nuclei templates**, https://github.com/projectdiscovery/nuclei-templates, commit `c80830f`.
  10,944 rows (template id, folder, tags, name, description).
  Copyright (c) 2025 ProjectDiscovery, Inc., MIT licence: see `licenses/nuclei-templates-MIT.txt`.
- **Lynis**, https://github.com/CISOfy/lynis, commit `9319416`.
  307 rows (test id, test group, warning/suggestion message).
  Copyright CISOfy, GNU GPL version 3: see `licenses/lynis-GPL-3.0.txt`.
  The Lynis rows are a modified extract of Lynis (messages taken from `include/tests_*`,
  variables like `${OPTIONNAME}` removed) and are distributed under the GPLv3.

The `action` column is NOT part of either source. It is derived by this project's rule in
`modules/action_data.py` from the category the maintainers gave each check.

Not used, on purpose: Nikto's check database (its licence forbids use outside the Nikto
package) and Nmap's service list (its licence restricts redistribution).
