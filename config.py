"""
config.py - shared settings. Change values here, not inside modules.

No passwords, API keys or private keys belong in this file (or anywhere in the
repo). The SSH key is referenced by PATH only.

Lab-specific values (VM address, SSH user, key path) can be set either by
editing the defaults below or with environment variables, e.g. on macOS:

    export COE444_VM_IP=192.168.64.5
    export COE444_SSH_USER=labadmin
    export COE444_SSH_KEY=~/.ssh/coe444_vm
"""

import os
from pathlib import Path

APP_NAME = "COE 444 Security Assessment Platform"
APP_VERSION = "1.0.0"

# ---------------------------------------------------------------- paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
MODELS_DIR = BASE_DIR / "models"
SYNTHETIC_DATASET_PATH = DATA_DIR / "synthetic_findings.csv"
PRIORITY_MODEL_PATH = MODELS_DIR / "priority_model.joblib"
ACTION_MODEL_PATH = MODELS_DIR / "action_model.joblib"
# Labelled sample tool output, used by the tests AND by sample mode.
FIXTURES_DIR = BASE_DIR / "tests" / "fixtures"
FIXTURE_HOST = "192.0.2.10"   # documentation-only address used inside the fixtures

# ---------------------------------------------------------------- lab environment
# TODO (before a real run): set the VM address and SSH user, here or via the
# environment variables above. Empty values mean "not configured": the VM is
# then not an authorized target and Lynis/remediation report a clear error.
VM_IP = os.environ.get("COE444_VM_IP", "")                        # e.g. "192.168.64.5"
SSH_USER = os.environ.get("COE444_SSH_USER", "")                  # non-root admin user on the VM
SSH_KEY_PATH = os.path.expanduser(os.environ.get("COE444_SSH_KEY", "~/.ssh/coe444_vm"))
SSH_CONNECT_TIMEOUT = 10                                          # seconds (ssh -o ConnectTimeout)

# ---------------------------------------------------------------- authorization
# The ONLY targets this application will ever scan. Exact match, no ranges.
AUTHORIZED_TARGETS = ["127.0.0.1"] + ([VM_IP] if VM_IP else [])

# ---------------------------------------------------------------- modes
# Sample mode returns clearly labelled fixtures instead of running tools.
# The dashboard starts in sample mode; real scans must be switched on by the user.
SAMPLE_MODE_DEFAULT = True

# Master switch for the ONE automatic fix (disable SSH root login).
# Off by default. For the remediation demo set it to True here, or run the app
# with COE444_ALLOW_REMEDIATION=1. Even when True, a fix still needs an explicit
# approval in the dashboard and every guard in modules/remediation.py to pass.
ALLOW_AUTO_REMEDIATION = os.environ.get("COE444_ALLOW_REMEDIATION", "") == "1"

# ---------------------------------------------------------------- timeouts (seconds)
DEFAULT_TIMEOUT = 300
TOOL_TIMEOUTS = {
    "nmap": 300,
    "nuclei": 600,
    "nikto": 600,
    "lynis": 900,     # the remote "lynis audit system" command
    "ssh": 60,        # every other short remote command
}

# ---------------------------------------------------------------- scan limits
# Largest network range accepted by validate_target(): /24 = 256 addresses.
MIN_IPV4_PREFIX = 24
MIN_IPV6_PREFIX = 120
NMAP_TOP_PORTS = 100          # nmap --top-ports value
NUCLEI_RATE_LIMIT = 50        # requests per second
NUCLEI_SEVERITIES = "info,low,medium,high,critical"
NIKTO_MAX_TIME = "300s"       # nikto -maxtime value

# ---------------------------------------------------------------- ML
RANDOM_SEED = 42
ML_TEST_SIZE = 0.25
SYNTHETIC_ROWS = 600
# Two ML features describe the ASSET, not the finding. Scanners cannot know
# them, so they are stated here for the lab VM.
ASSET_INTERNET_FACING = 0     # 0 = internal lab VM, 1 = reachable from the internet
ASSET_CRITICALITY = 2         # 1 = low, 2 = normal, 3 = business critical
