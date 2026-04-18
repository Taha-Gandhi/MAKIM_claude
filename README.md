# MAKIM — Multi-Agent Kernel Integrity Monitor
### A multi-AI agent framework for detecting rootkit-like behavior on Linux

---

## What is MAKIM?

MAKIM is a Python program that runs on Linux and uses 5 specialized AI agents to detect
if your Linux system has been compromised by a rootkit — a type of malware that hides
deep inside the operating system kernel.

Think of it like having 5 security guards, each with a specific job:

| Agent | Job |
|-------|-----|
| **Agent 1: Scanner** | Reads raw data from the kernel (like a camera recording everything) |
| **Agent 2: Anomaly Detector** | Compares the recording to a known-good snapshot |
| **Agent 3: Pattern Agent** | Checks for known rootkit tricks and behaviors |
| **Agent 4: LLM Analyst** | Sends findings to Claude AI for intelligent reasoning |
| **Agent 5: Report Agent** | Formats everything into a readable report + JSON file |

---

## Prerequisites (what you need before starting)

1. **Linux** — Ubuntu, Debian, Fedora, Arch, etc. MAKIM reads from `/proc` which only exists on Linux.
2. **Python 3.8 or later** — Check with: `python3 --version`
3. **Root access** (recommended) — Some `/proc` files need `sudo`
4. **An Anthropic API key** (optional but recommended) — Get one at https://console.anthropic.com/

---

## Installation

```bash
# Step 1: Clone or download MAKIM
# If you have git installed:
git clone https://github.com/yourusername/makim.git
cd makim

# OR just create a folder and copy the files there
mkdir makim && cd makim
# (copy all files here)

# Step 2: Verify Python version
python3 --version
# Should show Python 3.8.x or higher

# Step 3: No pip install needed! MAKIM uses only Python's standard library.
# Just confirm the project structure looks like this:
ls -la
# Should show:
#   main.py
#   requirements.txt
#   README.md
#   makim/
#       __init__.py
#       orchestrator.py
#       scanner_agent.py
#       anomaly_detector.py
#       rootkit_pattern_agent.py
#       llm_analyst_agent.py
#       report_agent.py
```

---

## Quick Start (5 minutes to first scan)

### Step 1: Set your Anthropic API key
```bash
# Replace 'sk-ant-...' with your actual API key
export ANTHROPIC_API_KEY='sk-ant-api03-...'

# To make this permanent (survives terminal close), add to ~/.bashrc:
echo "export ANTHROPIC_API_KEY='sk-ant-api03-...'" >> ~/.bashrc
source ~/.bashrc
```

### Step 2: Create a baseline (do this FIRST, on a clean system)
```bash
sudo python3 main.py --baseline
```
This saves a JSON file (`makim_baseline.json`) with your system's current state.
**Important:** Do this on a system you trust is clean. This is your "reference photograph."

### Step 3: Run a full scan
```bash
sudo python3 main.py
```
MAKIM will compare the current system state against your baseline and report any differences.

### Step 4: Read the report
- **Terminal**: Color-coded output appears immediately
- **JSON file**: `makim_report.json` is saved for detailed review
- **Alert file**: `makim_ALERT.txt` is created if threat level is HIGH or CRITICAL

---

## Command Reference

```bash
# Basic scan (requires baseline first)
sudo python3 main.py

# Create/update trusted baseline
sudo python3 main.py --baseline

# Save report to custom location
sudo python3 main.py --output /var/log/makim/scan_$(date +%Y%m%d).json

# Run without root (limited functionality)
python3 main.py

# Get help
python3 main.py --help
```

---

## Understanding the Output

### Threat Levels
| Level | Emoji | Meaning |
|-------|-------|---------|
| CLEAN | ✅ | No issues found |
| LOW | 🟢 | Minor anomalies, likely benign |
| MEDIUM | 🟡 | Suspicious activity, investigate |
| HIGH | 🔴 | Strong indicators of compromise |
| CRITICAL | 🚨 | Active rootkit likely — act immediately |

### Anomaly Types
| Type | What it means |
|------|---------------|
| `NEW_MODULE` | A kernel module not in baseline appeared |
| `MISSING_MODULE` | A baseline module disappeared |
| `MODULE_HIDDEN_FROM_LSMOD` | Module in /proc but hidden from lsmod — classic rootkit |
| `POTENTIAL_DKOM` | Processes may be hidden from process list |
| `NEW_TCP_CONNECTION` | New network connection not in baseline |
| `SUSPICIOUS_MODULE_NAME` | Module name matches rootkit patterns |
| `ANON_EXECUTABLE_MAPPING` | Shellcode-like anonymous executable memory |
| `KERNEL_TAINT` | Kernel integrity was compromised |
| `SUSPICIOUS_PORT` | Known malware port (4444, 31337, etc.) in use |
| `FAKE_KERNEL_THREAD` | Process pretending to be a kernel thread |

---

## How Each Agent Works (for beginners)

### The Linux /proc Filesystem
`/proc` is a special virtual filesystem that doesn't exist on disk — Linux creates it
in RAM and updates it live. It's a window into the kernel's internal state:

```
/proc/
  modules          ← list of all loaded kernel modules
  1234/            ← folder for process with PID 1234
    status         ← name, state, memory usage of that process
    maps           ← memory layout (what code is loaded where)
  net/
    tcp            ← active TCP network connections
  sys/
    kernel/
      tainted      ← kernel taint bitmask
```

### How DKOM Works (and how we detect it)
A rootkit using DKOM (Direct Kernel Object Manipulation) removes itself from the
kernel's internal list of processes. But it needs to continue running. Our DKOM
detector checks for PIDs that exist as `/proc/[PID]/` folders but somehow have
no readable status file — a discrepancy that hints at hidden processes.

### How the LLM Analysis Works
1. We format all findings as structured text
2. We POST it to `https://api.anthropic.com/v1/messages`
3. Claude reads the findings and returns a JSON assessment
4. We parse that JSON and include it in the report

---

## Limitations & Important Notes

1. **User-space only**: MAKIM runs in user-space and CANNOT match the detection
   power of kernel-space tools or hardware-assisted memory analysis. A sophisticated
   rootkit can potentially evade it.

2. **Baseline quality matters**: The baseline must be created on a CLEAN system.
   If your system is already compromised when you run `--baseline`, the compromise
   will be "learned" as normal.

3. **False positives are expected**: Updating your kernel, installing drivers, or
   starting new services will all look like anomalies. This is normal — review each
   finding with context.

4. **Requires Linux kernel 3.0+**: Modern `/proc` structure assumed.

5. **Not a replacement for full security tools**: Use alongside `rkhunter`,
   `chkrootkit`, `Tripwire`, and proper EDR solutions in production.

---

## Project Structure

```
makim_project/
├── main.py                      ← Entry point — run this
├── requirements.txt             ← No external dependencies!
├── README.md                    ← This file
├── makim_baseline.json          ← Created after running --baseline
├── makim_report.json            ← Created after each scan
└── makim/
    ├── __init__.py              ← Makes makim/ a Python package
    ├── orchestrator.py          ← Coordinator — runs all agents
    ├── scanner_agent.py         ← Agent 1: Reads /proc and system data
    ├── anomaly_detector.py      ← Agent 2: Baseline comparison
    ├── rootkit_pattern_agent.py ← Agent 3: Known rootkit signatures
    ├── llm_analyst_agent.py     ← Agent 4: Claude API integration
    └── report_agent.py          ← Agent 5: Terminal + JSON report
```

---

## Troubleshooting

### "Permission denied" errors
```bash
# Run as root
sudo python3 main.py
```

### "No baseline file found"
```bash
# Create one first
sudo python3 main.py --baseline
```

### "ANTHROPIC_API_KEY not set"
```bash
# Set your API key
export ANTHROPIC_API_KEY='your-key-here'
# Or run without AI (still does anomaly + pattern detection)
sudo python3 main.py
```

### API errors (401 Unauthorized)
- Your API key is wrong or expired
- Get a new one at https://console.anthropic.com/

### API errors (429 Rate Limited)
- You've made too many requests. Wait a minute and try again.

---

## Extending MAKIM (for later)

Once you're comfortable with the codebase, you can extend MAKIM by:

1. **Adding new patterns** to `RootkitPatternAgent.SUSPICIOUS_MODULE_PATTERNS`
2. **Adding new anomaly checks** as `_check_*` methods in `AnomalyDetector`
3. **Changing the AI model** in `llm_analyst_agent.py` (MODEL constant)
4. **Adding email/SMS alerts** in `ReportAgent._trigger_alert()`
5. **Scheduling regular scans** with a cron job:
   ```bash
   # Add to /etc/crontab — run every hour
   0 * * * * root python3 /path/to/makim/main.py --output /var/log/makim/$(date +\%H).json
   ```

---

*MAKIM — Assignment 1 | Kernel Systems Security | 20266094 Taha Yusuf Gandhi*
