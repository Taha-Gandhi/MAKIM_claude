# MAKIM — Multi-Agent Kernel Integrity Monitor
### A multi-AI agent, user-level Linux security monitoring application for detecting rootkit-like behavior on Linux

---

## What is MAKIM?

MAKIM is a Python program that runs on Linux and uses specialized AI/security agents to detect
if your Linux system has been compromised by a rootkit — a type of malware that hides
deep inside the operating system kernel.

Think of it like having 5 security guards, each with a specific job:

| Agent | Job |
|-------|-----|
| **Agent 1: Scanner** | Reads raw data from the kernel (like a camera recording everything) |
| **Agent 2: Anomaly Detector** | Compares the recording to a known-good snapshot |
| **Agent 3: Pattern Agent** | Checks for known rootkit tricks and behaviors |
| **Agent 4: LLM Analyst** | Sends findings to OpenRouter for intelligent reasoning |
| **Agent 5: Report Agent** | Formats everything into a readable report + JSON file |
| **Agent 6: Live Sentinel** | Uses eBPF/bpftrace to watch selected kernel events in real time |

---

## Prerequisites (what you need before starting)

1. **Linux** — Ubuntu, Debian, Fedora, Arch, etc. MAKIM reads from `/proc` which only exists on Linux.
2. **Python 3.8 or later** — Check with: `python3 --version`
3. **Root access** (recommended) — Some `/proc` files need `sudo`
4. **An OpenRouter Free LLM API key** 
5. **bpftrace** (optional) — Needed only for `--live` eBPF monitoring mode

---

## Quick Start (5 minutes to first scan)

### Step 1: Set your OpenRouter Free LLM API key
```bash
# Replace 'sk-ant-...' with your actual API key
export OPENROUTER_API_KEY='your-openrouter-key-here'
sudo -E python3 main.py

# To make this permanent (survives terminal close), add to ~/.bashrc:
echo "export OPENROUTER_API_KEY='sk-ant-api03-...'" >> ~/.bashrc
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

# Watch live kernel events using eBPF/bpftrace
sudo python3 main.py --live --live-duration 20

# One-command reliable live demo with automatic safe activity
sudo python3 main.py --live-demo --live-duration 30

# In a second terminal, trigger harmless demo events for Agent 6
python3 main.py --demo-activity
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
2. We POST it to `OpenRouter API`
3. OpenRouter reads the findings and returns a JSON assessment
4. We parse that JSON and include it in the report

### What eBPF, BCC, and bpftrace Mean

**eBPF** is a Linux kernel technology that lets you attach small, verified programs
to kernel events. It is safer than loading a custom kernel module because the Linux
kernel checks the program before allowing it to run.

**BCC** is a toolkit that lets Python programs load and control eBPF programs. It is
powerful, but it requires extra dependencies.

**bpftrace** is a command-line tracing language built on eBPF. MAKIM starts with
bpftrace because it is easier to install, easier to demo, and still shows real
kernel runtime behavior.

MAKIM's Live Sentinel mode currently watches:

| Event | Why it matters |
|-------|----------------|
| `MODULE_LOAD_ATTEMPT` | Rootkits often enter the kernel as malicious modules |
| `MODULE_UNLOAD_ATTEMPT` | Attackers may unload security tools or hide traces |
| `SENSITIVE_KERNEL_FILE_OPEN` | Access to files like `/proc/kallsyms` can support kernel probing |
| `NETWORK_CONNECT_ATTEMPT` | Helps correlate suspicious processes with outbound activity |

Live Sentinel also assigns each observed process a **trust score**:

| Score Range | Label | Meaning |
|-------------|-------|---------|
| 90-100 | `TRUSTED` | Normal or low-risk observed behavior |
| 70-89 | `WATCH` | Some suspicious activity worth reviewing |
| 40-69 | `SUSPICIOUS` | Multiple or stronger suspicious indicators |
| 0-39 | `HIGH_RISK` | Strong live indicators such as module-load behavior |

The score starts at 100 and drops when MAKIM observes risky actions. For example,
network connects are low impact, sensitive kernel file opens are medium impact,
and module load/unload attempts are high impact. Known noisy system services are
kept in the JSON report but suppressed from the terminal view when they only
produce routine network events.

Install bpftrace on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y bpftrace
sudo python3 main.py --live --live-duration 20
```

For a reliable classroom demo, use two terminals:

Terminal 1:

```bash
cd ~/MAKIM_claude
sudo python3 main.py --live --live-duration 30
```

Terminal 2, while Terminal 1 is still monitoring:

```bash
cd ~/MAKIM_claude
python3 main.py --demo-activity
```

Expected result: Terminal 1 should show events such as
`SENSITIVE_KERNEL_FILE_OPEN` and `NETWORK_CONNECT_ATTEMPT`.

If you want the most reliable single-command demo, use:

```bash
cd ~/MAKIM_claude
sudo python3 main.py --live-demo --live-duration 30
```

This starts Live Sentinel first, waits briefly, then triggers MAKIM's harmless
demo activity automatically so the timing cannot be missed.

---

## Limitations & Important Notes

1. **Mostly user-space**: MAKIM's normal scan mode runs in user-space and CANNOT
   match the detection power of kernel-space tools or hardware-assisted memory
   analysis. The optional `--live` mode uses eBPF through bpftrace for runtime
   visibility, but it is still a monitoring aid rather than a complete EDR.

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
    ├── llm_analyst_agent.py     ← Agent 4: OpenRouter API integration
    ├── report_agent.py          ← Agent 5: Terminal + JSON report
    └── live_sentinel_agent.py   ← Agent 6: Optional eBPF/bpftrace live monitor
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

### "OPENROUTER_API_KEY not set"
```bash
# Set your API key
export OPENROUTER_API_KEY='your-key-here'
# Or run without AI (still does anomaly + pattern detection)
sudo python3 main.py
```

### API errors (401 Unauthorized)
- Your API key is wrong or expired
- Get a new one at `openrouter.com/free`

### API errors (429 Rate Limited)
- You've made too many requests. Wait a minute and try again.

---

*MAKIM — Assignment 1 | Kernel Systems Security | 20266094 Taha Yusuf Gandhi*
