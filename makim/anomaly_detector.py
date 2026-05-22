"""
makim/anomaly_detector.py — Agent 2: The Anomaly Detector
==========================================================
WHAT IS THIS AGENT?
  The Anomaly Detector compares the CURRENT system state (from the Scanner)
  against a BASELINE — a trusted snapshot of your system taken when it was
  known to be clean.

  Think of it like a security guard who memorized what your house looks like,
  and now walks through checking if anything has moved, appeared, or disappeared.

WHAT IS A BASELINE?
  A JSON file saved to disk (baseline.json) that stores:
  - Which kernel modules were loaded on a clean system
  - Which process names were running
  - Which network ports were in use

  If a rootkit loads a new kernel module, or a new mystery process appears,
  the Anomaly Detector will flag it because it wasn't in the baseline.

WHAT DOES IT DETECT?
  1. NEW kernel modules    (appeared since baseline)
  2. REMOVED modules       (disappeared — could be a rootkit hiding itself)
  3. NEW processes         (appeared since baseline — unknown programs)
  4. HIDDEN PIDs (DKOM)    (PIDs visible in /proc but hidden from process list)
  5. NEW TCP connections   (new network activity not seen at baseline)
"""

import os
import json
import logging
from datetime import datetime  # datetime lets us work with dates/times
from makim.config_loader import ConfigLoader

logger = logging.getLogger("MAKIM.AnomalyDetector")

# Default location to store the baseline file
DEFAULT_BASELINE_PATH = "makim_baseline.json"


class AnomalyDetector:
    """
    Agent 2: Anomaly Detector

    Loads the trusted baseline and compares it against the current snapshot
    to produce a list of anomalies (things that changed).
    """

    def __init__(self, baseline_path: str = DEFAULT_BASELINE_PATH):
        """
        Args:
            baseline_path: Path to the JSON file where the baseline is saved.
                          Default: "makim_baseline.json" in the current directory.
        """
        self.baseline_path = baseline_path
        self.allowlist = ConfigLoader.load_allowlist()
        self.baseline = None   # Will be loaded from disk
        logger.info(f"Anomaly Detector initialized. Baseline path: {baseline_path}")

    # ── Baseline Management ────────────────────────────────────────────────

    def save_baseline(self, snapshot: dict) -> None:
        """
        Save the current scanner snapshot as the trusted baseline.
        Called when the user runs: python main.py --baseline

        The baseline is saved as a JSON file. JSON (JavaScript Object Notation)
        is a text format for storing structured data — it looks like Python
        dictionaries/lists, so it's easy to read and write.

        Args:
            snapshot: The dict returned by ScannerAgent.run()
        """
        baseline_data = {
            "captured_at": datetime.now().isoformat(),  # e.g. "2025-01-01T12:00:00"
            "module_names": [m["name"] for m in snapshot.get("modules_proc", [])],
            "lsmod_names":  snapshot.get("modules_lsmod", []),
            "process_names": list(set(
                p["name"] for p in snapshot.get("processes", [])
            )),  # set() removes duplicates — we only care about unique names
            "proc_pids": snapshot.get("proc_pids", []),
            "tcp_connections": [
                c["local"] for c in snapshot.get("tcp_connections", [])
                if c["state"] in ("LISTEN", "ESTABLISHED")
            ],
        }

        # json.dump writes the dictionary to a file as JSON text
        # indent=2 makes the file human-readable (pretty-printed with 2-space indent)
        with open(self.baseline_path, "w") as f:
            json.dump(baseline_data, f, indent=2)

        print(f"   ✓ Baseline saved to: {self.baseline_path}")
        print(f"     Captured: {baseline_data['captured_at']}")
        print(f"     Modules: {len(baseline_data['module_names'])}")
        print(f"     Processes: {len(baseline_data['process_names'])}")

    def load_baseline(self) -> bool:
        """
        Load the baseline from disk.

        Returns:
            True if loaded successfully, False if baseline file doesn't exist.
        """
        if not os.path.exists(self.baseline_path):
            logger.warning(f"Baseline file not found: {self.baseline_path}")
            return False

        try:
            with open(self.baseline_path, "r") as f:
                self.baseline = json.load(f)
            logger.info(f"Baseline loaded from {self.baseline_path} "
                        f"(captured: {self.baseline.get('captured_at', 'unknown')})")
            return True
        except json.JSONDecodeError as e:
            # JSONDecodeError means the file exists but is not valid JSON
            logger.error(f"Baseline file is corrupted (invalid JSON): {e}")
            return False

    # ── Main Analysis Method ───────────────────────────────────────────────

    def run(self, snapshot: dict) -> dict:
        """
        Compare the current snapshot against the baseline and return all anomalies.

        Args:
            snapshot: The dict returned by ScannerAgent.run()

        Returns:
            dict with keys:
              "anomalies": list of anomaly dicts, each with:
                  "type":        category of anomaly (e.g. "NEW_MODULE")
                  "severity":    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
                  "description": human-readable explanation
                  "details":     the raw data that triggered the anomaly
              "baseline_available": True/False
              "summary": short text summary
        """
        print("\n[Agent 2/5] Anomaly Detector — Comparing against baseline...")

        anomalies = []

        # Try to load the baseline
        baseline_available = self.load_baseline()

        if not baseline_available:
            # No baseline yet — we can still do DKOM checks (those don't need a baseline)
            print("   ⚠ No baseline found. Run with --baseline first for full comparison.")
            print("     Running DKOM detection only...")
            anomalies += self._detect_dkom(snapshot)
            return self._build_result(anomalies, baseline_available=False)

        # Compare each category
        anomalies += self._check_modules(snapshot)
        anomalies += self._check_lsmod_discrepancy(snapshot)
        anomalies += self._check_new_processes(snapshot)
        anomalies += self._detect_dkom(snapshot)
        anomalies += self._check_tcp_connections(snapshot)

        # Count by severity for the summary message
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for a in anomalies:
            counts[a.get("severity", "LOW")] += 1

        total = len(anomalies)
        if total == 0:
            print("   ✓ No anomalies detected — system matches baseline")
        else:
            print(f"   ⚠ {total} anomalies found: "
                  f"{counts['CRITICAL']} CRITICAL, {counts['HIGH']} HIGH, "
                  f"{counts['MEDIUM']} MEDIUM, {counts['LOW']} LOW")

        return self._build_result(anomalies, baseline_available=True)

    # ── Individual Check Methods ───────────────────────────────────────────

    def _check_modules(self, snapshot: dict) -> list:
        """
        Find kernel modules that appeared or disappeared since the baseline.

        NEW MODULE: Could be legitimate (user installed a driver) or a rootkit.
        MISSING MODULE: A rootkit might unload a security module to weaken defenses.
        """
        anomalies = []

        # Current modules (set of names)
        # A set is like a list but with no duplicates and supports fast lookup
        current_names = set(m["name"] for m in snapshot.get("modules_proc", []))

        # Baseline modules (set of names)
        baseline_names = set(self.baseline.get("module_names", []))

        # Set subtraction: current - baseline = things in current but not baseline
        new_modules = current_names - baseline_names
        # Set subtraction: baseline - current = things in baseline but not current
        removed_modules = baseline_names - current_names

        for name in new_modules:
            if name in self.allowlist["allowed_modules"]:
                continue
            anomalies.append({
                "type":        "NEW_MODULE",
                "severity":    "HIGH",
                "description": f"Kernel module '{name}' was NOT present at baseline. "
                               f"This could be a legitimate driver or a rootkit disguised as a module.",
                "details":     {"module_name": name},
            })

        for name in removed_modules:
            if name in self.allowlist["allowed_modules"]:
                continue
            anomalies.append({
                "type":        "MISSING_MODULE",
                "severity":    "MEDIUM",
                "description": f"Kernel module '{name}' was in baseline but is now MISSING. "
                               f"This might mean it was unloaded (normal) or a rootkit removed it.",
                "details":     {"module_name": name},
            })

        return anomalies

    def _check_lsmod_discrepancy(self, snapshot: dict) -> list:
        """
        Compare /proc/modules list vs lsmod output.

        WHY? A sophisticated rootkit might hook the system call that lsmod uses
        to HIDE itself from lsmod, but /proc/modules might still list it
        (or vice versa). Any discrepancy is suspicious.
        """
        anomalies = []

        proc_names  = set(m["name"] for m in snapshot.get("modules_proc", []))
        lsmod_names = set(snapshot.get("modules_lsmod", []))

        # Modules visible in /proc but hidden from lsmod — classic rootkit trick
        hidden_from_lsmod = proc_names - lsmod_names
        # Modules visible in lsmod but not in /proc — unusual
        hidden_from_proc  = lsmod_names - proc_names

        for name in hidden_from_lsmod:
            anomalies.append({
                "type":        "MODULE_HIDDEN_FROM_LSMOD",
                "severity":    "CRITICAL",
                "description": f"Module '{name}' is in /proc/modules but HIDDEN from lsmod. "
                               f"This is a strong indicator of syscall hooking by a rootkit!",
                "details":     {"module_name": name},
            })

        for name in hidden_from_proc:
            anomalies.append({
                "type":        "MODULE_HIDDEN_FROM_PROC",
                "severity":    "HIGH",
                "description": f"Module '{name}' appears in lsmod but NOT in /proc/modules. Suspicious.",
                "details":     {"module_name": name},
            })

        return anomalies

    def _check_new_processes(self, snapshot: dict) -> list:
        """
        Find process names that weren't running at baseline time.

        NOTE: We compare NAMES, not PIDs, because PIDs change every reboot.
        A process named "kworker_malicious" that wasn't there before is suspicious.
        """
        anomalies = []

        # Current process names (set — removes duplicates automatically)
        current_names = set(p["name"] for p in snapshot.get("processes", []))

        # Baseline process names
        baseline_names = set(self.baseline.get("process_names", []))

        new_process_names = current_names - baseline_names

        # Filter out very common transient process names that appear/disappear normally
        COMMON_TRANSIENTS = {
            "kworker", "ksoftirqd", "migration", "rcu_sched", "rcu_bh",
            "watchdog", "cpuhp", "irq", "kthreadd", "khungtaskd",
        }

        for name in new_process_names:
            # Check if this name is a known transient prefix
            is_transient = any(name.startswith(t) for t in COMMON_TRANSIENTS)
            if not is_transient:
                if name in self.allowlist["allowed_processes"]:
                    continue
                anomalies.append({
                    "type":        "NEW_PROCESS",
                    "severity":    "MEDIUM",
                    "description": f"Process '{name}' is running but was NOT present at baseline. "
                                   f"Investigate if this process is expected.",
                    "details":     {"process_name": name},
                })

        return anomalies

    def _detect_dkom(self, snapshot: dict) -> list:
        """
        Detect DKOM (Direct Kernel Object Manipulation) — the most stealthy rootkit trick.

        WHAT IS DKOM?
          The Linux kernel maintains a doubly-linked list of all processes (task_struct).
          A rootkit using DKOM removes its own entry from this list, making it invisible
          to `ps`, `top`, and anything that reads the task list.

          However, the process still needs to DO things, and doing things requires
          kernel resources. Those resources may leave traces.

        OUR DETECTION APPROACH:
          We compare two sources of process info:
          1. /proc/[PID]/status  → reads the process task list (could be hooked)
          2. /proc folder listing → lists folders by PID number (different kernel path)

          A PID that has a /proc/[PID]/ folder but no corresponding /proc/[PID]/status
          readable content is suspicious. This isn't 100% reliable but catches
          simple rootkits.

        Note: A proper DKOM check requires kernel-level tools or hardware-assisted
        memory inspection. This is a best-effort user-space heuristic.
        """
        anomalies = []

        # PIDs we see in the /proc folder listing
        proc_folder_pids = set(snapshot.get("proc_pids", []))

        # PIDs we actually read status from
        status_pids = set(p["pid"] for p in snapshot.get("processes", []))

        # PIDs that exist as /proc/[PID]/ folders but have no readable status
        # (This can happen legitimately for zombie processes or race conditions,
        #  but a large number is suspicious)
        unreadable_pids = proc_folder_pids - status_pids

        # Filter out PID 0 (swapper/idle) and very small PIDs (kernel threads)
        suspicious_pids = [p for p in unreadable_pids if p > 10]

        # Only flag if there are many — a few unreadable PIDs is normal
        if len(suspicious_pids) > 5:
            anomalies.append({
                "type":        "POTENTIAL_DKOM",
                "severity":    "HIGH",
                "description": f"{len(suspicious_pids)} PIDs are visible as /proc folders "
                               f"but their status was unreadable. "
                               f"This may indicate DKOM (process hiding) or just permission issues.",
                "details":     {"unreadable_pids_count": len(suspicious_pids),
                                "sample_pids": suspicious_pids[:10]},  # show first 10
            })

        return anomalies

    def _check_tcp_connections(self, snapshot: dict) -> list:
        """
        Flag TCP connections that weren't present at baseline.

        C2 CONNECTIONS:
          A rootkit "phones home" to a Command & Control (C2) server.
          This shows up as a new ESTABLISHED TCP connection to an unexpected IP.
          We flag any new ESTABLISHED connections not seen at baseline.
        """
        anomalies = []

        baseline_locals = set(self.baseline.get("tcp_connections", []))

        current_established = [
            c for c in snapshot.get("tcp_connections", [])
            if c["state"] == "ESTABLISHED"
        ]

        for conn in current_established:
            if conn["local"] not in baseline_locals:
                # Only flag if the remote isn't localhost (127.0.0.1)
                # localhost connections are normal inter-process communication
                remote_ip = conn["remote"].split(":")[0]
                if not remote_ip.startswith("127.") and remote_ip != "0.0.0.0":
                    anomalies.append({
                        "type":        "NEW_TCP_CONNECTION",
                        "severity":    "MEDIUM",
                        "description": f"New outbound TCP connection not in baseline: "
                                       f"{conn['local']} → {conn['remote']}. "
                                       f"Could be a C2 (Command & Control) connection.",
                        "details":     conn,
                    })

        return anomalies

    # ── Result Builder ─────────────────────────────────────────────────────

    def _build_result(self, anomalies: list, baseline_available: bool) -> dict:
        """Build the standardized result dict passed to the next agents."""

        # Determine overall severity (worst single anomaly)
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if anomalies:
            worst = max(anomalies, key=lambda a: severity_order.get(a["severity"], 0))
            overall_severity = worst["severity"]
        else:
            overall_severity = "CLEAN"

        return {
            "anomalies":           anomalies,
            "anomaly_count":       len(anomalies),
            "overall_severity":    overall_severity,
            "baseline_available":  baseline_available,
            "baseline_timestamp":  self.baseline.get("captured_at") if self.baseline else None,
        }
