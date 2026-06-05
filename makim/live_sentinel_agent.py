"""
makim/live_sentinel_agent.py - Agent 6: Live eBPF Runtime Sentinel
==================================================================

This optional agent uses bpftrace, an eBPF-based tracing tool, to watch kernel
events as they happen. The normal MAKIM scanner reads snapshots from /proc.
The Live Sentinel adds a runtime view: who attempted to load a kernel module,
who opened sensitive kernel files, and who created outbound network activity.

It is intentionally defensive and read-only. It does not modify kernel state.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime

from makim.config_loader import ConfigLoader


SENSITIVE_KERNEL_PATHS = {
    "/proc/kallsyms",
    "/proc/modules",
    "/proc/sys/kernel/tainted",
}

NOISY_TRUSTED_PROCESS_PREFIXES = {
    "NetworkManager",
    "systemd-resolve",
    "unattended-upgr",
    "dpkg-preconfigu",
    "gnome-terminal-",
    "pipewire-pulse",
    "snapd",
    "gdbus",
}

EVENT_TRUST_PENALTIES = {
    "NETWORK_CONNECT_ATTEMPT": 2,
    "SENSITIVE_KERNEL_FILE_OPEN": 15,
    "MODULE_UNLOAD_ATTEMPT": 30,
    "MODULE_LOAD_ATTEMPT": 40,
}


class LiveSentinelAgent:
    """
    Agent 6: Live eBPF Runtime Sentinel.

    Uses bpftrace tracepoints/syscalls where available. If bpftrace is missing,
    the agent explains exactly what is needed instead of crashing.
    """

    def __init__(
        self,
        duration: int = 20,
        output_file: str = "makim_live_events.json",
        run_demo_activity: bool = False,
    ):
        self.duration = max(1, int(duration))
        self.output_file = output_file
        self.run_demo_activity = run_demo_activity
        self.bpftrace_path = shutil.which("bpftrace")
        self.allowlist = ConfigLoader.load_allowlist()

    def run(self) -> dict:
        print("\n[Agent 6/6] Live Sentinel - eBPF/bpftrace runtime monitoring...")

        readiness = self._check_readiness()
        if not readiness["ready"]:
            self._print_readiness_help(readiness)
            result = {
                "ready": False,
                "reason": readiness["reason"],
                "events": [],
                "event_count": 0,
                "started_at": datetime.now().isoformat(),
                "duration_seconds": self.duration,
            }
            self._save_result(result)
            return result

        script = self._build_bpftrace_script()
        print(f"   Monitoring live kernel events for {self.duration} seconds...")
        print("   Watching: module loads, module unloads, sensitive file opens, outbound connects")
        demo_thread = self._start_demo_activity_thread()

        raw_lines = self._run_bpftrace(script)
        if demo_thread:
            demo_thread.join(timeout=1)
        events = self._parse_events(raw_lines)
        process_scores = self._score_processes(events)

        result = {
            "ready": True,
            "events": events,
            "event_count": len(events),
            "process_trust_scores": process_scores,
            "started_at": datetime.now().isoformat(),
            "duration_seconds": self.duration,
            "bpftrace_path": self.bpftrace_path,
        }
        self._print_summary(events, process_scores)
        self._save_result(result)
        return result

    def _check_readiness(self) -> dict:
        if sys.platform != "linux":
            return {
                "ready": False,
                "reason": "Live eBPF monitoring requires Linux.",
            }

        if os.geteuid() != 0:
            return {
                "ready": False,
                "reason": "Live eBPF monitoring needs root privileges.",
            }

        if not self.bpftrace_path:
            return {
                "ready": False,
                "reason": "bpftrace is not installed or not in PATH.",
            }

        return {"ready": True, "reason": "ready"}

    def _start_demo_activity_thread(self):
        if not self.run_demo_activity:
            return None

        def delayed_demo():
            time.sleep(3)
            print("\n   [DEMO] Auto-triggering safe demo activity while monitor is active...")
            try:
                from makim.demo_activity import run_demo_activity
                run_demo_activity(delay=0.4)
            except Exception as e:
                print(f"   [DEMO] Demo activity failed: {e}")

        thread = threading.Thread(target=delayed_demo, daemon=True)
        thread.start()
        return thread

    def _print_readiness_help(self, readiness: dict) -> None:
        print(f"   [INFO] {readiness['reason']}")
        print("   To enable this feature on Ubuntu/Debian:")
        print("     sudo apt update")
        print("     sudo apt install -y bpftrace")
        print("     sudo python3 main.py --live --live-duration 20")

    def _build_bpftrace_script(self) -> str:
        # JSON lines keep parsing simple and make the live output easy to reuse.
        return r'''
tracepoint:syscalls:sys_enter_finit_module
{
  printf("{\"event\":\"MODULE_LOAD_ATTEMPT\",\"time\":%llu,\"pid\":%d,\"comm\":\"%s\"}\n", nsecs, pid, comm);
}

tracepoint:syscalls:sys_enter_init_module
{
  printf("{\"event\":\"MODULE_LOAD_ATTEMPT\",\"time\":%llu,\"pid\":%d,\"comm\":\"%s\"}\n", nsecs, pid, comm);
}

tracepoint:syscalls:sys_enter_delete_module
{
  printf("{\"event\":\"MODULE_UNLOAD_ATTEMPT\",\"time\":%llu,\"pid\":%d,\"comm\":\"%s\"}\n", nsecs, pid, comm);
}

tracepoint:syscalls:sys_enter_connect
{
  printf("{\"event\":\"NETWORK_CONNECT_ATTEMPT\",\"time\":%llu,\"pid\":%d,\"comm\":\"%s\"}\n", nsecs, pid, comm);
}

tracepoint:syscalls:sys_enter_openat
{
  printf("{\"event\":\"FILE_OPEN_ATTEMPT\",\"time\":%llu,\"pid\":%d,\"comm\":\"%s\",\"path\":\"%s\",\"syscall\":\"openat\"}\n", nsecs, pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_openat2
{
  printf("{\"event\":\"FILE_OPEN_ATTEMPT\",\"time\":%llu,\"pid\":%d,\"comm\":\"%s\",\"path\":\"%s\",\"syscall\":\"openat2\"}\n", nsecs, pid, comm, str(args->filename));
}
'''

    def _run_bpftrace(self, script: str) -> list:
        script_path = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as f:
                script_path = f.name
                f.write(script)

            result = subprocess.run(
                [self.bpftrace_path, script_path],
                capture_output=True,
                text=True,
                timeout=self.duration,
            )
            return result.stdout.splitlines() + result.stderr.splitlines()

        except subprocess.TimeoutExpired as e:
            stdout = e.stdout or ""
            stderr = e.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            return stdout.splitlines() + stderr.splitlines()

        finally:
            if script_path and os.path.exists(script_path):
                try:
                    os.unlink(script_path)
                except OSError:
                    pass

    def _parse_events(self, lines: list) -> list:
        events = []
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event") == "FILE_OPEN_ATTEMPT":
                path = event.get("path")
                if path not in SENSITIVE_KERNEL_PATHS:
                    continue
                event["event"] = "SENSITIVE_KERNEL_FILE_OPEN"

            event["severity"] = self._severity_for_event(event.get("event"))
            event["trusted_noise"] = self._is_trusted_noise(event)
            events.append(event)
        return events

    def _severity_for_event(self, event_type: str) -> str:
        if event_type in ("MODULE_LOAD_ATTEMPT", "MODULE_UNLOAD_ATTEMPT"):
            return "HIGH"
        if event_type == "SENSITIVE_KERNEL_FILE_OPEN":
            return "MEDIUM"
        if event_type == "NETWORK_CONNECT_ATTEMPT":
            return "LOW"
        return "LOW"

    def _is_trusted_noise(self, event: dict) -> bool:
        comm = event.get("comm", "")
        if event.get("event") != "NETWORK_CONNECT_ATTEMPT":
            return False

        prefixes = set(NOISY_TRUSTED_PROCESS_PREFIXES)
        prefixes.update(self.allowlist.get("allowed_processes", []))
        return any(comm.startswith(prefix) for prefix in prefixes)

    def _score_processes(self, events: list) -> list:
        processes = {}
        event_counts = defaultdict(lambda: defaultdict(int))

        for event in events:
            pid = event.get("pid")
            comm = event.get("comm", "unknown")
            if pid is None:
                continue

            key = f"{pid}:{comm}"
            if key not in processes:
                processes[key] = {
                    "pid": pid,
                    "comm": comm,
                    "trust_score": 100,
                    "trust_label": "TRUSTED",
                    "total_penalty": 0,
                    "reasons": [],
                    "event_counts": {},
                    "sensitive_paths": [],
                    "score_explanation": "",
                    "trusted_noise": False,
                }

            event_type = event.get("event", "UNKNOWN")
            penalty = EVENT_TRUST_PENALTIES.get(event_type, 1)
            if event.get("trusted_noise"):
                penalty = 0
                processes[key]["trusted_noise"] = True

            processes[key]["trust_score"] = max(0, processes[key]["trust_score"] - penalty)
            processes[key]["total_penalty"] += penalty
            event_counts[key][event_type] += 1

            path = event.get("path")
            if path and path not in processes[key]["sensitive_paths"]:
                processes[key]["sensitive_paths"].append(path)

            if penalty:
                reason = f"{event_type} (-{penalty})"
                if reason not in processes[key]["reasons"]:
                    processes[key]["reasons"].append(reason)

        for key, counts in event_counts.items():
            processes[key]["event_counts"] = dict(counts)
            processes[key]["score_explanation"] = (self._build_score_explanation(processes[key]))
            score = processes[key]["trust_score"]
            if score >= 90:
                label = "TRUSTED"
            elif score >= 70:
                label = "WATCH"
            elif score >= 40:
                label = "SUSPICIOUS"
            else:
                label = "HIGH_RISK"
            processes[key]["trust_label"] = label
            processes[key]["score_explanation"] = self._build_score_explanation(processes[key])

        return sorted(
            processes.values(),
            key=lambda p: (p["trust_score"], p["pid"]),
        )

    def _build_score_explanation(self, proc: dict) -> str:
        counts = proc.get("event_counts", {})
        parts = []

        sensitive_count = counts.get("SENSITIVE_KERNEL_FILE_OPEN", 0)
        if sensitive_count:
            paths = ", ".join(proc.get("sensitive_paths", []))
            parts.append(f"{sensitive_count} sensitive kernel file open(s): {paths}")

        connect_count = counts.get("NETWORK_CONNECT_ATTEMPT", 0)
        if connect_count:
            parts.append(f"{connect_count} network connect attempt(s)")

        load_count = counts.get("MODULE_LOAD_ATTEMPT", 0)
        if load_count:
            parts.append(f"{load_count} kernel module load attempt(s)")

        unload_count = counts.get("MODULE_UNLOAD_ATTEMPT", 0)
        if unload_count:
            parts.append(f"{unload_count} kernel module unload attempt(s)")

        if not parts:
            return "Only trusted/noisy routine activity was observed."

        return (
            f"Started at 100, lost {proc['total_penalty']} point(s) because MAKIM observed "
            + "; ".join(parts)
            + "."
        )

    def _print_summary(self, events: list, process_scores: list) -> None:
        if not events:
            print("   No live eBPF events captured during the window.")
            return

        print(f"   Captured {len(events)} live event(s):")
        visible_events = [event for event in events if not event.get("trusted_noise")]
        hidden_count = len(events) - len(visible_events)

        for event in visible_events[:20]:
            path = f" path={event['path']}" if "path" in event else ""
            print(
                f"   [{event['severity']}] {event['event']} "
                f"pid={event.get('pid')} comm={event.get('comm')}{path}"
            )

        if len(visible_events) > 20:
            print(f"   ... {len(visible_events) - 20} more visible event(s) saved to JSON")
        if hidden_count:
            print(f"   Suppressed {hidden_count} trusted/noisy network event(s) from terminal view")

        print("\n   Process trust scores:")
        for proc in process_scores[:10]:
            reasons = ", ".join(proc["reasons"]) if proc["reasons"] else "trusted/noisy routine activity"
            explanation = proc.get(
                    "score_explanation",
                    "No explanation available."
                )
            print(
                f"   PID {proc['pid']} | "
                f"{proc['comm']} | "
                f"Score={proc['trust_score']} | "
                f"{proc['trust_label']}"
            )

            print(f"      Why this score? {explanation}")

    def _save_result(self, result: dict) -> None:
        try:
            with open(self.output_file, "w") as f:
                json.dump(result, f, indent=2)
            print(f"   Live Sentinel report saved to: {self.output_file}")
        except OSError as e:
            print(f"   [WARNING] Could not save live report: {e}")
    def _build_score_explanation(self, process: dict) -> str:
        """
        Generate a human-readable explanation for a trust score.
        """

        counts = process.get("event_counts", {})

        explanations = []

        if counts.get("SENSITIVE_KERNEL_FILE_OPEN"):
            explanations.append(
                f"{counts['SENSITIVE_KERNEL_FILE_OPEN']} sensitive kernel file open(s)"
            )

        if counts.get("NETWORK_CONNECT_ATTEMPT"):
            explanations.append(
                f"{counts['NETWORK_CONNECT_ATTEMPT']} network connect attempt(s)"
            )

        if counts.get("MODULE_LOAD_ATTEMPT"):
            explanations.append(
                f"{counts['MODULE_LOAD_ATTEMPT']} module load attempt(s)"
            )

        if counts.get("MODULE_UNLOAD_ATTEMPT"):
            explanations.append(
                f"{counts['MODULE_UNLOAD_ATTEMPT']} module unload attempt(s)"
            )

        if not explanations:
            return "No suspicious runtime activity observed."

        return " + ".join(explanations)