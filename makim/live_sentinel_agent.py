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
from datetime import datetime


SENSITIVE_KERNEL_PATHS = {
    "/proc/kallsyms",
    "/proc/modules",
    "/proc/sys/kernel/tainted",
}


class LiveSentinelAgent:
    """
    Agent 6: Live eBPF Runtime Sentinel.

    Uses bpftrace tracepoints/syscalls where available. If bpftrace is missing,
    the agent explains exactly what is needed instead of crashing.
    """

    def __init__(self, duration: int = 20, output_file: str = "makim_live_events.json"):
        self.duration = max(1, int(duration))
        self.output_file = output_file
        self.bpftrace_path = shutil.which("bpftrace")

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

        raw_lines = self._run_bpftrace(script)
        events = self._parse_events(raw_lines)

        result = {
            "ready": True,
            "events": events,
            "event_count": len(events),
            "started_at": datetime.now().isoformat(),
            "duration_seconds": self.duration,
            "bpftrace_path": self.bpftrace_path,
        }
        self._print_summary(events)
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

    def _print_summary(self, events: list) -> None:
        if not events:
            print("   No live eBPF events captured during the window.")
            return

        print(f"   Captured {len(events)} live event(s):")
        for event in events[:20]:
            path = f" path={event['path']}" if "path" in event else ""
            print(
                f"   [{event['severity']}] {event['event']} "
                f"pid={event.get('pid')} comm={event.get('comm')}{path}"
            )

        if len(events) > 20:
            print(f"   ... {len(events) - 20} more event(s) saved to JSON")

    def _save_result(self, result: dict) -> None:
        try:
            with open(self.output_file, "w") as f:
                json.dump(result, f, indent=2)
            print(f"   Live Sentinel report saved to: {self.output_file}")
        except OSError as e:
            print(f"   [WARNING] Could not save live report: {e}")
