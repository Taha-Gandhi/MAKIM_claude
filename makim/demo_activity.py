"""
makim/demo_activity.py - Harmless activity generator for Live Sentinel demos.

This module does not exploit anything. It only performs safe actions that are
useful for proving MAKIM's eBPF/bpftrace monitor is observing live kernel events.
"""

import socket
import time


SENSITIVE_KERNEL_PATHS = [
    "/proc/kallsyms",
    "/proc/modules",
    "/proc/sys/kernel/tainted",
]


def run_demo_activity(delay: float = 0.5) -> dict:
    """
    Trigger safe, observable events for Agent 6.

    Run this in a second terminal while `sudo python3 main.py --live` is running.
    It opens sensitive kernel information files and attempts a TCP connection.
    """
    print("[DEMO] Generating harmless kernel/security activity...")

    opened_paths = []
    failed_paths = []

    for path in SENSITIVE_KERNEL_PATHS:
        try:
            with open(path, "rb") as f:
                f.read(128)
            opened_paths.append(path)
            print(f"   opened {path}")
        except OSError as e:
            failed_paths.append({"path": path, "error": str(e)})
            print(f"   could not open {path}: {e}")
        time.sleep(delay)

    connection_result = _attempt_test_connection()

    print("[DEMO] Done. Check the Live Sentinel terminal for captured events.")
    return {
        "opened_paths": opened_paths,
        "failed_paths": failed_paths,
        "connection_result": connection_result,
    }


def _attempt_test_connection() -> dict:
    """
    Attempt a short TCP connection.

    The connection may fail, and that is okay. The connect syscall itself is the
    observable event we want bpftrace to capture.
    """
    target = ("127.0.0.1", 9)
    try:
        with socket.create_connection(target, timeout=1):
            pass
        print(f"   connected to {target[0]}:{target[1]}")
        return {"target": f"{target[0]}:{target[1]}", "status": "connected"}
    except OSError as e:
        print(f"   attempted TCP connect to {target[0]}:{target[1]} ({e})")
        return {"target": f"{target[0]}:{target[1]}", "status": "attempted", "error": str(e)}
