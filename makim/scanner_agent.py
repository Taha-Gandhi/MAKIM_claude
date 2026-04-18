"""
makim/scanner_agent.py — Agent 1: The Scanner
==============================================
WHAT IS THIS AGENT?
  The Scanner Agent is like a detective that reads raw data from the Linux kernel.
  It doesn't analyze anything yet — it just COLLECTS information and returns it.

WHERE DOES IT READ FROM?
  • /proc/modules     → List of kernel modules currently loaded
                        (A kernel module is a plugin for the kernel, like a driver.
                         Rootkits often disguise themselves as modules.)

  • /proc/[PID]/      → For every running process, Linux creates a folder in /proc
                        named with the process's ID (PID = Process ID, a unique number).
                        Inside: maps (memory layout), status (name, state, parent), etc.

  • lsmod             → A shell command that also lists kernel modules (different source
                        than /proc/modules — comparing both can reveal hidden modules)

  • dmesg             → The kernel's own log messages (like a black box recorder for the kernel)
                        Rootkits sometimes leave taint warnings here.

  • /proc/net/tcp     → List of active TCP network connections (useful to spot C2 ports —
                        "Command & Control" servers that rootkits phone home to)
"""

import os
import subprocess
import glob
import logging

# logging lets us print timestamped messages like:
# [2025-01-01 12:00:00] INFO - Scanner: Reading /proc/modules...
logger = logging.getLogger("MAKIM.Scanner")


class ScannerAgent:
    """
    Agent 1: Scanner Agent

    Reads raw system data from the Linux kernel via /proc and system commands.
    Returns a dictionary (snapshot) with everything it found.
    """

    def __init__(self):
        logger.info("Scanner Agent initialized.")

    def run(self) -> dict:
        """
        Main method — collect all system data and return it as a dictionary.

        A dictionary in Python is like a labeled box with compartments:
          snapshot = {
              "modules": [...],    # list of kernel modules
              "processes": [...],  # list of running processes
              ...
          }

        Returns:
            dict: A "snapshot" of the system's current state.
        """
        print("\n[Agent 1/5] Scanner Agent — Collecting system data...")

        snapshot = {
            "modules_proc":  self._read_proc_modules(),
            "modules_lsmod": self._read_lsmod(),
            "processes":     self._read_processes(),
            "dmesg_tail":    self._read_dmesg(),
            "tcp_connections": self._read_tcp_connections(),
            "proc_pids":     self._list_proc_pids(),
        }

        # Count how much we collected (just for a nice status message)
        num_modules  = len(snapshot["modules_proc"])
        num_procs    = len(snapshot["processes"])
        num_tcp      = len(snapshot["tcp_connections"])
        print(f"   ✓ Found {num_modules} kernel modules, {num_procs} processes, {num_tcp} TCP connections")

        return snapshot

    # ── Private helper methods (prefixed with _ by convention) ─────────────
    # These are internal — only called from inside this class.

    def _read_proc_modules(self) -> list:
        """
        Read /proc/modules — the kernel's live list of loaded modules.

        FILE FORMAT (each line):
          module_name  size  use_count  dependencies  state  memory_address
          Example:
            btrfs 1462272 0 - Live 0xffffffffc0a00000

        Returns:
            list of dicts, one per module:
              [{"name": "btrfs", "size": 1462272, "state": "Live", "address": "0x..."}, ...]
        """
        modules = []
        proc_path = "/proc/modules"

        if not os.path.exists(proc_path):
            logger.warning("/proc/modules not found — not on Linux?")
            return modules

        try:
            with open(proc_path, "r") as f:
                for line in f:
                    # line.split() breaks "btrfs 1462272 0 - Live 0x..." into a list of words
                    parts = line.split()
                    if len(parts) >= 6:
                        modules.append({
                            "name":    parts[0],           # module name
                            "size":    int(parts[1]),      # size in bytes (int = integer number)
                            "used_by": parts[3],           # dependencies (- means none)
                            "state":   parts[4],           # Live / Loading / Unloading
                            "address": parts[5].strip(),   # memory address (strip removes newline)
                        })
        except PermissionError:
            # PermissionError happens when we try to read a file we're not allowed to
            logger.warning("Permission denied reading /proc/modules. Try running as root.")
        except Exception as e:
            # Catch any other unexpected error and log it instead of crashing
            logger.error(f"Error reading /proc/modules: {e}")

        return modules

    def _read_lsmod(self) -> list:
        """
        Run the `lsmod` shell command and parse its output.

        WHY BOTH /proc/modules AND lsmod?
          lsmod reads /proc/modules internally, but a sophisticated rootkit could
          hook the system call that lsmod uses, while leaving /proc/modules alone
          (or vice versa). Comparing both sources can reveal hidden modules.

        Returns:
            list of module name strings: ["btrfs", "ext4", ...]
        """
        modules = []
        try:
            # subprocess.run() executes a shell command
            # capture_output=True means capture stdout/stderr instead of printing them
            # text=True means decode output as text (not bytes)
            result = subprocess.run(
                ["lsmod"],
                capture_output=True,
                text=True,
                timeout=10  # Don't wait more than 10 seconds
            )

            lines = result.stdout.strip().split("\n")
            # First line is the header "Module  Size  Used by" — skip it with [1:]
            for line in lines[1:]:
                parts = line.split()
                if parts:
                    modules.append(parts[0])  # Just the module name

        except FileNotFoundError:
            logger.warning("lsmod command not found.")
        except subprocess.TimeoutExpired:
            logger.warning("lsmod timed out.")
        except Exception as e:
            logger.error(f"Error running lsmod: {e}")

        return modules

    def _read_processes(self) -> list:
        """
        Read information about every running process from /proc/[PID]/status.

        WHAT IS A PID?
          Every running program gets a unique Process ID (PID) number.
          Example: your browser might be PID 1234, a text editor PID 5678.
          Linux exposes each process's details in /proc/1234/, /proc/5678/, etc.

        WHAT IS /proc/[PID]/status?
          A text file with fields like:
            Name:   bash           ← program name
            Pid:    1234           ← this process's ID
            PPid:   1000           ← parent process's ID (who started this process)
            VmRSS:  12345 kB       ← memory usage

        Returns:
            list of dicts, one per process:
              [{"pid": 1234, "name": "bash", "ppid": 1000, "state": "S"}, ...]
        """
        processes = []

        # glob.glob finds files matching a pattern
        # "/proc/*/status" matches /proc/1/status, /proc/2/status, /proc/1234/status, etc.
        status_files = glob.glob("/proc/*/status")

        for status_file in status_files:
            try:
                proc_info = {}
                with open(status_file, "r") as f:
                    for line in f:
                        # Each line looks like "Name:\tbash\n"
                        # split(":", 1) splits on the FIRST colon only (maxsplit=1)
                        if ":" in line:
                            key, value = line.split(":", 1)
                            # .strip() removes leading/trailing whitespace and newlines
                            proc_info[key.strip()] = value.strip()

                # Extract the fields we care about
                processes.append({
                    "pid":   int(proc_info.get("Pid", 0)),
                    "name":  proc_info.get("Name", "unknown"),
                    "ppid":  int(proc_info.get("PPid", 0)),   # parent PID
                    "state": proc_info.get("State", "?"),      # R=running, S=sleeping, Z=zombie
                })

            except (PermissionError, FileNotFoundError):
                # It's normal for some /proc files to disappear (process ended)
                # or be unreadable without root — just skip them
                continue
            except Exception as e:
                logger.debug(f"Skipping {status_file}: {e}")
                continue

        return processes

    def _list_proc_pids(self) -> list:
        """
        List all PID numbers visible in /proc by scanning folder names.

        WHY IS THIS SEPARATE FROM _read_processes()?
          _read_processes reads /proc/[PID]/status for detailed info.
          This method just lists the raw PID numbers from folder names.

          DKOM DETECTION: A rootkit using DKOM removes a process from the
          kernel's internal task list — so `ps` won't show it. But the
          /proc/[PID]/ folder might still exist for a moment, or there
          could be discrepancies between different kernel data sources.
          Comparing this list to what ps shows is a rootkit red flag.

        Returns:
            list of int PIDs: [1, 2, 3, ..., 1234, 5678, ...]
        """
        pids = []
        try:
            # os.listdir lists everything in a folder
            for entry in os.listdir("/proc"):
                # We only want entries that are pure digits (those are PIDs)
                # isdigit() returns True if the string contains only numbers
                if entry.isdigit():
                    pids.append(int(entry))
        except PermissionError:
            logger.warning("Cannot list /proc directory.")
        return sorted(pids)  # sorted() returns a sorted list

    def _read_dmesg(self) -> list:
        """
        Read the last 100 lines of dmesg — the kernel's own log.

        WHAT IS dmesg?
          The kernel writes its own diagnostic messages to a ring buffer.
          dmesg reads that buffer. Examples of what you might find:
          - "module loaded" messages
          - Hardware errors
          - "Kernel tainted" warnings (taint = kernel was modified in an unusual way —
            a common side effect of rootkit module installation)

        Returns:
            list of log line strings
        """
        lines = []
        try:
            result = subprocess.run(
                ["dmesg", "--time-format=iso"],  # ISO timestamps for readability
                capture_output=True,
                text=True,
                timeout=10
            )
            all_lines = result.stdout.strip().split("\n")
            # Only keep the last 100 lines — earlier lines are usually not relevant
            lines = all_lines[-100:] if len(all_lines) > 100 else all_lines
        except FileNotFoundError:
            logger.warning("dmesg not found.")
        except Exception as e:
            logger.error(f"Error reading dmesg: {e}")
        return lines

    def _read_tcp_connections(self) -> list:
        """
        Read /proc/net/tcp to find active TCP connections.

        WHAT IS TCP?
          TCP (Transmission Control Protocol) is how computers communicate
          over a network. Each connection has a local address:port and a
          remote address:port.

        WHY DO WE CARE?
          Rootkits often "phone home" to a Command & Control (C2) server —
          a remote computer the attacker controls. This appears as an unusual
          outbound TCP connection on an unexpected port.

        /proc/net/tcp FORMAT (hex values):
          sl  local_address rem_address   st ...
          0:  0F02000A:0050 00000000:0000 0A ...
              ↑ local IP:port in hex     ↑ state (0A = LISTEN)

        Returns:
            list of dicts with decoded connection info
        """
        connections = []
        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()

            # Skip the header line
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue

                local_addr  = self._decode_address(parts[1])
                remote_addr = self._decode_address(parts[2])
                state_hex   = parts[3]

                # TCP state codes (hex): 01=ESTABLISHED, 0A=LISTEN, 06=TIME_WAIT, etc.
                STATE_MAP = {
                    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
                    "04": "FIN_WAIT1",   "05": "FIN_WAIT2","06": "TIME_WAIT",
                    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
                    "0A": "LISTEN",      "0B": "CLOSING"
                }
                state = STATE_MAP.get(state_hex.upper(), f"UNKNOWN({state_hex})")

                connections.append({
                    "local":  local_addr,
                    "remote": remote_addr,
                    "state":  state,
                })
        except PermissionError:
            logger.warning("Cannot read /proc/net/tcp. Try running as root.")
        except FileNotFoundError:
            logger.warning("/proc/net/tcp not found.")
        except Exception as e:
            logger.error(f"Error reading TCP connections: {e}")

        return connections

    def _decode_address(self, hex_addr: str) -> str:
        """
        Convert the hex address:port format used in /proc/net/tcp to human-readable form.

        Example: "0F02000A:0050" → "10.0.2.15:80"

        EXPLANATION:
          /proc/net/tcp stores IP addresses as 8-character hex in LITTLE-ENDIAN byte order.
          "0F02000A" in little-endian means the actual bytes are 0A, 00, 02, 0F
          which in decimal is 10.0.2.15 (standard IP address format).

        Args:
            hex_addr: string like "0F02000A:0050"

        Returns:
            string like "10.0.2.15:80"
        """
        try:
            ip_hex, port_hex = hex_addr.split(":")

            # Convert hex IP (little-endian) to dotted decimal
            # int(ip_hex, 16) converts hex string to integer with base 16
            ip_int = int(ip_hex, 16)
            # Unpack the 4 bytes in reverse order (little-endian → big-endian)
            byte1 = (ip_int >> 0)  & 0xFF
            byte2 = (ip_int >> 8)  & 0xFF
            byte3 = (ip_int >> 16) & 0xFF
            byte4 = (ip_int >> 24) & 0xFF
            ip_str = f"{byte1}.{byte2}.{byte3}.{byte4}"

            # Convert hex port to decimal
            port = int(port_hex, 16)

            return f"{ip_str}:{port}"
        except Exception:
            return hex_addr  # If decoding fails, return the raw value
