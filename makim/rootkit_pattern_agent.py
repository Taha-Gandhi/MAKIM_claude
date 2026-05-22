"""
makim/rootkit_pattern_agent.py — Agent 3: The Rootkit Pattern Agent
===================================================================
WHAT IS THIS AGENT?
  This agent doesn't compare against a baseline — instead, it knows about
  SPECIFIC patterns and signatures that rootkits commonly exhibit.

  Think of it as a specialist with a checklist of "known red flags":
    ☐ Is any loaded module named suspiciously?
    ☐ Are there anonymous executable memory regions? (classic shellcode hiding trick)
    ☐ Did the kernel log "tainted" warnings?
    ☐ Are any known C2 (Command & Control) ports open?
    ☐ Are there signs of syscall table tampering?

  Unlike the Anomaly Detector (which needs a baseline), this agent can detect
  threats even on a fresh scan with no prior history.

KEY CONCEPTS:
  Anonymous Executable Mapping:
    Normal programs load code from FILES (like /usr/bin/bash).
    Shellcode — malicious code injected at runtime — often lives in
    ANONYMOUS memory regions (no file backing), and is marked EXECUTABLE.
    Finding [anon] memory marked as executable (rwx or --x) is very suspicious.

  Kernel Taint:
    When the kernel detects something unusual (like an unsigned module, or
    a kernel OOPS — a non-fatal kernel error), it sets a "taint flag".
    /proc/sys/kernel/tainted stores a bitmask of which taints are active.
    Non-zero taint + unusual modules = suspicious.

  Suspicious Module Names:
    Rootkits often use names that mimic legitimate kernel modules:
    "kworker_helper", "sys_monitor", "netfilter_ext"
    Or they use random-looking names: "xyzzy", "a1b2c3"

  Known C2 Ports:
    Common ports used by malware for remote access:
    31337 (elite), 4444 (Metasploit default), 1337, 12345, 54321, etc.
"""

import re
import subprocess
import logging
from makim.config_loader import ConfigLoader

logger = logging.getLogger("MAKIM.RootkitPattern")


class RootkitPatternAgent:
    """
    Agent 3: Rootkit Pattern Agent

    Checks for known rootkit indicators using heuristics and pattern matching.
    Does NOT require a baseline.
    """

    # ── Pattern Databases ──────────────────────────────────────────────────
    # These are Python class-level constants (shared by all instances of the class)

    # Known suspicious module name patterns (regex)
    # regex = Regular Expression — a pattern-matching language for strings
    SUSPICIOUS_MODULE_PATTERNS = [
        r"^hide",        # starts with "hide"
        r"^rootkit",     # starts with "rootkit"
        r"^rk_",         # starts with "rk_"
        r"^hook",        # starts with "hook"
        r"keylog",       # contains "keylog" (keylogger)
        r"backdoor",     # contains "backdoor"
        r"stealth",      # contains "stealth"
        r"^xyzzy",       # classic rootkit test name
        r"syscall_hook", # explicit syscall hooking
        r"dkom",         # explicit DKOM name
    ]

    # C2 (Command & Control) ports commonly used by malware
    # These ports have little legitimate use and are known malware favorites
    SUSPICIOUS_PORTS = {
        4444,   # Metasploit default listener
        4445,   # Metasploit variant
        5555,   # Android debug bridge (ADB) — often abused
        31337,  # "eleet" — traditional hacker port
        1337,   # "leet" — traditional hacker port
        12345,  # Generic backdoor
        54321,  # Generic backdoor (reversed)
        6666,   # Common malware port
        6667,   # IRC — used by bot herders for C2
        6668,   # IRC variant
        6669,   # IRC variant
        1234,   # Common test/malware port
        9999,   # Common backdoor
        65535,  # Max port — sometimes used to avoid detection
        7777,   # Common malware
        8888,   # Common malware / C2 panel
        2222,   # Alt SSH — sometimes used by rootkits
    }

    # Known legitimate module name prefixes (to reduce false positives)
    KNOWN_LEGIT_PREFIXES = {
        "ext4", "btrfs", "xfs", "nfs", "fat", "vfat", "ntfs",  # filesystems
        "nvidia", "amdgpu", "i915", "radeon",                    # GPU drivers
        "bluetooth", "bnep", "rfcomm",                           # Bluetooth
        "usb", "usbcore", "xhci", "ehci",                       # USB
        "net", "ip6", "ipv6", "ipv4", "tcp",                    # Networking
        "kvm", "vmware", "vbox", "virtio",                      # Virtualization
        "dm_", "md_", "raid",                                    # Storage
        "crypto", "aes", "sha",                                  # Crypto
        "drm", "fbdev",                                          # Display
        "snd_", "sound",                                         # Audio
        "input", "hid",                                          # Input devices
        "ata", "ahci", "nvme", "scsi",                          # Storage controllers
        "e1000", "igb", "ixgbe", "r8169", "rtl",               # Network drivers
    }

    def __init__(self):
        self.allowlist = ConfigLoader.load_allowlist()
        logger.info("Rootkit Pattern Agent initialized.")

    def run(self, snapshot: dict) -> dict:
        """
        Run all pattern checks against the current snapshot.

        Args:
            snapshot: The dict returned by ScannerAgent.run()

        Returns:
            dict with:
              "findings": list of finding dicts
              "risk_indicators": list of high-level risk summaries
        """
        print("\n[Agent 3/5] Rootkit Pattern Agent — Checking known indicators...")

        findings = []

        findings += self._check_suspicious_module_names(snapshot)
        findings += self._check_anon_executable_mappings(snapshot)
        findings += self._check_dmesg_patterns(snapshot)
        findings += self._check_kernel_taint()
        findings += self._check_c2_ports(snapshot)
        findings += self._check_suspicious_processes(snapshot)

        count = len(findings)
        if count == 0:
            print("   ✓ No known rootkit patterns detected")
        else:
            print(f"   ⚠ {count} suspicious pattern(s) found")

        return {
            "findings":        findings,
            "finding_count":   count,
            "risk_indicators": self._summarize_risks(findings),
        }

    # ── Check Methods ──────────────────────────────────────────────────────

    def _check_suspicious_module_names(self, snapshot: dict) -> list:
        """
        Check loaded module names against known suspicious patterns.

        We use regex (regular expressions) for flexible pattern matching.
        re.search(pattern, string) returns a match object if pattern is found,
        or None if not found. So `if re.search(...)` means "if a match was found".
        """
        findings = []
        modules = snapshot.get("modules_proc", [])

        for module in modules:
            name = module["name"]

            # Skip modules whose names start with known-legitimate prefixes
            is_legit = any(name.lower().startswith(prefix)
                           for prefix in self.KNOWN_LEGIT_PREFIXES)
            if is_legit:
                continue

            # Check against suspicious patterns
            for pattern in self.SUSPICIOUS_MODULE_PATTERNS:
                # re.IGNORECASE makes the pattern case-insensitive
                if re.search(pattern, name, re.IGNORECASE):
                    findings.append({
                        "type":        "SUSPICIOUS_MODULE_NAME",
                        "severity":    "HIGH",
                        "description": f"Module '{name}' matches suspicious pattern '{pattern}'. "
                                       f"Rootkits often disguise themselves as kernel modules.",
                        "details":     {"module": module, "matched_pattern": pattern},
                    })
                    break  # Don't double-report the same module

        return findings

    def _check_anon_executable_mappings(self, snapshot: dict) -> list:
        """
        Scan /proc/[PID]/maps for anonymous executable memory regions.

        WHAT IS /proc/[PID]/maps?
          It shows the memory layout of a process — what code/data is loaded where.
          Each line looks like:
            7f3a4b000000-7f3a4b001000 r-xp 00000000 08:01 12345  /usr/lib/libc.so.6
            ↑ address range          ↑ permissions                ↑ file (or empty=anon)

          Permissions: r=read, w=write, x=execute, p=private, s=shared
          r-xp = readable + executable + private (normal for code)
          rwxp = readable + writable + executable (very suspicious — shellcode?)

          If the last field (filename) is empty or "[anon]", the memory region
          has no file backing it — it was allocated at runtime.
          An anonymous executable region is a classic sign of injected shellcode.
        """
        findings = []
        processes = snapshot.get("processes", [])

        for proc in processes:
            pid = proc["pid"]
            maps_path = f"/proc/{pid}/maps"

            try:
                with open(maps_path, "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) < 5:
                            continue

                        permissions = parts[1]  # e.g. "rwxp" or "r-xp"
                        # The filename is the last part, or empty for anonymous mappings
                        filename = parts[5] if len(parts) >= 6 else ""

                        # Is this an executable anonymous mapping?
                        is_executable = "x" in permissions
                        is_anonymous  = (filename == "" or
                                        filename.startswith("[anon") or
                                        filename == "[heap]")

                        # [stack] and [vdso] are normal anonymous executable regions
                        is_normal_anon = filename in ("[stack]", "[vdso]", "[vsyscall]",
                                                      "[vvar]", "[heap]")
                        allowed_memory_processes = self.allowlist.get("allowed_memory_processes", [])

                        if any(proc["name"].startswith(name) for name in allowed_memory_processes):
                            continue
                        
                        if is_executable and is_anonymous and not is_normal_anon:
                            
                            severity = "HIGH" if "w" in permissions else "MEDIUM"

                            findings.append({
                                "type":        "ANON_EXECUTABLE_MAPPING",
                                "severity":    severity,
                                "description": f"Process '{proc['name']}' (PID {pid}) has an anonymous "
                                            f"executable memory region ({permissions}). "
                                            f"Writable + executable memory is more suspicious than "
                                            f"readable + executable memory.",
                                "details": {
                                    "pid":         pid,
                                    "process":     proc["name"],
                                    "address":     parts[0],
                                    "permissions": permissions,
                                    "region":      filename or "[anonymous]",
                                },
                            })
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue  # Process may have ended or be unreadable — that's OK
            except Exception as e:
                logger.debug(f"Error reading maps for PID {pid}: {e}")

        return findings

    def _check_dmesg_patterns(self, snapshot: dict) -> list:
        """
        Search the kernel log (dmesg) for suspicious keywords.

        Rootkits sometimes leave traces in the kernel log:
        - "hiding" — rootkit explicitly logs its own behavior (during testing)
        - "taint" — kernel detected something unusual
        - Suspicious module names in load messages
        """
        findings = []

        # Keywords that suggest rootkit activity in kernel logs
        SUSPICIOUS_DMESG_KEYWORDS = [
            "rootkit",
            "hiding process",
            "hiding module",
            "syscall table modified",
            "system call table",
            "hooked",
            "injected",
            "malicious",
        ]

        dmesg_lines = snapshot.get("dmesg_tail", [])

        for line in dmesg_lines:
            line_lower = line.lower()
            for keyword in SUSPICIOUS_DMESG_KEYWORDS:
                if keyword in line_lower:
                    findings.append({
                        "type":        "SUSPICIOUS_DMESG",
                        "severity":    "HIGH",
                        "description": f"Kernel log contains suspicious keyword '{keyword}'.",
                        "details":     {"keyword": keyword, "log_line": line.strip()},
                    })
                    break  # Don't double-report the same line

        return findings

    def _check_kernel_taint(self) -> list:
        """
        Read /proc/sys/kernel/tainted to check if the kernel has been "tainted".

        WHAT IS KERNEL TAINT?
          The Linux kernel tracks unusual events using a bitmask (a number where
          each bit represents a different type of unusual event).

          Common taint flags:
          Bit 0  (value 1):   Proprietary module loaded (e.g., closed-source drivers) — NORMAL
          Bit 1  (value 2):   Module was force-loaded (dangerous, bypass of checks)
          Bit 4  (value 16):  Machine check exception occurred
          Bit 12 (value 4096): Module was loaded despite signature verification failure
          Bit 13 (value 8192): Out-of-tree (not upstream Linux) module loaded

          A taint value of 0 means the kernel is clean.
          Non-zero taint is normal on many systems (proprietary GPU drivers, etc.)
          but combined with other findings, it's significant.
        """
        findings = []

        try:
            with open("/proc/sys/kernel/tainted", "r") as f:
                taint_value = int(f.read().strip())

            if taint_value == 0:
                return findings  # Clean — no taint

            # Decode the bitmask
            # A bitmask works like binary flags: bit 0 = 1, bit 1 = 2, bit 2 = 4, etc.
            TAINT_FLAGS = {
                1:     "Proprietary module (G)",
                2:     "Module force-loaded (F) — SUSPICIOUS",
                8:     "ACPI table overridden (A)",
                16:    "Machine check exception (M)",
                32:    "Bad page referenced (B)",
                64:    "Requested by userspace (U)",
                128:   "Die-on-oops called (D)",
                256:   "ACPI error (A)",
                512:   "Kernel warning (W)",
                1024:  "Module from staging tree (C)",
                2048:  "Unsigned module (E) — SUSPICIOUS",
                4096:  "Soft lockup detected (L)",
                8192:  "Out-of-tree module (O) — SUSPICIOUS",
                16384: "Externally built module (X)",
                32768: "Kernel died recently (T)",
            }

            active_taints = []
            for bit_value, description in TAINT_FLAGS.items():
                # Bitwise AND (&) checks if a specific bit is set
                # If (taint_value & bit_value) != 0, that bit is active
                if taint_value & bit_value:
                    active_taints.append(description)

            # Only flag as suspicious if unusual taints are present
            suspicious_taints = [t for t in active_taints
                                  if "SUSPICIOUS" in t or "Unsigned" in t or "force" in t]

            severity = "HIGH" if suspicious_taints else "LOW"
            findings.append({
                "type":        "KERNEL_TAINT",
                "severity":    severity,
                "description": f"Kernel taint value: {taint_value}. "
                               f"Active flags: {', '.join(active_taints)}. "
                               + ("Suspicious taints detected!" if suspicious_taints else
                                  "These taints may be from normal proprietary drivers."),
                "details":     {
                    "taint_value":     taint_value,
                    "active_flags":    active_taints,
                    "suspicious":      suspicious_taints,
                },
            })

        except FileNotFoundError:
            logger.warning("/proc/sys/kernel/tainted not found.")
        except Exception as e:
            logger.error(f"Error reading kernel taint: {e}")

        return findings

    def _check_c2_ports(self, snapshot: dict) -> list:
        """
        Check if any active TCP connections use known C2 (Command & Control) ports.

        C2 PORTS:
          When malware establishes a connection back to the attacker's server,
          it often uses well-known "hacker" ports. Seeing your system connected
          to or listening on port 4444 (Metasploit) or 31337 ("eleet") is a
          significant red flag.
        """
        findings = []
        connections = snapshot.get("tcp_connections", [])

        for conn in connections:
            if conn["state"] not in ("ESTABLISHED", "LISTEN"):
                continue

            # Check both local and remote ports
            for addr_type, addr_str in [("local", conn["local"]), ("remote", conn["remote"])]:
                try:
                    port = int(addr_str.split(":")[-1])
                except (ValueError, IndexError):
                    continue

                if port in self.SUSPICIOUS_PORTS:
                    findings.append({
                        "type":        "SUSPICIOUS_PORT",
                        "severity":    "HIGH",
                        "description": f"TCP connection uses known C2 port {port} "
                                       f"({addr_type} side, state: {conn['state']}). "
                                       f"Port {port} is commonly used by malware/rootkits.",
                        "details":     {
                            "connection": conn,
                            "suspicious_port": port,
                            "address_type": addr_type,
                        },
                    })

        return findings

    def _check_suspicious_processes(self, snapshot: dict) -> list:
        """
        Check for processes with suspicious characteristics:
        - Processes pretending to be kernel threads (names with brackets like [kworker/0])
          but NOT actually kernel threads (PPID should be 2 for real kernel threads)
        - Processes with numeric-only names (common malware evasion)
        - Processes with blank/whitespace-only names
        """
        findings = []
        processes = snapshot.get("processes", [])

        for proc in processes:
            name  = proc.get("name", "")
            pid   = proc.get("pid", 0)
            ppid  = proc.get("ppid", 0)

            # Skip PID 0, 1, 2 (swapper, init, kthreadd — always special)
            if pid <= 2:
                continue

            # Check 1: Fake kernel thread name (brackets) but wrong parent
            # Real kernel threads have PPID=2 (kthreadd)
            if name.startswith("[") and name.endswith("]") and ppid != 2:
                findings.append({
                    "type":        "FAKE_KERNEL_THREAD",
                    "severity":    "HIGH",
                    "description": f"Process '{name}' (PID {pid}) has a kernel-thread-style name "
                                   f"(brackets) but its parent is PID {ppid} instead of 2 (kthreadd). "
                                   f"Real kernel threads always have PPID=2. This may be a rootkit "
                                   f"impersonating a kernel thread.",
                    "details":     proc,
                })

            # Check 2: Purely numeric process name (unusual — processes are named by executable)
            if name.isdigit():
                findings.append({
                    "type":        "NUMERIC_PROCESS_NAME",
                    "severity":    "MEDIUM",
                    "description": f"Process has numeric-only name '{name}' (PID {pid}). "
                                   f"This is unusual — normal processes are named after executables.",
                    "details":     proc,
                })

            # Check 3: Empty or whitespace-only name
            if not name.strip():
                findings.append({
                    "type":        "BLANK_PROCESS_NAME",
                    "severity":    "MEDIUM",
                    "description": f"Process PID {pid} has a blank or whitespace-only name. "
                                   f"Some rootkits clear the process name to hide their identity.",
                    "details":     proc,
                })

        return findings

    def _summarize_risks(self, findings: list) -> list:
        """
        Create a short list of high-level risk descriptions for the report.
        """
        summaries = []
        types_seen = set()

        for f in findings:
            ftype = f["type"]
            if ftype not in types_seen:
                types_seen.add(ftype)
                summaries.append(f["description"][:120] + "...")  # Truncate to 120 chars

        return summaries
