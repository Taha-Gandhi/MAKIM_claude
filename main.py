"""
main.py — Entry Point for MAKIM
================================
This is the file you run to start MAKIM.
Think of it as the "front door" of the program.

HOW TO RUN:
  sudo python main.py              # Full scan (recommended)
  sudo python main.py --baseline   # Save a new trusted baseline snapshot
  python main.py                   # Limited scan (no root access)

WHAT IT DOES:
  1. Checks you're on Linux
  2. Warns if you're not root (some /proc files need root)
  3. Reads your ANTHROPIC_API_KEY from environment
  4. Hands control to the Orchestrator which runs all 5 agents
"""

import sys
import os
import argparse  # argparse lets us accept --flags when running the script

# Import our Orchestrator (the "manager" that coordinates all agents)
from makim.orchestrator import Orchestrator


def main():
    # ── 1. Parse command-line arguments ────────────────────────────────────
    # argparse reads the words after "python main.py" on the command line
    parser = argparse.ArgumentParser(
        description="MAKIM — Multi-Agent Kernel Integrity Monitor",
        epilog="Example: sudo python main.py --baseline"
    )
    parser.add_argument(
        "--baseline",
        action="store_true",   # This means --baseline is a flag (True/False), not a value
        help="Capture a new trusted baseline snapshot of your system and exit"
    )
    parser.add_argument(
        "--output",
        default="makim_report.json",
        help="Path to save the JSON report (default: makim_report.json)"
    )
    args = parser.parse_args()

    # ── 2. Print a welcome banner ───────────────────────────────────────────
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║        MAKIM — Multi-Agent Kernel Integrity Monitor          ║")
    print("║        Linux Rootkit Detection via AI Agents                 ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print()

    # ── 3. Make sure we're on Linux ────────────────────────────────────────
    # sys.platform is a string like "linux", "darwin" (macOS), or "win32"
    if sys.platform != "linux":
        print(f"[ERROR] MAKIM only works on Linux. Detected platform: {sys.platform}")
        sys.exit(1)  # Exit with error code 1

    # ── 4. Warn if not running as root ─────────────────────────────────────
    # os.geteuid() returns 0 if you are root (the super-user), else your user ID
    if os.geteuid() != 0:
        print("[WARNING] Not running as root. Some /proc files will be unreadable.")
        print("          For a full scan, run: sudo python main.py")
        print()

    # ── 5. Read the Claude API key from environment variable ───────────────
    # os.environ is a dictionary of all environment variables set in your shell
    # You set it beforehand with: export ANTHROPIC_API_KEY='sk-ant-...'
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[WARNING] ANTHROPIC_API_KEY environment variable not found.")
        print("          LLM (AI) analysis will be skipped.")
        print("          To enable: export ANTHROPIC_API_KEY='your-api-key-here'")
        print()

    # ── 6. Create the Orchestrator and run it ──────────────────────────────
    # The Orchestrator is the "manager" that coordinates all 5 agents.
    orchestrator = Orchestrator(
        api_key=api_key,
        output_file=args.output
    )

    if args.baseline:
        # --baseline mode: just capture a clean snapshot and save it
        print("[MODE] Baseline capture — saving trusted system snapshot...")
        orchestrator.capture_baseline()
        print("[DONE] Baseline saved. Run without --baseline next time to detect anomalies.")
    else:
        # Normal mode: full scan with all 5 agents
        print("[MODE] Full scan — running all 5 agents...")
        orchestrator.run()


# This special check means: only run main() if THIS file is the one being executed.
# If another file imports main.py, main() won't run automatically.
if __name__ == "__main__":
    main()
