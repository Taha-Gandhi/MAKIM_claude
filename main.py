"""
main.py — Entry Point for MAKIM
================================
This is the file you run to start MAKIM.
Think of it as the "front door" of the program.

HOW TO RUN:
  sudo -E python3 main.py             # Full scan (recommended)
  sudo -E python3 main.py --baseline   # Save a new trusted baseline snapshot
  sudo -E python3 main.py --live       # Watch live kernel events with eBPF/bpftrace
  python3 main.py --demo-activity      # Trigger safe events for a live demo
  python main.py                   # Limited scan (no root access)

WHAT IT DOES:
  1. Checks you're on Linux
  2. Warns if you're not root (some /proc files need root)
  3. Reads your OPENROUTER_API_KEY from environment
  4. Hands control to the Orchestrator which runs the agents
"""

import sys
import os
import argparse  # argparse lets us accept --flags when running the script

# Import our Orchestrator (the "manager" that coordinates all agents)
from makim.orchestrator import Orchestrator
from makim.demo_activity import run_demo_activity
from makim.live_sentinel_agent import LiveSentinelAgent


def main():
    # ── 1. Parse command-line arguments ────────────────────────────────────
    # argparse reads the words after "python main.py" on the command line
    parser = argparse.ArgumentParser(
        description="MAKIM — Multi-Agent Kernel Integrity Monitor",
        epilog="Example: sudo -E python3 main.py --baseline"
    )
    parser.add_argument(
        "--baseline",
        action="store_true",   # This means --baseline is a flag (True/False), not a value
        help="Capture a new trusted baseline snapshot of your system and exit"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run Agent 6 live eBPF/bpftrace monitoring mode"
    )
    parser.add_argument(
        "--live-duration",
        type=int,
        default=20,
        help="Seconds to run --live monitoring (default: 20)"
    )
    parser.add_argument(
        "--demo-activity",
        action="store_true",
        help="Trigger harmless events that Agent 6 can capture during a live demo"
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

    if args.demo_activity:
        # Demo activity mode: run harmless activity in a second terminal while --live watches.
        print("[MODE] Demo Activity — triggering safe observable events...")
        run_demo_activity()
        return

    # ── 4. Warn if not running as root ─────────────────────────────────────
    # os.geteuid() returns 0 if you are root (the super-user), else your user ID
    if os.geteuid() != 0:
        print("[WARNING] Not running as root. Some /proc files will be unreadable.")
        print("          For a full scan, run: sudo -E python3 main.py")
        print()

    if args.live:
        # Live mode only needs Agent 6, so do not initialize the full LLM scan pipeline.
        print("[MODE] Live Sentinel — watching runtime kernel events...")
        print("\n  Starting live eBPF runtime monitoring...")
        LiveSentinelAgent(duration=args.live_duration).run()
        return

    # ── 5. Read the OpenRouter API key from environment variable ───────────
    # os.environ is a dictionary of all environment variables set in your shell
    # You set it beforehand with: export OPENROUTER_API_KEY='your-key'
    api_key = os.environ.get("OPENROUTER_API_KEY")

    if not api_key:
        print("[WARNING] OPENROUTER_API_KEY environment variable not found.")
        print("          LLM analysis will use local rule-based fallback.")
        print("          To enable OpenRouter:")
        print("          export OPENROUTER_API_KEY='your-openrouter-key'")
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
