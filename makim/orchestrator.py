"""
makim/orchestrator.py — The Orchestrator (Manager)
====================================================
WHAT IS THE ORCHESTRATOR?
  The Orchestrator is the "manager" that coordinates all 5 agents.
  It's the only module that knows about ALL agents — the agents themselves
  don't know about each other.

  Think of it like a conductor in an orchestra:
  - The conductor doesn't play instruments
  - But the conductor tells each musician WHEN to play and WHAT to play
  - The musicians focus on their single instrument
  - Together they make music

  MAKIM's Orchestrator:
  - Tells Agent 1 (Scanner) to collect system data
  - Passes that data to Agent 2 (Anomaly Detector) for comparison
  - Passes the snapshot to Agent 3 (Pattern Agent) for signature checking
  - Passes all findings to Agent 4 (LLM Analyst) for AI analysis
  - Passes everything to Agent 5 (Report Agent) to generate the report

DATA FLOW:
  Orchestrator
      │
      ▼
  [Agent 1: Scanner]  ──── snapshot ────────────────────────────────────┐
      │                                                                   │
      └── snapshot ──► [Agent 2: Anomaly Detector] ── anomaly_result ──┐ │
                                                                        │ │
      └── snapshot ──► [Agent 3: Pattern Agent]    ── pattern_result ──┤ │
                                                                        │ │
                       [Agent 4: LLM Analyst] ◄──────────────────────  │ │
                           (uses all three)                             │ │
                                │                                       │ │
                                └── llm_result ──────────────────────► │ │
                                                                        │ │
                       [Agent 5: Report Agent] ◄── all results ────────┘ │
                           (uses everything)                              │
                                │                                         │
                                └── final_report ◄────────────────────────┘
"""

import logging
import sys

# Import all our agents
from makim.scanner_agent import ScannerAgent
from makim.anomaly_detector import AnomalyDetector
from makim.rootkit_pattern_agent import RootkitPatternAgent
from makim.llm_analyst_agent import LLMAnalystAgent
from makim.report_agent import ReportAgent
from makim.live_sentinel_agent import LiveSentinelAgent

# Configure logging for the whole application
# logging.basicConfig sets up the logging system globally
# format: what each log line looks like
# level: minimum level to show (DEBUG < INFO < WARNING < ERROR < CRITICAL)
logging.basicConfig(
    format  = "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt = "%Y-%m-%d %H:%M:%S",
    level   = logging.WARNING,   # Only show WARNING and above in normal operation
                                  # Change to logging.DEBUG for very verbose output
)

logger = logging.getLogger("MAKIM.Orchestrator")


class Orchestrator:
    """
    The Orchestrator — coordinates all MAKIM agents.

    This is the only class that main.py directly uses.
    Everything else flows from here.
    """

    def __init__(self, api_key: str = None, output_file: str = "makim_report.json"):
        """
        Initialize all 5 agents.

        Args:
            api_key:    OpenRouter API key for LLM analysis (can be None)
            output_file: Path to save the JSON report
        """
        logger.info("Orchestrator initializing all agents...")

        # Create one instance of each agent
        self.scanner         = ScannerAgent()
        self.anomaly_detector= AnomalyDetector()
        self.pattern_agent   = RootkitPatternAgent()
        self.llm_analyst     = LLMAnalystAgent(api_key=api_key)
        self.report_agent    = ReportAgent(output_file=output_file)

        logger.info("All agents initialized successfully.")

    def capture_baseline(self) -> None:
        """
        Baseline capture mode (run with --baseline flag).

        STEPS:
        1. Run the Scanner to collect current system state
        2. Save that state as the trusted baseline
        3. Exit (no analysis needed in baseline mode)
        """
        print("\n  Step 1: Running Scanner to collect system state...")
        snapshot = self.scanner.run()

        print("\n  Step 2: Saving as trusted baseline...")
        self.anomaly_detector.save_baseline(snapshot)

        print("\n  ✓ Baseline capture complete!")
        print("  Next time, run without --baseline to detect anomalies vs this snapshot.")

    def run_live_sentinel(self, duration: int = 20) -> dict:
        """
        Live eBPF mode.

        This mode runs the optional Agent 6. It watches selected kernel events
        in real time using bpftrace when the host supports it.
        """
        print("\n  Starting live eBPF runtime monitoring...")
        live_agent = LiveSentinelAgent(duration=duration)
        return live_agent.run()

    def run(self) -> dict:
        """
        Full scan mode — run all 5 agents in sequence.

        This is the main workflow of MAKIM.

        Returns:
            dict: The final report (also saved to disk and printed to terminal)
        """
        print("\n  Starting 5-agent scan pipeline...")
        print("  " + "─" * 50)

        # ── Agent 1: Collect data ──────────────────────────────────────────
        # The Scanner reads from /proc and runs system commands
        # Result: a dictionary of raw system state data
        try:
            snapshot = self.scanner.run()
        except Exception as e:
            # If the scanner completely fails, we can't continue
            logger.critical(f"Scanner Agent failed: {e}")
            print(f"\n[FATAL] Scanner Agent crashed: {e}")
            print("Cannot continue without system data.")
            sys.exit(2)

        # ── Agent 2: Compare against baseline ─────────────────────────────
        # If no baseline exists, this will only run DKOM checks
        try:
            anomaly_result = self.anomaly_detector.run(snapshot)
        except Exception as e:
            logger.error(f"Anomaly Detector failed: {e}")
            print(f"\n[ERROR] Anomaly Detector crashed: {e}")
            # Provide an empty result so the pipeline can continue
            anomaly_result = {
                "anomalies": [],
                "anomaly_count": 0,
                "overall_severity": "UNKNOWN",
                "baseline_available": False,
                "baseline_timestamp": None,
                "error": str(e),
            }

        # ── Agent 3: Check known patterns ─────────────────────────────────
        try:
            pattern_result = self.pattern_agent.run(snapshot)
        except Exception as e:
            logger.error(f"Pattern Agent failed: {e}")
            print(f"\n[ERROR] Pattern Agent crashed: {e}")
            pattern_result = {
                "findings": [],
                "finding_count": 0,
                "risk_indicators": [],
                "error": str(e),
            }

        # ── Agent 4: AI analysis ───────────────────────────────────────────
        try:
            llm_result = self.llm_analyst.run(anomaly_result, pattern_result, snapshot)
        except Exception as e:
            logger.error(f"LLM Analyst failed: {e}")
            print(f"\n[ERROR] LLM Analyst crashed: {e}")
            llm_result = {
                "threat_level": "UNKNOWN",
                "confidence": "LOW",
                "summary": f"AI analysis failed: {e}",
                "analysis": "",
                "remediation_steps": ["AI analysis failed — manual review required."],
                "false_positive_notes": "",
                "indicators_of_compromise": [],
                "recommended_next_tools": [],
            }

        # ── Agent 5: Generate report ───────────────────────────────────────
        # This always runs — even if earlier agents failed, we want some output
        try:
            final_report = self.report_agent.run(
                snapshot       = snapshot,
                anomaly_result = anomaly_result,
                pattern_result = pattern_result,
                llm_result     = llm_result,
            )
        except Exception as e:
            logger.critical(f"Report Agent failed: {e}")
            print(f"\n[FATAL] Report Agent crashed: {e}")
            print("Raw threat level:", llm_result.get("threat_level", "UNKNOWN"))
            sys.exit(3)

        return final_report
