"""
makim/report_agent.py — Agent 5: The Report Agent
==================================================
WHAT IS THIS AGENT?
  The Report Agent is the "presentation layer" of MAKIM — it takes the raw
  findings from all previous agents and makes them human-readable.

  It does two things:
  1. TERMINAL OUTPUT: Prints a color-coded, formatted security report to your screen
  2. JSON FILE:       Saves a complete machine-readable report to disk

WHY BOTH?
  - The colored terminal output is for YOU (human) to read right now
  - The JSON file is for tools, logging systems, or future analysis scripts to read

ANSI COLOR CODES:
  Terminals support color via escape sequences — special character sequences
  that tell the terminal "change color to X".
  Format: \033[CODEm where CODE is a number.
  Example: \033[31m = red text, \033[0m = reset to default color
  We wrap these in helper constants so the code is readable.

SEVERITY → COLOR MAPPING:
  CRITICAL → bright red (most urgent)
  HIGH     → red
  MEDIUM   → yellow
  LOW      → cyan
  CLEAN    → green (no issues)
"""

import json
import logging
from datetime import datetime

logger = logging.getLogger("MAKIM.ReportAgent")


# ── ANSI color constants ────────────────────────────────────────────────────
# ANSI = American National Standards Institute — defined the terminal color spec
# \033 is the ESC character in octal (base-8) notation
# [Nm sets foreground color where N is the color code

class Color:
    """ANSI color codes as class constants."""
    RESET   = "\033[0m"     # Back to default color
    BOLD    = "\033[1m"     # Bold/bright
    RED     = "\033[31m"    # Red
    YELLOW  = "\033[33m"    # Yellow
    GREEN   = "\033[32m"    # Green
    CYAN    = "\033[36m"    # Cyan
    MAGENTA = "\033[35m"    # Magenta
    WHITE   = "\033[37m"    # White
    BRIGHT_RED = "\033[91m" # Bright red (more alarming than regular red)

# Map severity strings to their display colors
SEVERITY_COLORS = {
    "CRITICAL": Color.BRIGHT_RED,
    "HIGH":     Color.RED,
    "MEDIUM":   Color.YELLOW,
    "LOW":      Color.CYAN,
    "CLEAN":    Color.GREEN,
}

# Map threat levels to emoji indicators
THREAT_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "CLEAN":    "✅",
    "UNKNOWN":  "❓",
}


class ReportAgent:
    """
    Agent 5: Report Agent

    Renders the terminal report and saves the JSON output file.
    """

    def __init__(self, output_file: str = "makim_report.json"):
        """
        Args:
            output_file: Path to save the JSON report.
        """
        self.output_file = output_file
        logger.info(f"Report Agent initialized. Output file: {output_file}")

    def run(self, snapshot: dict, anomaly_result: dict,
            pattern_result: dict, llm_result: dict) -> dict:
        """
        Render the full report — terminal output + JSON file.

        Args:
            snapshot:       From ScannerAgent
            anomaly_result: From AnomalyDetector
            pattern_result: From RootkitPatternAgent
            llm_result:     From LLMAnalystAgent

        Returns:
            dict: The complete report data (same thing saved to JSON)
        """
        print("\n[Agent 5/5] Report Agent — Generating report...")

        # Determine the final threat level (use LLM result if available)
        threat_level = llm_result.get("threat_level", "UNKNOWN")

        # Build the complete report dict
        report = self._build_report_dict(
            snapshot, anomaly_result, pattern_result, llm_result, threat_level
        )

        # Print to terminal
        self._print_terminal_report(report)

        # Save JSON file
        self._save_json_report(report)

        # Trigger alert if high severity
        if threat_level in ("HIGH", "CRITICAL"):
            self._trigger_alert(report)

        return report

    # ── Report Building ────────────────────────────────────────────────────

    def _build_report_dict(self, snapshot, anomaly_result,
                           pattern_result, llm_result, threat_level) -> dict:
        """Build the complete report as a Python dictionary."""

        now = datetime.now()

        return {
            "makim_version": "1.0.0",
            "scan_timestamp": now.isoformat(),
            "scan_date_human": now.strftime("%A, %B %d %Y at %H:%M:%S"),

            # High-level assessment
            "threat_level":    threat_level,
            "threat_emoji":    THREAT_EMOJI.get(threat_level, "❓"),
            "confidence":      llm_result.get("confidence", "LOW"),

            # AI analysis
            "ai_summary":               llm_result.get("summary", "No AI analysis."),
            "ai_analysis":              llm_result.get("analysis", ""),
            "ai_false_positive_notes":  llm_result.get("false_positive_notes", ""),
            "remediation_steps":        llm_result.get("remediation_steps", []),
            "indicators_of_compromise": llm_result.get("indicators_of_compromise", []),
            "recommended_next_tools":   llm_result.get("recommended_next_tools", []),

            # System snapshot summary
            "system_summary": {
                "modules_loaded":    len(snapshot.get("modules_proc", [])),
                "processes_running": len(snapshot.get("processes", [])),
                "tcp_connections":   len(snapshot.get("tcp_connections", [])),
                "baseline_available": anomaly_result.get("baseline_available", False),
                "baseline_timestamp": anomaly_result.get("baseline_timestamp"),
            },

            # Anomaly detector results
            "anomaly_detection": {
                "anomaly_count":    anomaly_result.get("anomaly_count", 0),
                "overall_severity": anomaly_result.get("overall_severity", "CLEAN"),
                "anomalies":        anomaly_result.get("anomalies", []),
            },

            # Pattern agent results
            "pattern_detection": {
                "finding_count": pattern_result.get("finding_count", 0),
                "findings":      pattern_result.get("findings", []),
                "risk_indicators": pattern_result.get("risk_indicators", []),
            },

            # Raw data (for forensic purposes)
            "raw_modules": [m["name"] for m in snapshot.get("modules_proc", [])],
            "raw_tcp_connections": snapshot.get("tcp_connections", []),
        }

    # ── Terminal Output ────────────────────────────────────────────────────

    def _print_terminal_report(self, report: dict) -> None:
        """Print the full color-coded report to the terminal."""

        threat = report["threat_level"]
        color  = SEVERITY_COLORS.get(threat, Color.WHITE)
        emoji  = report.get("threat_emoji", "?")

        print("\n")
        print(f"{Color.BOLD}{'═' * 65}{Color.RESET}")
        print(f"{Color.BOLD}  MAKIM — Security Scan Report{Color.RESET}")
        print(f"  {report['scan_date_human']}")
        print(f"{'═' * 65}")

        # ── Threat Level Banner ────────────────────────────────────────────
        print(f"\n  {Color.BOLD}OVERALL THREAT LEVEL:{Color.RESET} "
              f"{color}{Color.BOLD}{emoji}  {threat}{Color.RESET} "
              f"(AI Confidence: {report['confidence']})")

        # ── System Overview ────────────────────────────────────────────────
        sys = report["system_summary"]
        print(f"\n{Color.BOLD}┌─ SYSTEM OVERVIEW {'─' * 45}┐{Color.RESET}")
        print(f"  Kernel Modules : {sys['modules_loaded']}")
        print(f"  Processes      : {sys['processes_running']}")
        print(f"  TCP Connections: {sys['tcp_connections']}")
        if sys["baseline_available"]:
            print(f"  Baseline Date  : {sys['baseline_timestamp']}")
        else:
            print(f"  Baseline       : {Color.YELLOW}NOT AVAILABLE{Color.RESET} "
                  f"(run with --baseline to create one)")

        # ── AI Summary ────────────────────────────────────────────────────
        print(f"\n{Color.BOLD}┌─ AI ANALYSIS (Claude) {'─' * 41}┐{Color.RESET}")
        print(f"  {report['ai_summary']}")

        if report["ai_analysis"] and report["ai_analysis"] != report["ai_summary"]:
            # Word-wrap the analysis at 62 characters per line
            self._print_wrapped(report["ai_analysis"], width=62, indent="  ")

        # ── Anomaly Detection Results ──────────────────────────────────────
        ad = report["anomaly_detection"]
        ad_color = SEVERITY_COLORS.get(ad["overall_severity"], Color.GREEN)

        print(f"\n{Color.BOLD}┌─ ANOMALY DETECTION ({ad['anomaly_count']} found) {'─' * 37}┐{Color.RESET}")

        if not ad["anomalies"]:
            print(f"  {Color.GREEN}✓ No anomalies detected{Color.RESET}")
        else:
            for a in ad["anomalies"]:
                sev_color = SEVERITY_COLORS.get(a["severity"], Color.WHITE)
                print(f"\n  {sev_color}[{a['severity']}]{Color.RESET} {a['type']}")
                self._print_wrapped(a["description"], width=60, indent="    ")

        # ── Pattern Detection Results ──────────────────────────────────────
        pd = report["pattern_detection"]
        print(f"\n{Color.BOLD}┌─ PATTERN DETECTION ({pd['finding_count']} found) {'─' * 38}┐{Color.RESET}")

        if not pd["findings"]:
            print(f"  {Color.GREEN}✓ No known rootkit patterns detected{Color.RESET}")
        else:
            for f in pd["findings"]:
                sev_color = SEVERITY_COLORS.get(f["severity"], Color.WHITE)
                print(f"\n  {sev_color}[{f['severity']}]{Color.RESET} {f['type']}")
                self._print_wrapped(f["description"], width=60, indent="    ")

        # ── Indicators of Compromise ───────────────────────────────────────
        iocs = report.get("indicators_of_compromise", [])
        if iocs:
            print(f"\n{Color.BOLD}┌─ INDICATORS OF COMPROMISE {'─' * 37}┐{Color.RESET}")
            for ioc in iocs:
                print(f"  {Color.RED}⚑ {ioc}{Color.RESET}")

        # ── Remediation Steps ──────────────────────────────────────────────
        steps = report.get("remediation_steps", [])
        if steps:
            print(f"\n{Color.BOLD}┌─ REMEDIATION STEPS {'─' * 44}┐{Color.RESET}")
            for i, step in enumerate(steps, 1):
                priority_color = Color.RED if i <= 2 else Color.YELLOW
                print(f"  {priority_color}[{i}]{Color.RESET} ", end="")
                self._print_wrapped(step, width=58, indent="      ", first_line_no_indent=True)

        # ── False Positive Notes ───────────────────────────────────────────
        fp_notes = report.get("ai_false_positive_notes", "")
        if fp_notes:
            print(f"\n{Color.BOLD}┌─ FALSE POSITIVE NOTES {'─' * 41}┐{Color.RESET}")
            self._print_wrapped(fp_notes, width=62, indent="  ")

        # ── Next Tools ────────────────────────────────────────────────────
        next_tools = report.get("recommended_next_tools", [])
        if next_tools:
            print(f"\n{Color.BOLD}┌─ RECOMMENDED NEXT TOOLS {'─' * 39}┐{Color.RESET}")
            print(f"  {', '.join(next_tools)}")

        # ── Footer ────────────────────────────────────────────────────────
        print(f"\n{Color.BOLD}{'═' * 65}{Color.RESET}")
        print(f"  Report saved to: {Color.CYAN}{self.output_file}{Color.RESET}")
        if threat in ("HIGH", "CRITICAL"):
            print(f"  {Color.BRIGHT_RED}{Color.BOLD}⚠ ALERT TRIGGERED — Immediate investigation recommended!{Color.RESET}")
        print(f"{'═' * 65}\n")

    def _print_wrapped(self, text: str, width: int = 62,
                       indent: str = "  ", first_line_no_indent: bool = False) -> None:
        """
        Word-wrap a long string to fit within `width` characters per line.

        Args:
            text:                 The text to wrap
            width:                Max characters per line
            indent:               Prefix added to each line (for alignment)
            first_line_no_indent: If True, the first line doesn't get the indent
        """
        # Split text into individual words
        words = text.split()
        lines = []
        current_line = []
        current_length = 0

        for word in words:
            # +1 for the space before the word
            if current_length + len(word) + 1 > width and current_line:
                lines.append(" ".join(current_line))
                current_line = [word]
                current_length = len(word)
            else:
                current_line.append(word)
                current_length += len(word) + 1

        if current_line:
            lines.append(" ".join(current_line))

        for i, line in enumerate(lines):
            if i == 0 and first_line_no_indent:
                print(line)
            else:
                print(f"{indent}{line}")

    # ── JSON File Output ───────────────────────────────────────────────────

    def _save_json_report(self, report: dict) -> None:
        """
        Save the complete report as a JSON file.

        JSON (JavaScript Object Notation) is a universal data format —
        any programming language can read it, and you can open it in any text editor.

        The file will contain all findings, AI analysis, timestamps, and raw data
        for later forensic review or integration with other security tools.
        """
        try:
            with open(self.output_file, "w") as f:
                # default=str converts non-serializable objects to strings
                # (some Python types like datetime can't normally be JSONified)
                json.dump(report, f, indent=2, default=str)
            print(f"   ✓ JSON report saved to: {self.output_file}")
        except IOError as e:
            logger.error(f"Failed to save JSON report: {e}")
            print(f"   ✗ Failed to save report: {e}")

    # ── Alert System ───────────────────────────────────────────────────────

    def _trigger_alert(self, report: dict) -> None:
        """
        Trigger an alert when threat level is HIGH or CRITICAL.

        In a production system, this might:
        - Send an email/SMS
        - Page an on-call engineer
        - Create a ticket in a ticketing system
        - Block network traffic via iptables

        For now, we print a prominent terminal warning and write an alert file.
        """
        threat = report["threat_level"]
        color  = SEVERITY_COLORS.get(threat, Color.RED)

        print(f"\n  {color}{Color.BOLD}")
        print("  ╔══════════════════════════════════════════════════╗")
        print(f"  ║  🚨 SECURITY ALERT: {threat} THREAT DETECTED 🚨  ║")
        print("  ║  Immediate investigation recommended!           ║")
        print("  ║  See remediation steps above.                   ║")
        print("  ╚══════════════════════════════════════════════════╝")
        print(Color.RESET)

        # Write an alert file that monitoring tools can pick up
        alert_file = "makim_ALERT.txt"
        try:
            with open(alert_file, "w") as f:
                f.write(f"MAKIM SECURITY ALERT\n")
                f.write(f"Threat Level: {threat}\n")
                f.write(f"Timestamp: {report['scan_timestamp']}\n")
                f.write(f"Summary: {report['ai_summary']}\n\n")
                f.write("Remediation Steps:\n")
                for i, step in enumerate(report.get("remediation_steps", []), 1):
                    f.write(f"  {i}. {step}\n")
            print(f"   ⚠ Alert file written to: {alert_file}")
        except IOError as e:
            logger.error(f"Failed to write alert file: {e}")
