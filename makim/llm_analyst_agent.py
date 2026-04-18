"""
makim/llm_analyst_agent.py — Agent 4: The LLM Analyst
=======================================================
WHAT IS THIS AGENT?
  This agent is the "brain" of MAKIM. It takes all the raw findings from
  Agents 1-3 and sends them to Claude (via the Anthropic API) for intelligent,
  contextual analysis.

  Instead of just listing "NEW_MODULE detected", Claude can reason:
  "The module 'netfilter_evil' appeared 3 hours after the system started, is
  not a standard kernel module, has suspicious memory access patterns, and
  coincides with new outbound connections on port 31337. This strongly suggests
  a network-level rootkit. Recommended action: isolate the system immediately."

HOW DOES THE ANTHROPIC API WORK?
  You send Claude a text message (called a "prompt") via HTTP POST request.
  Claude reads it and sends back a response text.

  Your message includes:
  - A "system prompt" (background instructions for Claude)
  - A "user message" (the actual data you want analyzed)

  The API costs money per request (measured in "tokens" — roughly 1 word = 1 token).
  We minimize API calls by sending all findings in ONE request.

WHAT IF THERE'S NO API KEY?
  The agent gracefully degrades — it skips the API call and returns a
  "manual review needed" message instead of crashing.
"""

import json
import logging
import urllib.request  # urllib is Python's built-in HTTP library (no pip install needed)
import urllib.error

logger = logging.getLogger("MAKIM.LLMAnalyst")

# The Anthropic API endpoint — this URL receives our JSON request
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"

# We use claude-sonnet-4-20250514 as specified in your assignment
MODEL = "claude-sonnet-4-20250514"

# System prompt: background instructions that tell Claude its role
# This is sent with EVERY request to give Claude context
SYSTEM_PROMPT = """You are MAKIM's LLM Analyst — a kernel security expert embedded in a 
Linux rootkit detection system. You receive structured findings from automated security agents 
(anomaly detectors and pattern scanners) and must:

1. ANALYZE the findings holistically — look for patterns and correlations across multiple anomalies
2. ASSESS the overall threat level: CLEAN / LOW / MEDIUM / HIGH / CRITICAL
3. EXPLAIN your reasoning in plain English (the user may not be a security expert)
4. PROVIDE specific remediation steps ordered by priority
5. IDENTIFY false positive likelihood (some findings are normal system behavior)

Your response must be a valid JSON object with this exact structure:
{
  "threat_level": "CLEAN|LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": "LOW|MEDIUM|HIGH",
  "summary": "2-3 sentence executive summary of findings",
  "analysis": "Detailed analysis explaining what you found and why it is or isn't suspicious",
  "false_positive_notes": "Which findings are likely false positives and why",
  "remediation_steps": [
    "Step 1: Most urgent action",
    "Step 2: Second action",
    ...
  ],
  "indicators_of_compromise": ["list of specific IOCs found"],
  "recommended_next_tools": ["rkhunter", "volatility3", etc. — what to run next]
}

Return ONLY the JSON object. No markdown, no backticks, no explanation outside the JSON."""


class LLMAnalystAgent:
    """
    Agent 4: LLM Analyst Agent

    Sends aggregated findings to Claude API for intelligent contextual analysis.
    Gracefully handles missing API keys.
    """

    def __init__(self, api_key: str = None):
        """
        Args:
            api_key: Your Anthropic API key (starts with "sk-ant-...")
                     If None, LLM analysis is skipped.
        """
        self.api_key = api_key
        if api_key:
            logger.info("LLM Analyst initialized with API key.")
        else:
            logger.warning("LLM Analyst initialized WITHOUT API key — will skip AI analysis.")

    def run(self, anomaly_result: dict, pattern_result: dict, snapshot: dict) -> dict:
        """
        Analyze all findings using Claude API.

        Args:
            anomaly_result: Dict returned by AnomalyDetector.run()
            pattern_result: Dict returned by RootkitPatternAgent.run()
            snapshot:       Dict returned by ScannerAgent.run() (for system context)

        Returns:
            dict with Claude's analysis, or a fallback result if no API key.
        """
        print("\n[Agent 4/5] LLM Analyst — Sending findings to Claude API...")

        if not self.api_key:
            print("   ⚠ No API key — skipping AI analysis")
            return self._no_api_fallback(anomaly_result, pattern_result)

        # ── Build the prompt ───────────────────────────────────────────────
        # We format all findings into a structured text that Claude can understand
        prompt = self._build_prompt(anomaly_result, pattern_result, snapshot)

        # ── Call the API ───────────────────────────────────────────────────
        try:
            raw_response = self._call_api(prompt)
            analysis = self._parse_response(raw_response)
            print(f"   ✓ Claude analysis complete. Threat level: {analysis.get('threat_level', 'UNKNOWN')}")
            return analysis

        except APIError as e:
            logger.error(f"API call failed: {e}")
            print(f"   ✗ API call failed: {e}")
            return self._no_api_fallback(anomaly_result, pattern_result)

    # ── Prompt Building ────────────────────────────────────────────────────

    def _build_prompt(self, anomaly_result: dict, pattern_result: dict, snapshot: dict) -> str:
        """
        Format all findings into a structured prompt for Claude.

        A good prompt gives Claude:
        1. System context (kernel version, module count, etc.)
        2. All anomalies with their severity
        3. All pattern findings
        4. Raw data samples where relevant
        """

        # Gather system context info
        num_modules  = len(snapshot.get("modules_proc", []))
        num_procs    = len(snapshot.get("processes", []))
        num_tcp      = len(snapshot.get("tcp_connections", []))
        dmesg_sample = snapshot.get("dmesg_tail", [])[-5:]  # Last 5 dmesg lines

        # Format anomalies as a readable block
        anomalies = anomaly_result.get("anomalies", [])
        anomaly_text = ""
        if anomalies:
            for i, a in enumerate(anomalies, 1):
                anomaly_text += (f"\n  [{i}] [{a.get('severity', '?')}] {a.get('type', '?')}: "
                                 f"{a.get('description', '')}")
                details = a.get("details", {})
                if details:
                    # json.dumps converts a dict to a JSON string for display
                    anomaly_text += f"\n      Details: {json.dumps(details, default=str)}"
        else:
            anomaly_text = "\n  None detected (system matches baseline)"

        # Format pattern findings
        findings = pattern_result.get("findings", [])
        findings_text = ""
        if findings:
            for i, f in enumerate(findings, 1):
                findings_text += (f"\n  [{i}] [{f.get('severity', '?')}] {f.get('type', '?')}: "
                                  f"{f.get('description', '')}")
        else:
            findings_text = "\n  None detected"

        # Loaded module names list
        module_names = [m["name"] for m in snapshot.get("modules_proc", [])]
        modules_str  = ", ".join(module_names[:30])  # First 30 to avoid huge prompt
        if len(module_names) > 30:
            modules_str += f" ... (+{len(module_names)-30} more)"

        # Active TCP connections
        tcp_conns = snapshot.get("tcp_connections", [])
        established = [c for c in tcp_conns if c["state"] == "ESTABLISHED"]
        tcp_str = "\n  ".join(
            f"{c['local']} → {c['remote']}" for c in established[:10]
        ) or "None"

        # Build the full prompt string
        prompt = f"""=== MAKIM Security Scan Report ===
Timestamp: {anomaly_result.get('baseline_timestamp', 'no baseline')}
Baseline available: {anomaly_result.get('baseline_available', False)}

--- SYSTEM CONTEXT ---
Kernel modules loaded: {num_modules}
Processes running: {num_procs}
TCP connections: {num_tcp}
Module list: {modules_str}

Last 5 dmesg lines:
{chr(10).join('  ' + l for l in dmesg_sample)}

--- ANOMALY DETECTOR FINDINGS (vs baseline) ---
Overall severity: {anomaly_result.get('overall_severity', 'UNKNOWN')}
Total anomalies: {anomaly_result.get('anomaly_count', 0)}
{anomaly_text}

--- ROOTKIT PATTERN FINDINGS (signature-based) ---
Total findings: {pattern_result.get('finding_count', 0)}
{findings_text}

--- ACTIVE ESTABLISHED TCP CONNECTIONS ---
{tcp_str}

=== END OF REPORT ===
Please analyze these findings and provide your assessment in the JSON format specified."""

        return prompt

    # ── API Communication ──────────────────────────────────────────────────

    def _call_api(self, prompt: str) -> str:
        """
        Send a POST request to the Anthropic API and return the raw response text.

        HOW HTTP REQUESTS WORK:
          HTTP is the protocol your browser uses to load websites.
          A POST request sends data TO a server (as opposed to GET which retrieves data).
          We send our prompt as JSON in the request body.
          The server sends back a JSON response containing Claude's reply.

        REQUEST BODY:
          {
            "model": "claude-sonnet-4-20250514",  ← which Claude model to use
            "max_tokens": 1500,                    ← max length of response
            "system": "...",                       ← background instructions
            "messages": [{"role": "user", "content": "..."}]  ← the conversation
          }

        RESPONSE BODY:
          {
            "content": [{"type": "text", "text": "Claude's response here"}],
            ...
          }

        Args:
            prompt: The user message to send to Claude

        Returns:
            Claude's response text as a string

        Raises:
            APIError: if the request fails
        """

        # ── Build the request data (as a Python dict, then converted to JSON) ──
        request_data = {
            "model":      MODEL,
            "max_tokens": 1500,
            "system":     SYSTEM_PROMPT,
            "messages":   [
                {"role": "user", "content": prompt}
            ]
        }

        # json.dumps converts the Python dict to a JSON string
        # encode("utf-8") converts the string to bytes (required for HTTP)
        request_bytes = json.dumps(request_data).encode("utf-8")

        # ── Build the HTTP request ──────────────────────────────────────────
        # HTTP headers tell the server metadata about our request:
        #   Content-Type: we're sending JSON
        #   x-api-key: our authentication key
        #   anthropic-version: which version of the API spec we're using
        headers = {
            "Content-Type":    "application/json",
            "x-api-key":       self.api_key,
            "anthropic-version": "2023-06-01",
        }

        request = urllib.request.Request(
            url     = ANTHROPIC_API_URL,
            data    = request_bytes,
            headers = headers,
            method  = "POST"
        )

        # ── Send the request and get the response ──────────────────────────
        try:
            # urllib.request.urlopen() sends the request and returns the response
            # The response is a file-like object — we need to .read() it
            with urllib.request.urlopen(request, timeout=60) as response:
                response_bytes = response.read()
                response_text  = response_bytes.decode("utf-8")

        except urllib.error.HTTPError as e:
            # HTTPError means the server responded with an error status code
            # Common codes: 401=Unauthorized, 429=Rate limited, 500=Server error
            error_body = e.read().decode("utf-8") if e.fp else ""
            raise APIError(f"HTTP {e.code}: {e.reason}. Body: {error_body[:200]}")

        except urllib.error.URLError as e:
            # URLError means we couldn't even reach the server (network issue)
            raise APIError(f"Network error: {e.reason}")

        # ── Parse the response JSON ────────────────────────────────────────
        try:
            response_dict = json.loads(response_text)
        except json.JSONDecodeError:
            raise APIError(f"Invalid JSON response from API: {response_text[:200]}")

        # Extract Claude's text from the response structure
        content_blocks = response_dict.get("content", [])
        if not content_blocks:
            raise APIError("Empty content in API response")

        # Find the first text block
        for block in content_blocks:
            if block.get("type") == "text":
                return block["text"]

        raise APIError("No text content block found in API response")

    def _parse_response(self, raw_text: str) -> dict:
        """
        Parse Claude's JSON response into a Python dict.

        Claude was instructed to return only JSON, but sometimes it adds
        markdown formatting (```json ... ```) — we strip that if present.
        """
        # Remove markdown code fences if Claude added them
        cleaned = raw_text.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            # Remove first line (```json) and last line (```)
            cleaned = "\n".join(lines[1:-1])

        try:
            result = json.loads(cleaned)
            return result
        except json.JSONDecodeError as e:
            logger.error(f"Claude returned invalid JSON: {e}")
            logger.debug(f"Raw response: {raw_text[:500]}")
            # Return the raw text as a plain string result
            return {
                "threat_level":  "UNKNOWN",
                "confidence":    "LOW",
                "summary":       "AI analysis returned unparseable response.",
                "analysis":      raw_text[:1000],
                "remediation_steps": ["Manual review required — AI response parsing failed."],
                "false_positive_notes": "",
                "indicators_of_compromise": [],
                "recommended_next_tools": [],
            }

    # ── Fallback ───────────────────────────────────────────────────────────

    def _no_api_fallback(self, anomaly_result: dict, pattern_result: dict) -> dict:
        """
        Provide a basic summary when no API key is available.
        Uses rule-based logic to determine threat level without Claude.
        """

        total_anomalies = anomaly_result.get("anomaly_count", 0)
        total_findings  = pattern_result.get("finding_count", 0)
        overall_sev     = anomaly_result.get("overall_severity", "CLEAN")

        # Simple rule-based threat level (poor man's AI)
        if overall_sev == "CRITICAL" or total_findings > 5:
            threat_level = "HIGH"
        elif overall_sev == "HIGH" or total_anomalies > 3:
            threat_level = "MEDIUM"
        elif total_anomalies > 0 or total_findings > 0:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        return {
            "threat_level":  threat_level,
            "confidence":    "LOW",
            "summary":       (f"Rule-based assessment (no AI): "
                              f"{total_anomalies} anomalies, {total_findings} pattern findings. "
                              f"Set ANTHROPIC_API_KEY for full AI analysis."),
            "analysis":      "AI analysis unavailable. Set ANTHROPIC_API_KEY for detailed reasoning.",
            "remediation_steps": [
                "Set ANTHROPIC_API_KEY environment variable for AI-powered analysis.",
                "Review anomalies and pattern findings in the report manually.",
                "Consider running rkhunter or chkrootkit for additional checks.",
            ],
            "false_positive_notes": "Unable to assess false positives without AI analysis.",
            "indicators_of_compromise": [],
            "recommended_next_tools": ["rkhunter", "chkrootkit"],
        }


class APIError(Exception):
    """Custom exception for API communication errors."""
    pass
