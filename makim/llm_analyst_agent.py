"""
MAKIM Agent 4: LLM Analyst Agent using OpenRouter

This replaces the old Claude/Anthropic API version.

It uses OpenRouter's OpenAI-compatible chat completion API:
https://openrouter.ai/api/v1/chat/completions

Environment variable needed:
OPENROUTER_API_KEY
"""

import json
import logging
import urllib.request
import urllib.error

logger = logging.getLogger("MAKIM.LLMAnalyst")

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

# Free router. OpenRouter chooses an available free model.
MODEL = "openrouter/free"


SYSTEM_PROMPT = """You are MAKIM's LLM Analyst, a Linux kernel security analyst.

You receive structured findings from a multi-agent kernel integrity monitor.
Your job is to analyze ONLY the evidence provided. Do not invent findings.

Return ONLY valid JSON with this structure:
{
  "threat_level": "CLEAN|LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": "LOW|MEDIUM|HIGH",
  "summary": "Short executive summary",
  "analysis": "Detailed but clear explanation",
  "false_positive_notes": "Likely false positives and why",
  "remediation_steps": ["step 1", "step 2"],
  "indicators_of_compromise": ["ioc 1", "ioc 2"],
  "recommended_next_tools": ["tool 1", "tool 2"]
}
"""


class LLMAnalystAgent:
    def __init__(self, api_key: str = None):
        self.api_key = api_key

        if api_key:
            logger.info("LLM Analyst initialized with OpenRouter API key.")
        else:
            logger.warning("LLM Analyst initialized without OpenRouter API key.")

    def run(self, anomaly_result: dict, pattern_result: dict, snapshot: dict) -> dict:
        print("\n[Agent 4/5] LLM Analyst — Sending findings to OpenRouter...")

        if not self.api_key:
            print("   ⚠ OPENROUTER_API_KEY not found — using rule-based fallback")
            return self._no_api_fallback(anomaly_result, pattern_result)

        prompt = self._build_prompt(anomaly_result, pattern_result, snapshot)

        try:
            raw_response = self._call_openrouter(prompt)
            result = self._parse_response(raw_response)
            print(f"   ✓ OpenRouter analysis complete. Threat level: {result.get('threat_level', 'UNKNOWN')}")
            return result

        except APIError as e:
            print(f"   ✗ OpenRouter API failed: {e}")
            return self._no_api_fallback(anomaly_result, pattern_result)

    def _build_prompt(self, anomaly_result: dict, pattern_result: dict, snapshot: dict) -> str:
        num_modules = len(snapshot.get("modules_proc", []))
        num_processes = len(snapshot.get("processes", []))
        num_tcp = len(snapshot.get("tcp_connections", []))

        safe_payload = {
            "system_context": {
                "kernel_modules_loaded": num_modules,
                "processes_running": num_processes,
                "tcp_connections": num_tcp,
                "dmesg_tail_sample": snapshot.get("dmesg_tail", [])[-5:]
            },
            "anomaly_result": anomaly_result,
            "pattern_result": pattern_result
        }

        return json.dumps(safe_payload, indent=2, default=str)

    def _call_openrouter(self, prompt: str) -> str:
        request_data = {
            "model": MODEL,
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.2,
            "max_tokens": 1200
        }

        request_bytes = json.dumps(request_data).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/",
            "X-OpenRouter-Title": "MAKIM Kernel Integrity Monitor"
        }

        request = urllib.request.Request(
            url=OPENROUTER_API_URL,
            data=request_bytes,
            headers=headers,
            method="POST"
        )

        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                response_text = response.read().decode("utf-8")

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8") if e.fp else ""
            raise APIError(f"HTTP {e.code}: {e.reason}. {body[:300]}")

        except urllib.error.URLError as e:
            raise APIError(f"Network error: {e.reason}")

        try:
            response_json = json.loads(response_text)
        except json.JSONDecodeError:
            raise APIError(f"Invalid JSON from OpenRouter: {response_text[:300]}")

        choices = response_json.get("choices", [])
        if not choices:
            raise APIError(f"No choices returned: {response_text[:300]}")

        message = choices[0].get("message", {})
        content = message.get("content")

        if not content:
            raise APIError(f"No message content returned: {response_text[:300]}")

        return content

    def _parse_response(self, raw_text: str) -> dict:
        cleaned = raw_text.strip()

        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            cleaned = "\n".join(
                line for line in lines
                if not line.strip().startswith("```")
            )

        try:
            return json.loads(cleaned)

        except json.JSONDecodeError:
            return {
                "threat_level": "UNKNOWN",
                "confidence": "LOW",
                "summary": "The LLM response could not be parsed as JSON.",
                "analysis": raw_text[:1000],
                "false_positive_notes": "Manual review required.",
                "remediation_steps": [
                    "Review the raw MAKIM findings manually.",
                    "Check whether the model returned non-JSON text."
                ],
                "indicators_of_compromise": [],
                "recommended_next_tools": ["rkhunter", "chkrootkit", "osquery"]
            }

    def _no_api_fallback(self, anomaly_result: dict, pattern_result: dict) -> dict:
        total_anomalies = anomaly_result.get("anomaly_count", 0)
        total_findings = pattern_result.get("finding_count", 0)
        overall_severity = anomaly_result.get("overall_severity", "CLEAN")

        if overall_severity in ("CRITICAL", "HIGH") or total_findings >= 5:
            threat_level = "HIGH"
        elif overall_severity == "MEDIUM" or total_anomalies >= 3:
            threat_level = "MEDIUM"
        elif total_anomalies > 0 or total_findings > 0:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        return {
            "threat_level": threat_level,
            "confidence": "LOW",
            "summary": (
                f"Rule-based fallback: {total_anomalies} anomalies and "
                f"{total_findings} rootkit-pattern findings detected."
            ),
            "analysis": "OpenRouter API was not available, so MAKIM used local rule-based analysis.",
            "false_positive_notes": "False positives require manual review without LLM analysis.",
            "remediation_steps": [
                "Review all HIGH and CRITICAL findings first.",
                "Re-run MAKIM after confirming a clean baseline.",
                "Use rkhunter, chkrootkit, or osquery for comparison."
            ],
            "indicators_of_compromise": [],
            "recommended_next_tools": ["rkhunter", "chkrootkit", "osquery"]
        }


class APIError(Exception):
    pass