"""
security_headers.py
--------------------
Security Headers Analyzer — Core Engine

Scans a target URL's HTTP response headers, checks them against a
checklist of security best-practice headers, flags missing/leaky
headers with a severity rating, and gives a specific remediation
recommendation for each finding.

This module only contains the analysis logic. See main.py for the
command-line / interactive interface.

Author: <your name>
"""

import json
import time
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse

import requests


class SecurityHeadersAnalyzer:
    """
    Analyzes the HTTP security headers of a target URL.

    Usage:
        analyzer = SecurityHeadersAnalyzer("https://example.com")
        report = analyzer.run()
    """

    # Checklist of security-relevant headers.
    # Each entry: header name -> (severity, risk explanation, fix/recommendation)
    CHECKLIST = {
        "Content-Security-Policy": (
            "HIGH",
            "XSS (Cross-Site Scripting) attacks are easier to exploit.",
            "Add a 'Content-Security-Policy' header defining allowed content sources."
        ),
        "Strict-Transport-Security": (
            "HIGH",
            "Susceptible to Man-in-the-Middle (MITM) protocol downgrade attacks.",
            "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains'."
        ),
        "X-Content-Type-Options": (
            "MEDIUM",
            "Browsers may MIME-sniff the response body, leading to XSS.",
            "Add 'X-Content-Type-Options: nosniff'."
        ),
        "X-Frame-Options": (
            "MEDIUM",
            "Page can be embedded in an iframe, enabling Clickjacking attacks.",
            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
        ),
        "Referrer-Policy": (
            "LOW",
            "Full URLs may leak to third parties via the Referer header.",
            "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
        ),
        "Permissions-Policy": (
            "LOW",
            "Browser features (camera, mic, geolocation) are not restricted.",
            "Add 'Permissions-Policy' to disable unused browser features."
        ),
    }

    # Headers that leak information about the server stack if present.
    INFO_DISCLOSURE_HEADERS = {
        "Server": (
            "LOW",
            "Reveals server technology, helping attackers verify CVEs.",
            "Configure server to suppress or obfuscate the 'Server' header."
        ),
        "X-Powered-By": (
            "LOW",
            "Reveals backend framework/language, aiding targeted exploits.",
            "Remove or disable the 'X-Powered-By' header in server config."
        ),
        "X-AspNet-Version": (
            "LOW",
            "Reveals exact ASP.NET version, aiding targeted exploits.",
            "Disable version headers in web.config (enableVersionHeader=false)."
        ),
    }

    def __init__(self, url: str, timeout: int = 10):
        self.url = self._normalize_url(url)
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Adds https:// automatically if the user forgot a scheme."""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url

    @staticmethod
    def domain_from_url(url: str) -> str:
        """Extracts a clean domain name, used for report filenames."""
        netloc = urlparse(url).netloc
        return netloc.replace(":", "_") or "target"

    # ------------------------------------------------------------------
    # Core logic
    # ------------------------------------------------------------------

    def fetch(self) -> Dict[str, Any]:
        """Sends the request and returns response metadata + headers."""
        try:
            start = time.time()
            response = requests.get(
                self.url, timeout=self.timeout, allow_redirects=True
            )
            elapsed_ms = round((time.time() - start) * 1000, 1)
            return {
                "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "response_time_ms": elapsed_ms,
                "redirect_count": len(response.history),
            }
        except requests.exceptions.ConnectionError:
            raise ConnectionError(
                f"Could not connect to '{self.url}'. Check the URL or your network."
            )
        except requests.exceptions.Timeout:
            raise TimeoutError(
                f"Request to '{self.url}' timed out after {self.timeout}s."
            )
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Request failed: {exc}")

    def run(self) -> Dict[str, Any]:
        """
        Runs the full analysis and returns a structured report dict.
        """
        meta = self.fetch()
        headers_lower = {k.lower(): v for k, v in meta["headers"].items()}

        findings: List[Dict[str, str]] = []
        present, missing = {}, {}

        # 1. Check for missing security headers
        for header, (severity, risk, recommendation) in self.CHECKLIST.items():
            if header.lower() in headers_lower:
                present[header] = headers_lower[header.lower()]
            else:
                missing[header] = severity
                findings.append({
                    "severity": severity,
                    "issue": f"Missing {header}",
                    "risk": risk,
                    "recommendation": recommendation,
                })

        # 2. Check for information-disclosure headers that ARE present
        for header, (severity, risk, recommendation) in self.INFO_DISCLOSURE_HEADERS.items():
            if header.lower() in headers_lower:
                value = headers_lower[header.lower()]
                label = "Server Header Leaked" if header == "Server" else f"{header} Leaked"
                findings.append({
                    "severity": severity,
                    "issue": f"{label}: {value}",
                    "risk": risk,
                    "recommendation": recommendation,
                })

        # Sort findings by severity (HIGH -> MEDIUM -> LOW)
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        findings.sort(key=lambda f: order.get(f["severity"], 3))

        score = round((len(present) / len(self.CHECKLIST)) * 100, 1)

        report = {
            "module": "Security Headers Analyzer",
            "target_input": self.url,
            "target": meta["final_url"],
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "status_code": meta["status_code"],
            "response_time_ms": meta["response_time_ms"],
            "redirect_count": meta["redirect_count"],
            "headers_found": len(meta["headers"]),
            "security_score_percent": score,
            "findings": findings,
            "headers_present": present,
            "headers_missing": missing,
            "raw_headers": meta["headers"],
        }
        return report

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def save_json(report: Dict[str, Any], filepath: str) -> None:
        """Saves the report as a JSON file."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
