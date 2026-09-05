from .headers_engine import SecurityHeadersAnalyzer


def run(target_url, http_client=None):
    report = SecurityHeadersAnalyzer(target_url).run()
    findings = []

    for item in report["findings"]:
        findings.append({
            "vulnerability_type": "Security Header",
            "parameter": "",
            "method": "GET",
            "payload_type": item["issue"],
            "encoding_variant": "",
            "severity": item["severity"].title(),
            "evidence": item["issue"],
            "location": report["target"],
            "remediation": item["recommendation"],
        })

    return findings
