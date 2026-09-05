from urllib.parse import urlparse, parse_qs
from . import sqli_engine


def run(target_url, http_client=None):
    cookies = None

    if http_client is not None:
        cookies = http_client.session.cookies.get_dict()

    parameters = list(parse_qs(urlparse(target_url).query).keys())

    if not parameters:
        parameters = ["id"]

    findings = []

    for parameter in parameters:
        findings.extend(
            sqli_engine.run(
                target_url,
                param=parameter,
                cookies=cookies
            )
        )

    normalized = []

    for item in findings:
        normalized.append({
            "vulnerability_type": item["type"],
            "parameter": item["parameter"],
            "method": "GET",
            "payload_type": "SQL Injection",
            "encoding_variant": "",
            "severity": item["severity"],
            "evidence": item["evidence"],
            "location": target_url,
            "remediation": item["remediation"],
        })

    return normalized
