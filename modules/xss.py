"""
modules/xss.py
---------------
Module 3 - Reflected XSS Testing

Tests discovered GET and POST parameters for reflected Cross-Site
Scripting using a set of safe, marker-based payloads with several basic
encoding variants.

Detection logic:
  A parameter is flagged as vulnerable when the *unescaped* payload
  (or a recognizably decoded/unescaped form of it) is found reflected
  back verbatim in the HTTP response body. Payloads that come back
  HTML-entity-encoded (e.g. &lt;script&gt;) are treated as safely
  neutralized and are NOT flagged, since the browser would not execute
  them as markup.

This module never performs any real exploitation (no alert boxes are
actually triggered, no browser/JS engine is used) -- everything is
judged purely from the raw HTTP response text.
"""

import html as html_lib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from utils.payloads import generate_marker, build_payload_set, encode_variants
from utils.param_discovery import discover_get_params, discover_post_forms
from utils.logger import log


SEVERITY = "High"
REMEDIATION_TEXT = (
    "Encode all user-supplied output for the context it is rendered in "
    "(HTML entity encoding for HTML body, attribute encoding for HTML "
    "attributes, JS string encoding for inline scripts). Apply a strict "
    "Content-Security-Policy, validate input server-side, and use a "
    "templating engine with auto-escaping enabled by default."
)


def run(target_url: str, http_client, threads: int = 1):
    """
    Entry point called by framework.py for `--module xss`.

    Returns a list of finding dicts compatible with utils.reporter.
    """
    findings = []
    marker = generate_marker()
    payload_set = build_payload_set(marker)

    log(f"[xss] Starting reflected XSS testing on {target_url}", "info")

    _warn_if_login_wall(target_url, http_client)

    # --- GET parameter testing (params already present in the target URL) -----
    get_params = discover_get_params(target_url)
    if get_params:
        log(f"[xss] Discovered {len(get_params)} GET parameter(s) in URL: {', '.join(get_params)}", "info")
        for param in get_params:
            findings.extend(
                _test_get_parameter(target_url, param, payload_set, http_client, marker)
            )
    else:
        log("[xss] No GET parameters found in target URL.", "muted")

    # --- Form discovery (covers <form method="get"> and <form method="post">) --
    forms = discover_post_forms(target_url, http_client)

    get_forms = [f for f in forms if f["method"] == "get"]
    if get_forms:
        log(f"[xss] Discovered {len(get_forms)} GET form(s) on the page.", "info")
        for form in get_forms:
            for field in form["inputs"]:
                findings.extend(
                    _test_get_form_field(form, field, payload_set, http_client, marker)
                )
    else:
        log("[xss] No GET forms discovered on target page.", "muted")

    post_forms = [f for f in forms if f["method"] == "post"]
    if post_forms:
        log(f"[xss] Discovered {len(post_forms)} POST form(s).", "info")
        for form in post_forms:
            for field in form["inputs"]:
                findings.extend(
                    _test_post_parameter(form, field, payload_set, http_client, marker)
                )
    else:
        log("[xss] No POST forms discovered on target page.", "muted")

    if not findings:
        log("[xss] No reflected XSS vulnerabilities detected.", "success")
    else:
        log(f"[xss] {len(findings)} potential reflected XSS issue(s) found.", "danger")

    return findings


def _warn_if_login_wall(target_url, http_client):
    """
    Heuristic check: if the target page looks like a login form (common on
    DVWA/bWAPP/WebGoat when unauthenticated), warn the user, since every
    payload will just bounce off the login page and produce false negatives.
    """
    try:
        response = http_client.get(target_url)
    except Exception:
        return

    text_lower = response.text.lower()
    login_signals = ("name=\"password\"", "user_token", "login.php", "type=\"password\"")
    hits = sum(1 for signal in login_signals if signal in text_lower)

    if hits >= 2:
        log(
            "[xss] WARNING: the target response looks like a login page. "
            "If this target requires authentication (e.g. DVWA), pass "
            "--login-url, --username, --password (and --security-level) "
            "so the scan runs against an authenticated session.",
            "warning",
        )


def _test_get_form_field(form, field, payload_set, http_client, marker):
    """
    Test a field belonging to a <form method="get"> element. Builds a request
    to the form's action URL with all fields filled with a benign value except
    the one under test, which gets each payload/encoding variant in turn.
    """
    results = []
    for payload_name, raw_payload in payload_set:
        variants = encode_variants(raw_payload)
        for variant_name in ("raw", "double_url_enc"):
            test_value = variants[variant_name] if variant_name != "raw" else raw_payload
            params = {name: "test" for name in form["inputs"]}
            params[field] = test_value

            try:
                response = http_client.get(form["action"], params=params)
            except Exception as exc:
                log(f"[xss] Request failed for GET form field '{field}': {exc}", "warning")
                continue

            finding = _analyze_response(
                response_text=response.text,
                marker=marker,
                raw_payload=raw_payload,
                parameter=field,
                method="GET (form)",
                payload_name=payload_name,
                variant_name=variant_name,
                location=response.url,
            )
            if finding:
                results.append(finding)
                break
    return results


def _test_get_parameter(target_url, param, payload_set, http_client, marker):
    results = []
    parsed = urlparse(target_url)
    original_params = parse_qs(parsed.query)

    for payload_name, raw_payload in payload_set:
        variants = encode_variants(raw_payload)
        # Test both the raw payload and its URL-encoded form; requests will
        # re-encode automatically, so we send the raw string as the param
        # value and let requests handle transport encoding, then separately
        # send a manually double/pre-encoded variant to catch filters that
        # only decode once.
        for variant_name in ("raw", "double_url_enc"):
            test_value = variants[variant_name] if variant_name != "raw" else raw_payload
            test_params = {k: v[0] for k, v in original_params.items()}
            test_params[param] = test_value

            new_query = urlencode(test_params)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                response = http_client.get(test_url)
            except Exception as exc:
                log(f"[xss] Request failed for param '{param}': {exc}", "warning")
                continue

            finding = _analyze_response(
                response_text=response.text,
                marker=marker,
                raw_payload=raw_payload,
                parameter=param,
                method="GET",
                payload_name=payload_name,
                variant_name=variant_name,
                location=test_url,
            )
            if finding:
                results.append(finding)
                # one confirmed hit per parameter is enough detail; continue
                # to next payload to still enumerate other payload types
                break
    return results


def _test_post_parameter(form, field, payload_set, http_client, marker):
    results = []
    for payload_name, raw_payload in payload_set:
        variants = encode_variants(raw_payload)
        for variant_name in ("raw", "double_url_enc"):
            test_value = variants[variant_name] if variant_name != "raw" else raw_payload
            data = {name: "test" for name in form["inputs"]}
            data[field] = test_value

            try:
                response = http_client.post(form["action"], data=data)
            except Exception as exc:
                log(f"[xss] Request failed for field '{field}': {exc}", "warning")
                continue

            finding = _analyze_response(
                response_text=response.text,
                marker=marker,
                raw_payload=raw_payload,
                parameter=field,
                method="POST",
                payload_name=payload_name,
                variant_name=variant_name,
                location=form["action"],
            )
            if finding:
                results.append(finding)
                break
    return results


def _analyze_response(response_text, marker, raw_payload, parameter, method,
                       payload_name, variant_name, location):
    """
    Decide whether the payload was reflected in an *exploitable* (unescaped)
    form. Returns a finding dict, or None if not vulnerable.
    """
    if marker not in response_text:
        return None

    # If the marker only appears inside an HTML-entity-encoded form
    # (e.g. &lt;script&gt;...marker...&lt;/script&gt;), the output was
    # safely escaped and is NOT exploitable.
    escaped_form = html_lib.escape(raw_payload)
    if raw_payload in response_text:
        # Raw, unescaped payload reflected verbatim -> vulnerable
        pass
    elif escaped_form in response_text and raw_payload not in response_text:
        return None
    elif marker in response_text and raw_payload not in response_text:
        # Marker present, but not as part of the intact raw payload string
        # (e.g. tags were stripped) -- not enough evidence of executable
        # reflection, skip.
        return None

    evidence_snippet = _extract_snippet(response_text, raw_payload)

    return {
        "vulnerability_type": "Reflected XSS",
        "parameter": parameter,
        "method": method,
        "payload_type": payload_name,
        "encoding_variant": variant_name,
        "severity": SEVERITY,
        "evidence": evidence_snippet,
        "location": location,
        "remediation": REMEDIATION_TEXT,
    }


def _extract_snippet(response_text, needle, context=40):
    idx = response_text.find(needle)
    if idx == -1:
        return needle
    start = max(0, idx - context)
    end = min(len(response_text), idx + len(needle) + context)
    return response_text[start:end].replace("\n", " ").strip()
