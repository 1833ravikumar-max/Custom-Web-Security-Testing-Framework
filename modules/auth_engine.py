"""
Safe authentication assessment engine.

Checks:
- Weak or absent client-side password length policy
- Login response differences / possible username enumeration
- Obvious lockout or rate-limit signals during two controlled failures
- Session-cookie Secure, HttpOnly and SameSite attributes

The module performs at most two controlled failed-login requests. It does not
brute-force passwords, bypass authentication or attempt account takeover.
"""

from __future__ import annotations

import re
import secrets
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils.http_client import HttpClient
from utils.logger import log


SESSION_COOKIE_HINTS = (
    "session",
    "sess",
    "sid",
    "auth",
    "token",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
)

LOCKOUT_MARKERS = (
    "too many attempts",
    "too many login attempts",
    "account locked",
    "temporarily locked",
    "try again later",
    "rate limit",
    "captcha",
)

PASSWORD_REMEDIATION = (
    "Enforce password requirements on the server, including an appropriate "
    "minimum length and checks against weak or compromised passwords. Client-"
    "side HTML validation may be used for guidance but must not be the only "
    "control."
)

ENUMERATION_REMEDIATION = (
    "Return the same status code, redirect behavior, response size and generic "
    "error message for all failed login attempts. Avoid revealing whether a "
    "username exists."
)

COOKIE_REMEDIATION = (
    "Protect authentication cookies with Secure, HttpOnly and an appropriate "
    "SameSite value. Regenerate the session identifier after login and expire "
    "it correctly on logout."
)


def assess_authentication(
    target_url: str,
    http_client: Any,
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run safe authentication checks."""

    findings: list[dict[str, Any]] = []
    login_url = options.get("login_url") or target_url

    username = options.get("username")
    username_field = options.get("username_field") or "username"
    password_field = options.get("password_field") or "password"

    log(f"[auth] Assessing login page: {login_url}", "info")

    assessment_client = _fresh_client(http_client)

    try:
        login_response = assessment_client.get(login_url)
    except Exception as exc:
        log(f"[auth] Could not fetch login page: {exc}", "warning")
        findings.extend(_assess_session_cookies(target_url, http_client))
        return findings

    form = _find_login_form(login_response.text)

    if form is None:
        log("[auth] No password-based login form was found.", "warning")
    else:
        findings.extend(
            _assess_password_policy(
                login_url=login_url,
                form=form,
                default_password_field=password_field,
            )
        )

        if username:
            findings.extend(
                _assess_login_response_differences(
                    login_url=login_url,
                    initial_form=form,
                    assessment_client=assessment_client,
                    known_username=username,
                    username_field=username_field,
                    password_field=password_field,
                )
            )
        else:
            log(
                "[auth] Username enumeration comparison skipped because no "
                "--username value was supplied.",
                "muted",
            )

    findings.extend(_assess_session_cookies(target_url, http_client))
    return _deduplicate(findings)


def _fresh_client(http_client: Any) -> HttpClient:
    """Create an unauthenticated client while preserving request settings."""

    session_headers = dict(getattr(http_client.session, "headers", {}))
    user_agent = session_headers.pop("User-Agent", None)
    session_headers.pop("Cookie", None)

    client = HttpClient(
        user_agent=user_agent,
        timeout=getattr(http_client, "timeout", 10),
        cookies=None,
        extra_headers=session_headers,
        proxy=None,
        verify_ssl=getattr(http_client, "verify_ssl", True),
    )

    client.session.proxies.update(
        dict(getattr(http_client.session, "proxies", {}))
    )
    return client


def _find_login_form(html_text: str):
    soup = BeautifulSoup(html_text or "", "html.parser")

    for form in soup.find_all("form"):
        if form.find("input", {"type": re.compile("^password$", re.I)}):
            return form

    return None


def _assess_password_policy(
    login_url: str,
    form: Any,
    default_password_field: str,
) -> list[dict[str, Any]]:
    password_input = form.find(
        "input",
        {"type": re.compile("^password$", re.I)},
    )

    if password_input is None:
        return []

    field_name = password_input.get("name") or default_password_field
    minlength_raw = password_input.get("minlength")

    try:
        minlength = int(minlength_raw) if minlength_raw is not None else None
    except (TypeError, ValueError):
        minlength = None

    if minlength is not None and minlength >= 8:
        return []

    issue_type = "Weak or Absent Client-Side Password Length Policy"

    return [
        {
            "type": issue_type,
            "vulnerability_type": issue_type,
            "parameter": field_name,
            "method": (form.get("method") or "GET").upper(),
            "severity": "Low",
            "evidence": (
                f"Password field name='{field_name}' has minlength="
                f"{minlength_raw!r}. This is only a client-side observation "
                "and does not prove that server-side password policy is absent."
            ),
            "location": login_url,
            "remediation": PASSWORD_REMEDIATION,
        }
    ]


def _assess_login_response_differences(
    login_url: str,
    initial_form: Any,
    assessment_client: Any,
    known_username: str,
    username_field: str,
    password_field: str,
) -> list[dict[str, Any]]:
    """Perform only two controlled failed-login attempts."""

    wrong_password = f"WSF-invalid-{secrets.token_hex(8)}"
    random_username = f"wsf-no-user-{secrets.token_hex(6)}"

    first = _failed_login_probe(
        client=assessment_client,
        login_url=login_url,
        fallback_form=initial_form,
        username=known_username,
        password=wrong_password,
        username_field=username_field,
        password_field=password_field,
    )

    second = _failed_login_probe(
        client=assessment_client,
        login_url=login_url,
        fallback_form=initial_form,
        username=random_username,
        password=wrong_password,
        username_field=username_field,
        password_field=password_field,
    )

    if first is None or second is None:
        return []

    if first["lockout_signal"] or second["lockout_signal"]:
        log(
            "[auth] A lockout, CAPTCHA or rate-limit signal was observed; "
            "username-enumeration comparison was not reported.",
            "muted",
        )
        return []

    status_diff = first["status_code"] != second["status_code"]
    url_diff = first["final_url"] != second["final_url"]

    length_a = max(first["length"], 1)
    length_b = max(second["length"], 1)
    length_ratio = abs(length_a - length_b) / max(length_a, length_b)

    similarity = SequenceMatcher(
        None,
        first["normalized_text"],
        second["normalized_text"],
    ).ratio()

    materially_different = (
        status_diff
        or url_diff
        or length_ratio >= 0.20
        or similarity < 0.75
    )

    if not materially_different:
        return []

    issue_type = "Login Responses Differ for Valid and Invalid Usernames"

    return [
        {
            "type": issue_type,
            "vulnerability_type": issue_type,
            "parameter": username_field,
            "method": first["method"],
            "severity": "Medium",
            "evidence": (
                "Two controlled failed-login attempts produced different "
                "responses. "
                f"Known-user probe: status={first['status_code']}, "
                f"length={first['length']}, final_url={first['final_url']}; "
                f"random-user probe: status={second['status_code']}, "
                f"length={second['length']}, final_url={second['final_url']}; "
                f"normalized similarity={similarity:.2f}. No password value "
                "is stored in this evidence."
            ),
            "location": login_url,
            "remediation": ENUMERATION_REMEDIATION,
        }
    ]


def _failed_login_probe(
    client: Any,
    login_url: str,
    fallback_form: Any,
    username: str,
    password: str,
    username_field: str,
    password_field: str,
) -> dict[str, Any] | None:
    try:
        page_response = client.get(login_url)
    except Exception:
        return None

    form = _find_login_form(page_response.text) or fallback_form
    method = (form.get("method") or "post").strip().upper()
    action_url = urljoin(page_response.url or login_url, form.get("action") or login_url)

    data: dict[str, str] = {}

    for input_tag in form.find_all("input"):
        name = input_tag.get("name")
        if not name:
            continue

        input_type = (input_tag.get("type") or "text").lower()

        if input_type in {"hidden", "submit"}:
            data[name] = input_tag.get("value") or ""

    detected_username = _detect_username_field(form) or username_field
    detected_password = _detect_password_field(form) or password_field

    data[detected_username] = username
    data[detected_password] = password

    try:
        if method == "GET":
            response = client.get(action_url, params=data)
        else:
            response = client.post(action_url, data=data)
    except Exception:
        return None

    normalized_text = _normalize_response_text(response.text)
    response_lower = normalized_text.lower()

    lockout_signal = (
        response.status_code == 429
        or bool(response.headers.get("Retry-After"))
        or any(marker in response_lower for marker in LOCKOUT_MARKERS)
    )

    return {
        "status_code": response.status_code,
        "final_url": response.url,
        "length": len(response.text or ""),
        "normalized_text": normalized_text,
        "lockout_signal": lockout_signal,
        "method": method,
    }


def _detect_username_field(form: Any) -> str | None:
    candidates = form.find_all("input")

    for tag in candidates:
        name = (tag.get("name") or "").lower()
        input_type = (tag.get("type") or "text").lower()

        if input_type in {"text", "email"} and any(
            word in name for word in ("user", "email", "login")
        ):
            return tag.get("name")

    return None


def _detect_password_field(form: Any) -> str | None:
    tag = form.find("input", {"type": re.compile("^password$", re.I)})
    return tag.get("name") if tag and tag.get("name") else None


def _normalize_response_text(html_text: str) -> str:
    soup = BeautifulSoup(html_text or "", "html.parser")

    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = " ".join(soup.get_text(" ", strip=True).split())
    text = re.sub(r"\b[0-9a-f]{16,}\b", "<token>", text, flags=re.I)
    text = re.sub(r"\b\d{5,}\b", "<number>", text)
    return text[:12000]


def _assess_session_cookies(
    target_url: str,
    http_client: Any,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    cookies = list(getattr(http_client.session, "cookies", []))

    if not cookies:
        return findings

    likely_session_cookies = [
        cookie
        for cookie in cookies
        if any(hint in cookie.name.lower() for hint in SESSION_COOKIE_HINTS)
    ]

    cookies_to_check = likely_session_cookies or cookies
    target_is_https = urlparse(target_url).scheme.lower() == "https"

    for cookie in cookies_to_check:
        rest = {
            str(key).lower(): value
            for key, value in getattr(cookie, "_rest", {}).items()
        }

        http_only = "httponly" in rest
        same_site = rest.get("samesite")

        missing: list[str] = []

        if target_is_https and not cookie.secure:
            missing.append("Secure")

        if not http_only:
            missing.append("HttpOnly")

        if not same_site:
            missing.append("SameSite")

        if not missing:
            continue

        severity = "Medium" if any(
            item in missing for item in ("Secure", "HttpOnly")
        ) else "Low"

        issue_type = "Session Cookie Missing Security Attributes"

        findings.append(
            {
                "type": issue_type,
                "vulnerability_type": issue_type,
                "parameter": cookie.name,
                "method": "COOKIE",
                "severity": severity,
                "evidence": (
                    f"Cookie '{cookie.name}' is missing: {', '.join(missing)}. "
                    f"Domain={cookie.domain or 'unspecified'}, "
                    f"Path={cookie.path or '/'}; cookie value was not recorded."
                ),
                "location": target_url,
                "remediation": COOKIE_REMEDIATION,
            }
        )

    return findings


def _deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}

    for finding in findings:
        key = (
            finding.get("vulnerability_type"),
            finding.get("parameter"),
            finding.get("location"),
        )
        unique[key] = finding

    return list(unique.values())
