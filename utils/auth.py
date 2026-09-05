"""
auth.py
--------
Generic form-based login automation, used to authenticate against targets
that require a session before vulnerable pages become reachable (e.g. DVWA).

DVWA specifics handled:
  - DVWA's login form includes a hidden CSRF field named `user_token` that
    changes on every page load. We fetch the login page first, extract the
    current token, then submit it along with the username/password.
  - After login, DVWA exposes a security level selector at
    `security.php?security=low|medium|high` (also CSRF-protected the same
    way) which controls how strict each vulnerable module's filtering is.
    Testing against anything other than "low" will usually cause payloads
    to be filtered/encoded, which is expected/intentional DVWA behavior,
    not a scanner bug.

This module is intentionally generic (not DVWA-only): it looks for a hidden
CSRF-style token field by name, and works against any similar login form as
long as the field names are supplied.
"""

from urllib.parse import urljoin
from bs4 import BeautifulSoup

from utils.logger import log


def _extract_hidden_field(html_text: str, field_name: str):
    soup = BeautifulSoup(html_text, "html.parser")
    tag = soup.find("input", {"name": field_name})
    if tag and tag.get("value"):
        return tag["value"]
    return None


def login(http_client, login_url: str, username: str, password: str,
          username_field: str = "username", password_field: str = "password",
          csrf_field: str = "user_token", submit_field: str = "Login"):
    """
    Perform a generic form-based login.

    Returns True if the login request completed without error (does not
    guarantee correct credentials -- callers should verify success by
    checking that a protected page is reachable afterward).
    """
    log(f"[auth] Fetching login page: {login_url}", "info")
    try:
        get_resp = http_client.get(login_url)
    except Exception as exc:
        log(f"[auth] Failed to fetch login page: {exc}", "danger")
        return False

    token = _extract_hidden_field(get_resp.text, csrf_field)
    if token:
        log(f"[auth] Found CSRF token field '{csrf_field}'.", "info")
    else:
        log(f"[auth] No CSRF token field '{csrf_field}' found (may not be required).", "muted")

    data = {
        username_field: username,
        password_field: password,
        submit_field: "Login",
    }
    if token:
        data[csrf_field] = token

    try:
        post_resp = http_client.post(login_url, data=data)
    except Exception as exc:
        log(f"[auth] Login POST failed: {exc}", "danger")
        return False

    if post_resp.status_code >= 400:
        log(f"[auth] Login request returned HTTP {post_resp.status_code}.", "warning")
        return False

    log("[auth] Login request submitted.", "success")
    return True


def set_security_level(http_client, base_url: str, level: str = "low",
                        csrf_field: str = "user_token"):
    """
    DVWA-style security level setter: GET the security.php page, extract the
    CSRF token, then POST the desired level.
    """
    security_url = urljoin(base_url, "security.php")
    log(f"[auth] Setting security level to '{level}' via {security_url}", "info")

    try:
        get_resp = http_client.get(security_url)
    except Exception as exc:
        log(f"[auth] Could not fetch security settings page: {exc}", "warning")
        return False

    token = _extract_hidden_field(get_resp.text, csrf_field)
    data = {"security": level, "seclev_submit": "Submit"}
    if token:
        data[csrf_field] = token

    try:
        http_client.post(security_url, data=data)
    except Exception as exc:
        log(f"[auth] Could not set security level: {exc}", "warning")
        return False

    log(f"[auth] Security level set to '{level}'.", "success")
    return True
