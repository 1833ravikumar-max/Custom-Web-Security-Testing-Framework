"""
http_client.py
---------------
Thin wrapper around `requests` used by the testing modules.

Provides:
  - consistent, configurable User-Agent
  - timeout handling
  - a single re-usable session (keeps cookies across requests, useful
    when a target requires a pre-authenticated session)
  - optional proxy support (e.g. routing through Burp Suite / OWASP ZAP)
"""

import requests

DEFAULT_USER_AGENT = "SecurityTestingFramework/1.0 (+authorized-testing-only)"
DEFAULT_TIMEOUT = 10


class HttpClient:
    def __init__(self, user_agent: str = None, timeout: int = None, cookies: dict = None,
                 extra_headers: dict = None, proxy: str = None, verify_ssl: bool = True):
        self.session = requests.Session()
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.verify_ssl = verify_ssl

        headers = {"User-Agent": user_agent or DEFAULT_USER_AGENT}
        if extra_headers:
            headers.update(extra_headers)
        self.session.headers.update(headers)

        if cookies:
            self.session.cookies.update(cookies)

        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

    def get(self, url, params=None):
        return self.session.get(
            url, params=params, timeout=self.timeout, verify=self.verify_ssl
        )

    def post(self, url, data=None):
        return self.session.post(
            url, data=data, timeout=self.timeout, verify=self.verify_ssl
        )
