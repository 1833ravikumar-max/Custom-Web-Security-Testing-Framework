"""
Safe information-disclosure scanner.

Checks a small explicit list for:
- robots.txt and sitemap.xml
- exposed .git metadata
- exposed environment/configuration files
- backup archives and SQL dumps
- phpinfo pages
- directory listing

Requests are GET-only, redirects are not followed, and only the first 64 KiB
of a response is read to avoid downloading large files.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

from utils.logger import log


MAX_RESPONSE_BYTES = 64 * 1024

REMEDIATION = (
    "Remove the exposed resource from the web root, deny public access at the "
    "web-server level, disable directory listing, and keep secrets and backup "
    "files outside publicly served directories. Rotate any credentials or "
    "tokens that may have been exposed."
)


@dataclass(frozen=True)
class Candidate:
    path: str
    category: str


BASE_CANDIDATES = (
    Candidate("robots.txt", "robots"),
    Candidate("sitemap.xml", "sitemap"),
    Candidate(".git/HEAD", "git_head"),
    Candidate(".git/config", "git_config"),
    Candidate(".env", "environment"),
    Candidate(".env.local", "environment"),
    Candidate("config.php.bak", "configuration"),
    Candidate("config.php~", "configuration"),
    Candidate("web.config", "configuration"),
    Candidate("web.config.bak", "configuration"),
    Candidate("phpinfo.php", "phpinfo"),
    Candidate("info.php", "phpinfo"),
    Candidate("backup.zip", "backup"),
    Candidate("site.zip", "backup"),
    Candidate("database.sql", "sql_dump"),
    Candidate("db.sql", "sql_dump"),
)


def scan_information_disclosure(
    target_url: str,
    http_client: Any,
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    """Check an explicit, limited set of disclosure paths."""

    root_url = _origin_root(target_url)
    candidates = list(BASE_CANDIDATES)
    candidates.extend(_target_specific_candidates(target_url))

    max_paths = options.get("disclosure_max_paths", len(candidates))

    try:
        max_paths = max(1, min(int(max_paths), len(candidates)))
    except (TypeError, ValueError):
        max_paths = len(candidates)

    candidates = _deduplicate_candidates(candidates)[:max_paths]

    log(
        f"[disclosure] Checking {len(candidates)} explicit path(s) on "
        f"{root_url}",
        "info",
    )

    baseline_url = urljoin(
        root_url,
        f".wsf-not-found-{secrets.token_hex(8)}",
    )
    baseline = _limited_get(http_client, baseline_url)
    baseline_fingerprint = _fingerprint(baseline.body) if baseline else None

    findings: list[dict[str, Any]] = []

    directory_url = _target_directory_url(target_url)
    directory_response = _limited_get(http_client, directory_url)

    if directory_response:
        directory_finding = _analyze_directory_listing(
            directory_url,
            directory_response,
        )
        if directory_finding:
            findings.append(directory_finding)

    for candidate in candidates:
        url = urljoin(root_url, candidate.path)
        response = _limited_get(http_client, url)

        if response is None:
            continue

        if response.status_code in {301, 302, 303, 307, 308, 401, 403, 404}:
            continue

        if response.status_code not in {200, 206}:
            continue

        if (
            baseline_fingerprint
            and _fingerprint(response.body) == baseline_fingerprint
        ):
            continue

        finding = _analyze_candidate(url, candidate, response)

        if finding:
            findings.append(finding)

    return _deduplicate_findings(findings)


@dataclass
class LimitedResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


def _limited_get(http_client: Any, url: str) -> LimitedResponse | None:
    """GET a URL without redirects and read at most MAX_RESPONSE_BYTES."""

    response = None

    try:
        response = http_client.session.get(
            url,
            timeout=getattr(http_client, "timeout", 10),
            verify=getattr(http_client, "verify_ssl", True),
            allow_redirects=False,
            stream=True,
        )

        chunks: list[bytes] = []
        total = 0

        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue

            remaining = MAX_RESPONSE_BYTES - total

            if remaining <= 0:
                break

            chunks.append(chunk[:remaining])
            total += min(len(chunk), remaining)

            if total >= MAX_RESPONSE_BYTES:
                break

        return LimitedResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=b"".join(chunks),
        )

    except Exception:
        return None

    finally:
        if response is not None:
            response.close()


def _analyze_candidate(
    url: str,
    candidate: Candidate,
    response: LimitedResponse,
) -> dict[str, Any] | None:
    text = response.body.decode("utf-8", errors="replace")
    lower = text.lower()
    content_type = response.headers.get("Content-Type", "").lower()

    if candidate.category == "robots" and "user-agent:" in lower:
        return _finding(
            "Exposed robots.txt",
            candidate.path,
            "Info",
            url,
            _snippet(text, "user-agent:"),
        )

    if candidate.category == "sitemap" and (
        "<urlset" in lower or "<sitemapindex" in lower
    ):
        marker = "<urlset" if "<urlset" in lower else "<sitemapindex"
        return _finding(
            "Exposed sitemap.xml",
            candidate.path,
            "Info",
            url,
            _snippet(text, marker),
        )

    if candidate.category == "git_head" and "ref: refs/" in lower:
        return _finding(
            "Exposed Git Repository Metadata",
            candidate.path,
            "High",
            url,
            _snippet(text, "ref: refs/"),
        )

    if candidate.category == "git_config" and (
        "[core]" in lower and "repositoryformatversion" in lower
    ):
        return _finding(
            "Exposed Git Configuration",
            candidate.path,
            "High",
            url,
            _snippet(text, "[core]"),
        )

    if candidate.category == "environment":
        marker = _first_marker(
            lower,
            (
                "app_key=",
                "secret_key=",
                "db_password=",
                "database_url=",
                "aws_access_key_id=",
            ),
        )

        if marker:
            return _finding(
                "Exposed Environment Configuration File",
                candidate.path,
                "High",
                url,
                _redacted_configuration_evidence(text, marker),
            )

    if candidate.category == "configuration":
        marker = _first_marker(
            lower,
            (
                "db_password",
                "database_password",
                "$db_password",
                "<connectionstrings",
                "connectionstring=",
                "secret_key",
            ),
        )

        if marker:
            return _finding(
                "Exposed Application Configuration File",
                candidate.path,
                "High",
                url,
                _redacted_configuration_evidence(text, marker),
            )

    if candidate.category == "phpinfo" and (
        "phpinfo()" in lower
        or ("php version" in lower and "configuration file" in lower)
    ):
        marker = "phpinfo()" if "phpinfo()" in lower else "php version"
        return _finding(
            "Exposed PHP Information Page",
            candidate.path,
            "Medium",
            url,
            _snippet(text, marker),
        )

    if candidate.category == "backup" and (
        response.body.startswith(b"PK\x03\x04")
        or "application/zip" in content_type
        or "application/x-zip" in content_type
    ):
        return _finding(
            "Publicly Accessible Backup Archive",
            candidate.path,
            "High",
            url,
            "The response has a ZIP archive signature or ZIP content type; "
            "archive contents were not downloaded beyond the response limit.",
        )

    if candidate.category == "sql_dump":
        marker = _first_marker(
            lower,
            (
                "-- mysql dump",
                "create table",
                "insert into",
                "postgresql database dump",
            ),
        )

        if marker:
            return _finding(
                "Publicly Accessible Database Dump",
                candidate.path,
                "High",
                url,
                _snippet(text, marker),
            )

    return None


def _analyze_directory_listing(
    url: str,
    response: LimitedResponse,
) -> dict[str, Any] | None:
    if response.status_code not in {200, 206}:
        return None

    text = response.body.decode("utf-8", errors="replace")
    lower = text.lower()

    marker = _first_marker(
        lower,
        (
            "<title>index of /",
            "<h1>index of /",
            "directory listing for",
        ),
    )

    if not marker:
        return None

    return _finding(
        "Directory Listing Enabled",
        urlparse(url).path or "/",
        "Medium",
        url,
        _snippet(text, marker),
    )


def _finding(
    title: str,
    path: str,
    severity: str,
    url: str,
    evidence: str,
) -> dict[str, Any]:
    return {
        "type": title,
        "vulnerability_type": title,
        "parameter": path,
        "method": "GET",
        "severity": severity,
        "evidence": evidence,
        "location": url,
        "remediation": REMEDIATION,
    }


def _origin_root(target_url: str) -> str:
    parsed = urlparse(target_url)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _target_directory_url(target_url: str) -> str:
    parsed = urlparse(target_url)
    path = parsed.path or "/"

    if not path.endswith("/"):
        path = os.path.dirname(path).rstrip("/") + "/"

    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _target_specific_candidates(target_url: str) -> list[Candidate]:
    parsed = urlparse(target_url)
    basename = os.path.basename(parsed.path)

    if not basename or "." not in basename:
        return []

    relative_path = parsed.path.lstrip("/")

    return [
        Candidate(f"{relative_path}.bak", "configuration"),
        Candidate(f"{relative_path}~", "configuration"),
    ]


def _deduplicate_candidates(candidates: list[Candidate]) -> list[Candidate]:
    unique: dict[str, Candidate] = {}

    for candidate in candidates:
        unique[candidate.path] = candidate

    return list(unique.values())


def _deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}

    for finding in findings:
        key = (
            finding.get("vulnerability_type", ""),
            finding.get("location", ""),
        )
        unique[key] = finding

    return list(unique.values())


def _fingerprint(body: bytes) -> str:
    normalized = b" ".join(body.split())[:8192]
    return hashlib.sha256(normalized).hexdigest()


def _first_marker(text: str, markers: tuple[str, ...]) -> str | None:
    return next((marker for marker in markers if marker in text), None)


def _snippet(text: str, marker: str, context: int = 100) -> str:
    lower = text.lower()
    index = lower.find(marker.lower())

    if index < 0:
        return marker

    start = max(0, index - context)
    end = min(len(text), index + len(marker) + context)
    return " ".join(text[start:end].split())[:350]


def _redacted_configuration_evidence(text: str, marker: str) -> str:
    """Report the key name without exposing the secret value."""

    del text
    return (
        f"Sensitive configuration marker '{marker}' was found; "
        "the associated value was intentionally redacted."
    )
