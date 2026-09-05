"""Adapter for Module 5 - Information Disclosure."""

from __future__ import annotations

from typing import Any

from modules.disclosure_engine import scan_information_disclosure


def run(
    target_url: str,
    http_client: Any,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run safe, explicit-path information-disclosure checks."""

    return scan_information_disclosure(
        target_url=target_url,
        http_client=http_client,
        options=options or {},
    )
