"""Adapter for Module 2 - Authentication Assessment."""

from __future__ import annotations

from typing import Any

from modules.auth_engine import assess_authentication


def run(
    target_url: str,
    http_client: Any,
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run safe authentication checks and return reporter-compatible findings."""

    return assess_authentication(
        target_url=target_url,
        http_client=http_client,
        options=options or {},
    )
