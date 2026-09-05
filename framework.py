#!/usr/bin/env python3

"""
Modular Web Security Testing Framework

Supported modules:
    xss
    headers
    sqli
    auth
    disclosure
    all

Only scan systems that you own or are explicitly authorized to test.
"""

import argparse
import importlib
import json
import os
import sys
from datetime import datetime, timezone

from utils import auth
from utils.http_client import HttpClient
from utils.logger import log
from utils.reporter import (
    build_report_data,
    save_html_report,
    save_json_report,
)


MODULES = {
    "xss": "modules.xss",
    "headers": "modules.headers",
    "sqli": "modules.sqli",
    "auth": "modules.auth",
    "disclosure": "modules.disclosure",
}


def load_config(config_path):
    """Load optional JSON configuration."""

    if not config_path or not os.path.exists(config_path):
        return {}

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, dict):
            log(
                "Configuration file must contain a JSON object.",
                "warning",
            )
            return {}

        data.pop("_comment", None)
        return data

    except Exception as exc:
        log(
            f"Could not load configuration: {exc}",
            "warning",
        )
        return {}


def parse_cookie_string(cookie_string):
    """Convert cookie text into a dictionary."""

    cookies = {}

    if not cookie_string:
        return cookies

    for part in cookie_string.split(";"):
        if "=" in part:
            key, value = part.strip().split("=", 1)
            cookies[key.strip()] = value.strip()

    return cookies


def parse_header_string(header_string):
    """Convert header text into a dictionary."""

    headers = {}

    if not header_string:
        return headers

    for part in header_string.split(";"):
        if ":" in part:
            key, value = part.split(":", 1)
            headers[key.strip()] = value.strip()

    return headers


def build_parser(config):
    """Build the command-line parser."""

    parser = argparse.ArgumentParser(
        description="Modular Web Security Testing Framework"
    )

    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to a JSON configuration file.",
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target URL, including http:// or https://.",
    )

    parser.add_argument(
        "--module",
        required=True,
        choices=[
            *MODULES.keys(),
            "all",
        ],
        help="Module to run.",
    )

    parser.add_argument(
        "--format",
        choices=[
            "html",
            "json",
            "both",
        ],
        default="both",
        help="Report format.",
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for generated reports.",
    )

    parser.add_argument(
        "--user-agent",
        default=None,
        help="Custom User-Agent header.",
    )

    parser.add_argument(
        "--cookie",
        default=None,
        help="Cookies, for example: PHPSESSID=abc123.",
    )

    parser.add_argument(
        "--header",
        default=None,
        help="Extra headers separated by semicolons.",
    )

    parser.add_argument(
        "--proxy",
        default=None,
        help="Proxy URL, for example: http://127.0.0.1:8080.",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds.",
    )

    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable SSL certificate verification.",
    )

    parser.add_argument(
        "--login-url",
        default=None,
        help="Login page URL for authenticated scans.",
    )

    parser.add_argument(
        "--username",
        default=None,
        help="Login username.",
    )

    parser.add_argument(
        "--password",
        default=None,
        help="Login password.",
    )

    parser.add_argument(
        "--username-field",
        default="username",
        help="Username form field name.",
    )

    parser.add_argument(
        "--password-field",
        default="password",
        help="Password form field name.",
    )

    parser.add_argument(
        "--csrf-field",
        default="user_token",
        help="CSRF token form field name.",
    )

    parser.add_argument(
        "--security-level",
        choices=[
            "low",
            "medium",
            "high",
            "impossible",
        ],
        default=None,
        help="DVWA security level.",
    )

    if config:
        parser.set_defaults(**config)

    return parser


def create_http_client(args):
    """Create one shared HTTP client for all modules."""

    return HttpClient(
        user_agent=args.user_agent,
        timeout=args.timeout,
        cookies=parse_cookie_string(args.cookie),
        extra_headers=parse_header_string(args.header),
        proxy=args.proxy,
        verify_ssl=not args.no_verify_ssl,
    )


def authenticate_if_requested(args, client):
    """Authenticate when login options are supplied."""

    if not args.login_url:
        return True

    if not args.username or not args.password:
        log(
            "--login-url requires both --username and --password.",
            "danger",
        )
        return False

    success = auth.login(
        client,
        args.login_url,
        args.username,
        args.password,
        username_field=args.username_field,
        password_field=args.password_field,
        csrf_field=args.csrf_field,
    )

    if not success:
        log(
            "Login failed. Results may be inaccurate.",
            "warning",
        )
        return False

    if args.security_level:
        auth.set_security_level(
            client,
            args.login_url,
            args.security_level,
            args.csrf_field,
        )

    return True


def run_selected_modules(args, client):
    """Run one selected module or all modules."""

    if args.module == "all":
        selected_modules = list(MODULES.keys())
    else:
        selected_modules = [args.module]

    all_findings = []
    modules_executed = []
    failed_modules = []

    for module_name in selected_modules:
        module_path = MODULES[module_name]

        try:
            module = importlib.import_module(module_path)

        except Exception as exc:
            log(
                f"Could not import module '{module_name}': {exc}",
                "danger",
            )
            failed_modules.append(module_name)
            continue

        try:
            log(
                f"Running module: {module_name}",
                "info",
            )

            runner = getattr(module, "run", None)

            if not callable(runner):
                raise AttributeError(
                    f"{module_path} does not contain a callable run() function."
                )

            module_findings = runner(
                args.target,
                client,
            )

            if module_findings is None:
                module_findings = []

            if not isinstance(module_findings, list):
                raise TypeError(
                    "Module must return a list of findings."
                )

            for finding in module_findings:
                if not isinstance(finding, dict):
                    raise TypeError(
                        "Every module finding must be a dictionary."
                    )

            all_findings.extend(module_findings)
            modules_executed.append(module_name)

            log(
                f"Module completed: {module_name}",
                "success",
            )

            log(
                f"Findings from {module_name}: "
                f"{len(module_findings)}",
                "info",
            )

        except Exception as exc:
            log(
                f"Module '{module_name}' failed: {exc}",
                "danger",
            )
            failed_modules.append(module_name)

    return (
        all_findings,
        modules_executed,
        failed_modules,
    )


def create_unique_report_base(output_dir, module_name):
    """Create a unique report filename base."""

    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d_%H%M%S"
    )

    safe_module_name = (
        module_name
        .replace("/", "_")
        .replace(" ", "_")
    )

    base_name = (
        f"scan_{safe_module_name}_{timestamp}"
    )

    base_path = os.path.join(
        output_dir,
        base_name,
    )

    counter = 1

    while (
        os.path.exists(base_path + ".json")
        or os.path.exists(base_path + ".html")
    ):
        base_path = os.path.join(
            output_dir,
            f"{base_name}_{counter}",
        )

        counter += 1

    return base_path


def save_reports(args, report_data):
    """Save reports without overwriting previous reports."""

    os.makedirs(
        args.output_dir,
        exist_ok=True,
    )

    base_path = create_unique_report_base(
        args.output_dir,
        args.module,
    )

    if args.format in (
        "json",
        "both",
    ):
        json_path = base_path + ".json"

        save_json_report(
            report_data,
            json_path,
        )

        log(
            f"JSON report saved to {json_path}",
            "success",
        )

    if args.format in (
        "html",
        "both",
    ):
        html_path = base_path + ".html"

        save_html_report(
            report_data,
            html_path,
        )

        log(
            f"HTML report saved to {html_path}",
            "success",
        )


def main():
    """Main application entry point."""

    pre_parser = argparse.ArgumentParser(
        add_help=False
    )

    pre_parser.add_argument(
        "--config",
        default="config.json",
    )

    pre_args, _ = pre_parser.parse_known_args()

    config = load_config(
        pre_args.config
    )

    parser = build_parser(config)
    args = parser.parse_args()

    if not args.target.startswith(
        (
            "http://",
            "https://",
        )
    ):
        log(
            "Target must start with http:// or https://.",
            "danger",
        )
        sys.exit(1)

    if args.timeout <= 0:
        log(
            "Timeout must be greater than zero.",
            "danger",
        )
        sys.exit(1)

    client = create_http_client(args)

    log(
        f"Target: {args.target}",
        "info",
    )

    log(
        f"Selected module: {args.module}",
        "info",
    )

    if args.login_url:
        authenticated = authenticate_if_requested(
            args,
            client,
        )

        if not authenticated:
            log(
                "Continuing without a confirmed authenticated session.",
                "warning",
            )

    (
        findings,
        modules_executed,
        failed_modules,
    ) = run_selected_modules(
        args,
        client,
    )

    if not modules_executed:
        log(
            "No module completed successfully.",
            "danger",
        )
        sys.exit(1)

    report_data = build_report_data(
        args.target,
        modules_executed,
        findings,
    )

    save_reports(
        args,
        report_data,
    )

    log(
        f"Total findings: {len(findings)}",
        "info",
    )

    log(
        f"Overall Risk Rating: "
        f"{report_data['overall_risk_rating']}",
        "info",
    )

    if failed_modules:
        log(
            "Failed modules: "
            + ", ".join(failed_modules),
            "warning",
        )


if __name__ == "__main__":
    main()
