<div align="center">

# Custom Web Security Testing Framework

A modular Python command-line framework for safe and authorized web application security testing.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20WSL-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-success)
![Testing](https://img.shields.io/badge/Testing-Authorized%20Targets%20Only-red)

</div>

## Overview

Custom Web Security Testing Framework is a modular Python security scanner developed for the **ITSOLERA Summer Internship 2026**.

It automates safe checks for common web application security weaknesses while maintaining a clean module structure, shared authenticated HTTP sessions, and professional HTML and JSON reporting.

The framework is intended for educational labs, intentionally vulnerable applications, and systems where the tester has explicit authorization.

## Features

* Modular command-line architecture
* Shared HTTP session across modules
* Authenticated DVWA scanning
* Custom cookies and request headers
* Custom User-Agent support
* Proxy and Burp Suite support
* Configurable request timeout
* Optional SSL verification control
* HTML and JSON report generation
* Unique timestamped report filenames
* Evidence and remediation for each finding
* Overall risk rating calculation

## Security Modules

| Module       | Description                                                                                                                                             |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `headers`    | Checks important HTTP security headers and reports missing or weak configurations                                                                       |
| `auth`       | Assesses login forms, password-policy indicators, response differences, username-enumeration signals, lockout indicators, and session-cookie attributes |
| `xss`        | Tests discovered GET and POST parameters for reflected Cross-Site Scripting using safe payloads                                                         |
| `sqli`       | Performs non-destructive SQL Injection checks using error detection and response comparison                                                             |
| `disclosure` | Detects exposed resources such as `robots.txt`, `sitemap.xml`, `.git`, backup files, configuration files, directory listings, and `phpinfo.php`         |

## Safety Notice

> Use this framework only against applications you own, intentionally vulnerable security labs, or systems for which you have explicit authorization.

Unauthorized security testing may be illegal and unethical.

Recommended practice targets include:

* DVWA
* OWASP Juice Shop
* bWAPP
* WebGoat
* Mutillidae

The framework does not perform destructive exploitation, database modification, password brute forcing, or automatic submission of destructive forms.

## Requirements

* Python 3.10 or newer
* Git
* Linux, Kali Linux, Ubuntu, or WSL
* An authorized testing target

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/1833ravikumar-max/Custom-Web-Security-Testing-Framework.git
cd Custom-Web-Security-Testing-Framework
```

### 2. Install Python virtual-environment support

On Kali Linux, Ubuntu, or WSL:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

### 3. Create a virtual environment

```bash
python3 -m venv .venv
```

### 4. Activate the virtual environment

```bash
source .venv/bin/activate
```

### 5. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 6. Confirm installation

```bash
python framework.py --help
```

The available modules should include:

```text
xss
headers
sqli
auth
disclosure
all
```

## Basic Usage

```bash
python framework.py \
  --target TARGET_URL \
  --module MODULE_NAME \
  --format both
```

Example:

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module headers \
  --format both
```

## Module Examples

The examples below assume DVWA is running locally at:

```text
http://127.0.0.1:4280/
```

### Security Headers

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module headers \
  --format both
```

### Authentication Assessment

Use the login page as the target:

```bash
python framework.py \
  --target http://127.0.0.1:4280/login.php \
  --module auth \
  --format both
```

The Authentication Assessment module performs only a small number of controlled checks. It does not brute-force passwords.

### Reflected XSS

```bash
python framework.py \
  --target "http://127.0.0.1:4280/vulnerabilities/xss_r/?name=test" \
  --module xss \
  --login-url http://127.0.0.1:4280/login.php \
  --username admin \
  --password password \
  --security-level low \
  --format both
```

### SQL Injection

```bash
python framework.py \
  --target "http://127.0.0.1:4280/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --module sqli \
  --login-url http://127.0.0.1:4280/login.php \
  --username admin \
  --password password \
  --security-level low \
  --format both
```

### Information Disclosure

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module disclosure \
  --format both
```

The disclosure module checks a small, predefined set of common exposed resources. It does not aggressively crawl the target.

### Run All Modules

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module all \
  --format both
```

Some modules require a specific vulnerable endpoint or URL parameter. Running `all` against the site homepage may therefore produce zero findings for XSS or SQL Injection.

## Authenticated Scanning

The framework can log in to DVWA and reuse the authenticated session:

```bash
python framework.py \
  --target TARGET_URL \
  --module MODULE_NAME \
  --login-url http://127.0.0.1:4280/login.php \
  --username admin \
  --password password \
  --security-level low \
  --format both
```

Supported DVWA security levels:

```text
low
medium
high
impossible
```

## Additional Options

### Custom User-Agent

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module headers \
  --user-agent "ITSOLERA-WSF/1.0"
```

### Custom Cookie

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module headers \
  --cookie "PHPSESSID=example"
```

### Custom Header

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module headers \
  --header "X-Lab: ITSOLERA; Accept-Language: en"
```

### Burp Suite Proxy

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module headers \
  --proxy http://127.0.0.1:8080 \
  --no-verify-ssl
```

### Custom Timeout

```bash
python framework.py \
  --target http://127.0.0.1:4280/ \
  --module disclosure \
  --timeout 15
```

## Reports

Reports are generated inside the `reports/` directory.

Example filenames:

```text
reports/scan_headers_20260722_095955.html
reports/scan_headers_20260722_095955.json
```

Each report includes:

* Target URL
* Scan date
* Modules executed
* Number of findings
* Finding type
* Parameter
* HTTP method
* Severity
* Evidence
* Remediation
* Overall risk rating

Open the newest HTML report from WSL:

```bash
explorer.exe "$(wslpath -w "$(ls -t reports/*.html | head -1)")"
```

Format JSON for terminal viewing:

```bash
python -m json.tool "$(ls -t reports/*.json | head -1)"
```

## Project Structure

```text
Custom-Web-Security-Testing-Framework/
├── framework.py
├── config.json
├── requirements.txt
├── README.md
├── modules/
│   ├── __init__.py
│   ├── headers.py
│   ├── headers_engine.py
│   ├── auth.py
│   ├── auth_engine.py
│   ├── xss.py
│   ├── sqli.py
│   ├── sqli_engine.py
│   ├── disclosure.py
│   └── disclosure_engine.py
├── utils/
│   ├── __init__.py
│   ├── auth.py
│   ├── http_client.py
│   ├── logger.py
│   ├── param_discovery.py
│   ├── payloads.py
│   └── reporter.py
└── reports/
    ├── sample_report.html
    └── sample_report.json
```

## Important Note About Authentication Files

The project contains two files with similar names:

```text
modules/auth.py
utils/auth.py
```

Their purposes are different:

* `modules/auth.py` performs the Authentication Assessment.
* `utils/auth.py` handles login automation and authenticated session setup.

Neither file should replace the other.

## Testing the Framework

Check all Python files for syntax errors:

```bash
python -m py_compile framework.py modules/*.py utils/*.py
```

Test each module separately:

```bash
python framework.py --target http://127.0.0.1:4280/ --module headers
python framework.py --target http://127.0.0.1:4280/login.php --module auth
python framework.py --target http://127.0.0.1:4280/ --module disclosure
```

Automated findings should always be manually verified before being treated as confirmed vulnerabilities.

## Limitations

* The framework is intended as an educational security-testing project.
* It does not replace a professional penetration test.
* Results may include false positives or false negatives.
* The authentication module does not perform password brute forcing.
* The disclosure module uses a limited predefined path list.
* XSS and SQL Injection checks require suitable target parameters.
* Some authenticated applications require custom login field names.

## Team and Attribution

Developed as part of the **ITSOLERA Summer Internship 2026 — Offensive Security Task 2**.

**Repository owner and maintainer:** Muhammad Abdullah
**GitHub:** [abdullahcyberx](https://github.com/abdullahcyberx)

This project was developed collaboratively by the internship team. Contributions should be properly attributed through Git commits and pull requests.

## Responsible Disclosure

When the framework identifies a weakness in an authorized system:

1. Verify the result manually.
2. Save only the evidence needed to demonstrate the problem.
3. Avoid accessing unnecessary sensitive information.
4. Report the issue privately to the system owner.
5. Allow reasonable time for remediation.
6. Retest only after receiving authorization.

---

<div align="center">

**Built for authorized security testing and cybersecurity education.**

</div>
