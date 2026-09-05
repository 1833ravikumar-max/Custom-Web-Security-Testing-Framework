"""
logger.py
----------
Minimal colored terminal output helper (no external dependency required).
"""

RESET = "\033[0m"
COLORS = {
    "info": "\033[94m",     # blue
    "success": "\033[92m",  # green
    "warning": "\033[93m",  # yellow
    "danger": "\033[91m",   # red
    "muted": "\033[90m",    # grey
}


def log(message: str, level: str = "info"):
    color = COLORS.get(level, "")
    print(f"{color}{message}{RESET}")
