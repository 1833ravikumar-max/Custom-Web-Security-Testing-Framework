"""
param_discovery.py
-------------------
Discovers injectable parameters on a target page:

  - GET parameters : parsed straight from the target URL's query string
  - POST parameters: discovered by fetching the page and parsing any
                      <form> elements found in the HTML

This keeps discovery separate from testing (xss.py), so it can later be
reused by other modules (e.g. SQLi testing) without duplication.
"""

from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup


def discover_get_params(target_url: str):
    """Return a list of GET parameter names found in the target URL's query string."""
    parsed = urlparse(target_url)
    query_params = parse_qs(parsed.query)
    return list(query_params.keys())


def discover_post_forms(target_url: str, http_client):
    """
    Fetch the target page and extract every <form> on it.

    Returns a list of dicts:
        {
            "action": <absolute URL the form submits to>,
            "method": "get" | "post",
            "inputs": [input_name, input_name, ...]
        }
    """
    forms = []
    try:
        response = http_client.get(target_url)
    except Exception:
        return forms

    soup = BeautifulSoup(response.text, "html.parser")
    for form in soup.find_all("form"):
        action = form.get("action") or target_url
        action_url = urljoin(target_url, action)
        method = (form.get("method") or "get").lower()

        input_names = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                input_names.append(name)

        if input_names:
            forms.append({
                "action": action_url,
                "method": method,
                "inputs": input_names,
            })

    return forms
