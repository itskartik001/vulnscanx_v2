"""
VulnScanX - Utility Helpers
"""
import re
import socket
import urllib.parse
from typing import Optional, Tuple


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def extract_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(normalize_url(url))
    return parsed.netloc or parsed.path


def is_valid_url(url: str) -> bool:
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def truncate(text: str, max_len: int = 200) -> str:
    return text[:max_len] + "..." if len(text) > max_len else text


def resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def parse_severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "INFO"


def inject_payload(url: str, param: str, payload: str) -> str:
    """Inject a payload into a specific URL parameter."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def get_all_params(url: str) -> dict:
    parsed = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def sanitize_filename(name: str) -> str:
    return re.sub(r'[^\w\-_.]', '_', name)
