"""Tests for utility helpers."""
import sys; sys.path.insert(0, '.')
from utils.helpers import normalize_url, extract_domain, is_valid_url, parse_severity_from_cvss


def test_normalize_url():
    assert normalize_url("example.com") == "https://example.com"
    assert normalize_url("http://example.com/") == "http://example.com"
    assert normalize_url("https://example.com") == "https://example.com"


def test_extract_domain():
    assert extract_domain("https://example.com/path?q=1") == "example.com"
    assert extract_domain("http://sub.example.com") == "sub.example.com"


def test_is_valid_url():
    assert is_valid_url("https://example.com")
    assert not is_valid_url("notaurl")
    assert not is_valid_url("")


def test_severity_from_cvss():
    assert parse_severity_from_cvss(9.5) == "CRITICAL"
    assert parse_severity_from_cvss(7.5) == "HIGH"
    assert parse_severity_from_cvss(5.0) == "MEDIUM"
    assert parse_severity_from_cvss(2.0) == "LOW"
    assert parse_severity_from_cvss(0.0) == "INFO"
