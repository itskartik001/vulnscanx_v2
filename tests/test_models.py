"""Tests for core data models."""
import sys; sys.path.insert(0, '.')
import pytest
from core.models import Finding, ScanResult
from core.config import Severity


def test_finding_creation():
    f = Finding(title="Test XSS", severity=Severity.HIGH, cvss_score=8.0)
    assert f.title == "Test XSS"
    assert f.severity == Severity.HIGH
    assert f.id is not None
    assert len(f.id) == 8


def test_scan_result_dedup():
    result = ScanResult(target="example.com")
    f1 = Finding(title="XSS", url="http://example.com", parameter="q")
    f2 = Finding(title="XSS", url="http://example.com", parameter="q")  # duplicate
    f3 = Finding(title="SQLi", url="http://example.com", parameter="id")

    result.add_finding(f1)
    result.add_finding(f2)  # should be deduped
    result.add_finding(f3)

    assert len(result.findings) == 2


def test_scan_result_stats():
    result = ScanResult(target="example.com")
    result.add_finding(Finding(title="A", severity=Severity.CRITICAL, url="u1"))
    result.add_finding(Finding(title="B", severity=Severity.HIGH, url="u2"))
    result.add_finding(Finding(title="C", severity=Severity.MEDIUM, url="u3"))

    stats = result.stats
    assert stats["CRITICAL"] == 1
    assert stats["HIGH"] == 1
    assert stats["MEDIUM"] == 1
    assert stats["total"] == 3


def test_risk_score():
    result = ScanResult(target="example.com")
    result.add_finding(Finding(title="Critical", severity=Severity.CRITICAL, url="u1"))
    assert result.risk_score > 0


def test_finding_to_dict():
    f = Finding(title="Test", severity=Severity.LOW)
    d = f.to_dict()
    assert d["title"] == "Test"
    assert d["severity"] == Severity.LOW


def test_scan_sort():
    result = ScanResult(target="example.com")
    result.add_finding(Finding(title="Low", severity=Severity.LOW, url="u1"))
    result.add_finding(Finding(title="Critical", severity=Severity.CRITICAL, url="u2"))
    result.sort_findings()
    assert result.findings[0].severity == Severity.CRITICAL
