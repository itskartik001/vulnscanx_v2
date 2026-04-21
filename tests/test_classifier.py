"""Tests for AI classifier."""
import sys; sys.path.insert(0, '.')
from core.models import Finding
from core.config import Severity
from ai.classifier import VulnClassifier


def test_heuristic_sqli():
    clf = VulnClassifier()
    f = Finding(title="SQL Injection in param", category="SQL Injection", cvss_score=9.0)
    sev, conf = clf.predict(f)
    assert sev == Severity.CRITICAL
    assert conf > 0.5


def test_heuristic_xss():
    clf = VulnClassifier()
    f = Finding(title="Reflected XSS", category="Cross-Site Scripting", cvss_score=7.5)
    sev, conf = clf.predict(f)
    assert sev in (Severity.HIGH, Severity.MEDIUM)


def test_heuristic_info():
    clf = VulnClassifier()
    f = Finding(title="Subdomain found", category="Recon", cvss_score=0.0)
    sev, conf = clf.predict(f)
    assert sev == Severity.INFO
