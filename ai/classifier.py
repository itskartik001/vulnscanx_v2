"""
VulnScanX - AI Vulnerability Classifier
=========================================
ML-based severity classification using scikit-learn.
Falls back to heuristic rules if model not trained yet.
"""
import os
import json
import pickle
import numpy as np
from pathlib import Path
from core.models import Finding
from core.config import Severity

MODEL_PATH = Path(__file__).parent / "model.pkl"
FEATURES_PATH = Path(__file__).parent / "feature_config.json"


class VulnClassifier:
    """
    Two-stage classifier:
    1. Attempts to load a trained sklearn model (if available)
    2. Falls back to a rule-based heuristic system
    """

    CATEGORY_SCORES = {
        "sql injection": 9.5,
        "command injection": 9.8,
        "path traversal": 8.0,
        "cross-site scripting": 7.5,
        "xss": 7.5,
        "open redirect": 6.1,
        "csrf": 6.5,
        "ssrf": 8.6,
        "xxe": 8.0,
        "idor": 8.1,
        "authentication": 7.0,
        "broken access control": 7.5,
        "misconfiguration": 5.0,
        "information disclosure": 4.0,
        "cryptographic": 7.4,
        "subdomain": 0.0,
        "recon": 0.0,
        "port": 4.0,
    }

    def __init__(self):
        self.model = None
        self._try_load_model()

    def _try_load_model(self):
        try:
            if MODEL_PATH.exists():
                with open(MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
        except Exception:
            pass

    def predict(self, finding: Finding):
        """Returns (severity_label, confidence_score)."""
        if self.model:
            try:
                features = self._extract_features(finding)
                proba = self.model.predict_proba([features])[0]
                label_idx = np.argmax(proba)
                labels = self.model.classes_
                return labels[label_idx], float(proba[label_idx])
            except Exception:
                pass
        # Fallback to heuristics
        return self._heuristic_classify(finding)

    def _heuristic_classify(self, finding: Finding):
        """
        Rule-based fallback classification using category + CVSS score.
        Returns (severity, confidence).
        """
        title_lower = finding.title.lower()
        cat_lower = finding.category.lower()

        # Match against known categories
        for keyword, base_score in self.CATEGORY_SCORES.items():
            if keyword in title_lower or keyword in cat_lower:
                severity = self._score_to_severity(base_score)
                confidence = 0.82
                return severity, confidence

        # Use existing CVSS score if available
        if finding.cvss_score > 0:
            severity = self._score_to_severity(finding.cvss_score)
            return severity, 0.70

        return finding.severity, 0.50

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0: return Severity.CRITICAL
        if score >= 7.0: return Severity.HIGH
        if score >= 4.0: return Severity.MEDIUM
        if score > 0.0:  return Severity.LOW
        return Severity.INFO

    def _extract_features(self, finding: Finding) -> list:
        """Extract numerical features for ML model."""
        return [
            finding.cvss_score,
            len(finding.title),
            1 if finding.parameter else 0,
            1 if finding.payload_used else 0,
            len(finding.description),
            hash(finding.category) % 100,
        ]

    def train(self, training_data: list):
        """
        Train the classifier on labeled data.
        training_data: list of (Finding, severity_label) tuples
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder

        X = [self._extract_features(f) for f, _ in training_data]
        y = [label for _, label in training_data]

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X, y)

        with open(MODEL_PATH, "wb") as f:
            pickle.dump(clf, f)

        self.model = clf
        return clf
