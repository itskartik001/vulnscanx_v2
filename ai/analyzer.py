"""
VulnScanX — AI/ML Vulnerability Classifier & Explainer
=========================================================
Lightweight ML model that:
  1. Classifies vulnerability severity using feature engineering + Random Forest
  2. Explains findings in human-readable analyst language
  3. Detects anomaly patterns via Isolation Forest

No GPU required. Pure scikit-learn.
"""

import json
import logging
import os
import pickle
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("vulnscanx.ai")

# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

VULN_KEYWORDS = {
    "sqli":        ["sql", "injection", "union", "sleep", "waitfor", "pg_sleep", "error-based"],
    "xss":         ["xss", "cross-site", "script", "alert", "onerror", "onload", "reflected", "dom"],
    "rce":         ["rce", "remote code", "command injection", "exec", "shell", "reverse shell"],
    "lfi":         ["lfi", "traversal", "path traversal", "include", "passwd", "win.ini"],
    "auth":        ["authentication", "bypass", "brute force", "default credential", "weak password"],
    "crypto":      ["ssl", "tls", "weak cipher", "rc4", "md5", "sha1", "self-signed"],
    "config":      ["misconfiguration", "exposed", "header", "cors", "csp", "hsts"],
    "network":     ["port", "exposed service", "rdp", "smb", "redis", "mongodb", "elasticsearch"],
    "info_disc":   ["disclosure", "error message", "stack trace", "debug", "phpinfo"],
}

SEVERITY_WEIGHTS = {
    "sqli":      9.0,
    "xss":       7.5,
    "rce":       10.0,
    "lfi":       8.5,
    "auth":      8.0,
    "crypto":    6.0,
    "config":    5.0,
    "network":   7.0,
    "info_disc": 4.0,
}


def extract_features(
    title: str,
    description: str,
    tags: List[str],
    evidence: str = "",
) -> Dict:
    """Extract numeric feature vector from a vulnerability description."""
    text  = " ".join([title, description, evidence, " ".join(tags)]).lower()
    feats = {}

    # Keyword category scores
    for cat, keywords in VULN_KEYWORDS.items():
        feats[f"kw_{cat}"] = sum(1 for kw in keywords if kw in text)

    # Structural signals
    feats["has_payload"]     = int(bool(re.search(r"payload|inject|<script|union select", text)))
    feats["has_evidence"]    = int(bool(evidence and len(evidence) > 10))
    feats["tag_count"]       = len(tags)
    feats["title_len"]       = len(title)
    feats["desc_len"]        = len(description)
    feats["has_cve"]         = int(bool(re.search(r"CVE-\d{4}-\d+", text, re.I)))
    feats["has_auth"]        = int(any(t in text for t in ["authenticated", "unauthenticated"]))
    feats["exploitability"]  = _exploitability_score(text)
    feats["network_exposure"]= int(any(t in tags for t in ["port", "network", "smb", "rdp"]))
    feats["data_exposure"]   = int(any(t in tags for t in ["sqli", "lfi", "rce", "traversal"]))

    return feats


def _exploitability_score(text: str) -> int:
    high_risk = ["confirmed", "exploitable", "unauthenticated", "pre-auth",
                 "remote", "critical", "no credentials", "public exploit"]
    return sum(1 for term in high_risk if term in text)


# ---------------------------------------------------------------------------
# Heuristic Severity Classifier
# ---------------------------------------------------------------------------

class SeverityClassifier:
    """
    Rule-based + weighted heuristic severity classifier.
    Falls back to ML model if trained weights are available.
    """

    MODEL_PATH = Path(__file__).parent / "severity_model.pkl"

    def __init__(self):
        self._model = self._load_model()

    def predict(
        self,
        title:       str,
        description: str,
        tags:        List[str],
        evidence:    str = "",
    ) -> Tuple[str, float, str]:
        """
        Returns: (severity_label, confidence, reason)
        """
        if self._model:
            return self._ml_predict(title, description, tags, evidence)
        return self._heuristic_predict(title, description, tags, evidence)

    def _heuristic_predict(
        self, title: str, description: str, tags: List[str], evidence: str
    ) -> Tuple[str, float, str]:
        feats  = extract_features(title, description, tags, evidence)
        score  = 0.0
        reason = []

        # Category-based scoring
        for cat, keywords in VULN_KEYWORDS.items():
            hits = feats.get(f"kw_{cat}", 0)
            if hits > 0:
                cat_score = SEVERITY_WEIGHTS[cat] * (hits / len(keywords))
                score    += cat_score
                reason.append(f"{cat}({hits} keywords)")

        # Multipliers
        if feats.get("exploitability", 0) >= 2:
            score *= 1.3
            reason.append("high-exploitability-signals")
        if feats.get("network_exposure"):
            score *= 1.15
            reason.append("network-exposed")
        if feats.get("data_exposure"):
            score *= 1.2
            reason.append("data-exposure")

        score = min(score, 10.0)

        if score >= 9.0:
            label, conf = "CRITICAL", 0.95
        elif score >= 7.0:
            label, conf = "HIGH", 0.88
        elif score >= 4.0:
            label, conf = "MEDIUM", 0.80
        elif score >= 1.0:
            label, conf = "LOW", 0.75
        else:
            label, conf = "INFO", 0.95

        return label, conf, " | ".join(reason) or "no-signals"

    def _ml_predict(
        self, title: str, description: str, tags: List[str], evidence: str
    ) -> Tuple[str, float, str]:
        try:
            import numpy as np
            feats  = extract_features(title, description, tags, evidence)
            X      = np.array(list(feats.values())).reshape(1, -1)
            label  = self._model.predict(X)[0]
            proba  = self._model.predict_proba(X)[0]
            conf   = float(max(proba))
            return label, conf, "ml-model"
        except Exception:
            return self._heuristic_predict(title, description, tags, evidence)

    def _load_model(self):
        if self.MODEL_PATH.exists():
            try:
                with open(self.MODEL_PATH, "rb") as f:
                    return pickle.load(f)
            except Exception:
                pass
        return None

    @staticmethod
    def train_and_save(training_data: List[Dict]):
        """
        Train a Random Forest classifier on labeled vulnerability data.
        training_data: list of {title, description, tags, evidence, label}
        """
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import classification_report
            import numpy as np

            X, y = [], []
            for sample in training_data:
                feats = extract_features(
                    sample["title"], sample["description"],
                    sample.get("tags", []), sample.get("evidence", "")
                )
                X.append(list(feats.values()))
                y.append(sample["label"])

            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            clf = RandomForestClassifier(
                n_estimators=100, max_depth=8, random_state=42, n_jobs=-1
            )
            clf.fit(X_train, y_train)

            y_pred = clf.predict(X_test)
            logger.info(f"Model trained:\n{classification_report(y_test, y_pred)}")

            model_path = Path(__file__).parent / "severity_model.pkl"
            with open(model_path, "wb") as f:
                pickle.dump(clf, f)
            logger.info(f"Model saved → {model_path}")
            return clf
        except ImportError:
            logger.warning("scikit-learn not available. Using heuristic classifier.")
            return None


# ---------------------------------------------------------------------------
# Anomaly Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Detects unusual scan patterns using Isolation Forest.
    Can identify potential false positives or unusual finding clusters.
    """

    def __init__(self):
        self._model = None

    def fit(self, findings_data: List[Dict]):
        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np

            vectors = [self._vectorize(f) for f in findings_data]
            X       = np.array(vectors)
            self._model = IsolationForest(contamination=0.1, random_state=42)
            self._model.fit(X)
        except ImportError:
            pass

    def predict(self, finding: Dict) -> bool:
        """Returns True if finding is anomalous (potential false positive)."""
        if not self._model:
            return False
        try:
            import numpy as np
            v = np.array(self._vectorize(finding)).reshape(1, -1)
            return self._model.predict(v)[0] == -1
        except Exception:
            return False

    @staticmethod
    def _vectorize(f: Dict) -> List[float]:
        return [
            len(f.get("title", "")),
            len(f.get("evidence", "")),
            len(f.get("payload", "")),
            len(f.get("tags", [])),
            float(f.get("cvss_score", 0)),
        ]


# ---------------------------------------------------------------------------
# Human-Readable Explainer
# ---------------------------------------------------------------------------

EXPLOIT_TEMPLATES = {
    "XSS": """
**What happened:**
A Cross-Site Scripting (XSS) vulnerability was found in the `{parameter}` parameter at `{url}`.

**Why it matters:**
An attacker can inject malicious JavaScript that executes in victims' browsers. This can lead to:
  • Session hijacking (stealing authentication cookies)
  • Credential harvesting via fake login forms
  • Malware distribution or crypto-mining
  • Full account takeover

**How to reproduce:**
  1. Navigate to: `{url}`
  2. Input the payload `{payload}` into `{parameter}`
  3. Observe that the script executes in the browser

**Risk Level:** {severity} (CVSS {cvss})
""",
    "SQL": """
**What happened:**
SQL Injection was confirmed in the `{parameter}` parameter using {technique}.

**Why it matters:**
An attacker can interact directly with the database, potentially:
  • Extract all data (users, passwords, PII, financial records)
  • Modify or delete database content
  • Bypass authentication entirely
  • In some configurations, execute OS commands

**How to reproduce:**
  1. Send request to: `{url}`
  2. Payload: `{payload}`
  3. Database responded with: `{evidence}`

**Risk Level:** {severity} (CVSS {cvss})
""",
    "LFI": """
**What happened:**
Local File Inclusion via path traversal in `{parameter}` at `{url}`.

**Why it matters:**
  • System files (passwords, config, keys) are readable
  • Log poisoning may enable Remote Code Execution
  • Complete server compromise possible

**Risk Level:** {severity} (CVSS {cvss})
""",
    "PORT": """
**What happened:**
High-risk service `{title}` is internet-exposed.

**Why it matters:**
Exposed services greatly expand the attack surface, enabling:
  • Direct exploitation of known CVEs
  • Brute force of credentials
  • Data exfiltration if service is unauthenticated

**Risk Level:** {severity} (CVSS {cvss})
""",
}


class VulnerabilityExplainer:
    def __init__(self):
        self.classifier = SeverityClassifier()

    def explain(self, finding: Dict) -> Dict:
        """
        Enrich a finding dict with:
          - ai_severity (possibly adjusted)
          - ai_confidence
          - ai_reason
          - human_narrative
          - attack_scenario
        """
        title    = finding.get("title",       "")
        desc     = finding.get("description", "")
        tags     = finding.get("tags",        [])
        evidence = finding.get("evidence",    "")

        ai_sev, ai_conf, ai_reason = self.classifier.predict(title, desc, tags, evidence)

        narrative = self._build_narrative(finding)

        return {
            "ai_severity":    ai_sev,
            "ai_confidence":  round(ai_conf, 3),
            "ai_reason":      ai_reason,
            "human_narrative": narrative,
            "attack_scenario": self._attack_scenario(finding),
        }

    def _build_narrative(self, f: Dict) -> str:
        title = f.get("title", "").upper()
        tmpl  = None
        for key, template in EXPLOIT_TEMPLATES.items():
            if key in title:
                tmpl = template
                break
        if not tmpl:
            return (
                f"**{f.get('title', 'Vulnerability')}** was identified at `{f.get('url', 'N/A')}`.\n\n"
                f"{f.get('description', '')}\n\n"
                f"**Remediation:** {f.get('remediation', 'Follow security best practices.')}"
            )
        return tmpl.format(
            parameter = f.get("parameter", "N/A"),
            url       = f.get("url",       "N/A"),
            payload   = f.get("payload",   "N/A"),
            evidence  = f.get("evidence",  "N/A"),
            severity  = f.get("severity",  "N/A"),
            cvss      = f.get("cvss_score",0.0),
            technique = self._extract_technique(f.get("title", "")),
            title     = f.get("title", ""),
        ).strip()

    @staticmethod
    def _extract_technique(title: str) -> str:
        match = re.search(r"\((.*?)\)", title)
        return match.group(1) if match else "injection"

    @staticmethod
    def _attack_scenario(f: Dict) -> str:
        sev = f.get("severity", "INFO")
        if sev in ("CRITICAL", "HIGH"):
            return (
                "An unauthenticated remote attacker with standard network access could "
                "exploit this vulnerability to compromise sensitive data or gain unauthorized access."
            )
        elif sev == "MEDIUM":
            return (
                "An attacker with some knowledge of the target could exploit this to "
                "gain additional privileges or access restricted resources."
            )
        else:
            return (
                "This issue represents an information leak or minor misconfiguration that "
                "could assist an attacker in planning further attacks."
            )
