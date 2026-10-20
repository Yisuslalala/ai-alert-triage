from ai_alert_triage.domain.alert import Alert
from ai_alert_triage.domain.severity import Severity
from ai_alert_triage.domain.triage import Classification

# Checked from most to least severe; the first match wins.
_RULES: list[tuple[Severity, tuple[str, ...]]] = [
    (Severity.CRITICAL, ("ransomware", "data exfiltration", "domain admin", "mimikatz")),
    (Severity.HIGH, ("malware", "privilege escalation", "lateral movement", "powershell")),
    (Severity.MEDIUM, ("brute force", "failed login", "phishing", "suspicious")),
]


class KeywordClassifier:
    """Placeholder classifier so the API works end to end before the LLM adapter exists."""

    model = "keyword-rules-v1"

    def classify(self, alert: Alert) -> Classification:
        text = f"{alert.title} {alert.description}".lower()
        for severity, keywords in _RULES:
            matched = [keyword for keyword in keywords if keyword in text]
            if matched:
                summary = f"Matched keywords: {', '.join(matched)}."
                return Classification(severity, summary, self.model)
        return Classification(Severity.LOW, "No known threat keywords matched.", self.model)
