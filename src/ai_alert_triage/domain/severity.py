from enum import StrEnum


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    @property
    def requires_investigation(self) -> bool:
        return self in (Severity.HIGH, Severity.CRITICAL)
