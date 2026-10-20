import json
from dataclasses import asdict
from pathlib import Path
from threading import Lock

from ai_alert_triage.ports.llm import LLMAuditEntry


class JsonlAuditLog:
    """Appends one JSON object per LLM call to a file.

    Prompts are logged after redaction, so the file holds no raw secrets.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, entry: LLMAuditEntry) -> None:
        line = json.dumps(asdict(entry), default=str, ensure_ascii=False)
        with self._lock, self._path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")
