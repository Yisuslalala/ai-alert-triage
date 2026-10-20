from copy import deepcopy
from typing import Any

# Shapes follow SentinelOne's Management API v2.1:
# GET /web/api/v2.1/agents?computerName={hostname} and GET /web/api/v2.1/threats?computerName=...
_AGENTS: dict[str, dict[str, Any]] = {
    "ws-0142": {
        "id": "1834519302719482211",
        "computerName": "WS-0142",
        "osName": "Windows 11 Enterprise",
        "agentVersion": "24.2.3.471",
        "networkStatus": "connected",
        "isActive": True,
        "infected": True,
        "activeThreats": 1,
        "lastLoggedInUserName": "EXAMPLE\\j.doe",
        "lastActiveDate": "2026-10-20T08:01:17.000Z",
        "externalIp": "201.141.22.18",
    },
}

_THREATS: dict[str, list[dict[str, Any]]] = {
    "ws-0142": [
        {
            "id": "1834520011254770921",
            "threatInfo": {
                "threatName": "invoice_0923.ps1",
                "classification": "Malware",
                "confidenceLevel": "malicious",
                "mitigationStatus": "not_mitigated",
                "initiatedBy": "agent_policy",
                "filePath": "\\Device\\HarddiskVolume3\\Users\\j.doe\\Downloads\\invoice_0923.ps1",
                "sha1": "3f786850e387550fdab836ed7e6dc881de23001b",
                "createdAt": "2026-10-20T07:59:30.000Z",
            },
            "agentRealtimeInfo": {"agentComputerName": "WS-0142"},
            "indicators": [
                {"category": "Evasion", "description": "Encoded PowerShell command line"},
                {"category": "Persistence", "description": "Registry Run key created"},
            ],
        },
    ],
}


class MockSentinelOneEndpointSource:
    """Read-only stand-in for SentinelOne. Swap for an HTTP client with an ApiToken."""

    def get_agent(self, hostname: str) -> dict[str, Any] | None:
        agent = _AGENTS.get(hostname.lower())
        return deepcopy(agent) if agent else None

    def get_threats(self, hostname: str) -> list[dict[str, Any]]:
        return deepcopy(_THREATS.get(hostname.lower(), []))
