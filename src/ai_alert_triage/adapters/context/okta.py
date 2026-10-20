from copy import deepcopy
from typing import Any

# Shapes follow Okta's Users API (GET /api/v1/users/{login}) and
# System Log API (GET /api/v1/logs?filter=actor.alternateId eq "{login}").
_USERS: dict[str, dict[str, Any]] = {
    "j.doe@example.com": {
        "id": "00u1a2b3c4d5e6f7g8h9",
        "status": "ACTIVE",
        "created": "2024-03-11T15:02:10.000Z",
        "lastLogin": "2026-10-20T07:58:41.000Z",
        "passwordChanged": "2026-10-20T07:41:03.000Z",
        "profile": {
            "login": "j.doe@example.com",
            "email": "j.doe@example.com",
            "firstName": "Jordan",
            "lastName": "Doe",
            "department": "Finance",
            "title": "Accounts Payable Analyst",
        },
    },
}

_EVENTS: dict[str, list[dict[str, Any]]] = {
    "j.doe@example.com": [
        {
            "uuid": "a1f3e9c2-0b7d-11f1-9a51-1b2c3d4e5f60",
            "published": "2026-10-20T07:38:12.000Z",
            "eventType": "system.push.send_factor_verify_push",
            "outcome": {"result": "FAILURE", "reason": "USER_REJECTED"},
            "client": {
                "ipAddress": "185.220.101.47",
                "geographicalContext": {"country": "Netherlands", "city": "Amsterdam"},
            },
            "actor": {"alternateId": "j.doe@example.com"},
        },
        {
            "uuid": "a1f3e9c3-0b7d-11f1-9a51-1b2c3d4e5f60",
            "published": "2026-10-20T07:40:55.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "outcome": {"result": "SUCCESS"},
            "client": {
                "ipAddress": "185.220.101.47",
                "geographicalContext": {"country": "Netherlands", "city": "Amsterdam"},
            },
            "actor": {"alternateId": "j.doe@example.com"},
        },
        {
            "uuid": "a1f3e9c4-0b7d-11f1-9a51-1b2c3d4e5f60",
            "published": "2026-10-20T07:41:03.000Z",
            "eventType": "user.account.update_password",
            "outcome": {"result": "SUCCESS"},
            "client": {
                "ipAddress": "185.220.101.47",
                "geographicalContext": {"country": "Netherlands", "city": "Amsterdam"},
            },
            "actor": {"alternateId": "j.doe@example.com"},
        },
    ],
}


class MockOktaIdentitySource:
    """Read-only stand-in for Okta. Swap for an HTTP client with an SSWS/OAuth token."""

    def get_user(self, login: str) -> dict[str, Any] | None:
        user = _USERS.get(login.lower())
        return deepcopy(user) if user else None

    def get_recent_events(self, login: str) -> list[dict[str, Any]]:
        return deepcopy(_EVENTS.get(login.lower(), []))
