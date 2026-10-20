from typing import Any
from urllib.parse import urlsplit

# Shape follows Zscaler ZIA's URL Lookup API (POST /api/v1/urlLookup).
_CLASSIFICATIONS: dict[str, dict[str, list[str]]] = {
    "update-microsoft-cdn.com": {
        "urlClassifications": ["MISCELLANEOUS_OR_UNKNOWN"],
        "urlClassificationsWithSecurityAlert": ["MALWARE_SITE"],
    },
    "login.microsoftonline.com": {
        "urlClassifications": ["WEB_BANNERS", "PROFESSIONAL_SERVICES"],
        "urlClassificationsWithSecurityAlert": [],
    },
}
_UNKNOWN: dict[str, list[str]] = {
    "urlClassifications": ["MISCELLANEOUS_OR_UNKNOWN"],
    "urlClassificationsWithSecurityAlert": [],
}


class MockZscalerNetworkSource:
    """Read-only stand-in for Zscaler ZIA. Swap for an HTTP client with a session cookie."""

    def lookup_url(self, url: str) -> dict[str, Any]:
        host = (urlsplit(url).hostname if "//" in url else url.split("/")[0]) or url
        known = _CLASSIFICATIONS.get(host.lower(), _UNKNOWN)
        return {"url": url, **{key: list(value) for key, value in known.items()}}
