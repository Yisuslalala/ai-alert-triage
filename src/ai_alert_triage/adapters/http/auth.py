from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt

# Asymmetric only: accepting HS256 would let anyone holding the public key forge tokens.
ALLOWED_ALGORITHMS = ["RS256", "ES256"]


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    scopes: frozenset[str]


class AuthError(Exception):
    """The token is missing, malformed, expired, or not meant for this API."""


class JwtVerifier:
    """Validates OAuth2 access tokens issued by an OIDC provider (Okta, Entra ID).

    Checks signature, issuer, audience and expiry. The signing key comes from
    ``key_resolver``; in production that is the provider's JWKS endpoint.
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        key_resolver: Callable[[str], Any],
        leeway_seconds: int = 30,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._key_resolver = key_resolver
        self._leeway = leeway_seconds

    @classmethod
    def from_jwks(cls, issuer: str, audience: str, jwks_url: str) -> JwtVerifier:
        # PyJWKClient caches keys and refetches when it sees an unknown `kid`,
        # so key rotation at the provider needs no restart.
        jwks = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=3600, timeout=5)
        return cls(issuer, audience, lambda token: jwks.get_signing_key_from_jwt(token).key)

    def verify(self, token: str) -> Principal:
        try:
            key = self._key_resolver(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=ALLOWED_ALGORITHMS,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(str(exc)) from exc
        return Principal(subject=claims["sub"], scopes=_scopes(claims))


def _scopes(claims: dict[str, Any]) -> frozenset[str]:
    # Okta sends `scp` as a list; Entra ID and RFC 8693 use a space-separated string.
    raw = claims.get("scp", claims.get("scope", []))
    if isinstance(raw, str):
        raw = raw.split()
    return frozenset(scope for scope in raw if isinstance(scope, str))
