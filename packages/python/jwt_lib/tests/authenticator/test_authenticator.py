from typing import Iterable

import pytest

from jwt_lib.src.authenticator import (
    Auth0Authenticator,
    Authenticator,
    UserAuthenticator,
)
from jwt_lib.src.claims import TrustedClaims
from jwt_lib.src.config.config import (
    DEFAULT_USER_AUDIENCE,
    DEFAULT_USER_ISSUER,
)
from jwt_lib.src.profiles import TokenProfile, UserTokenProfile
from jwt_lib.src.validation import ClaimRule, ClaimValidator, RequireClaim
from jwt_lib.src.exceptions import InvalidClaimError


class _StubVerifier:
    def __init__(self, claims: TrustedClaims) -> None:
        self.claims = claims
        self.tokens: list[str] = []

    async def validate(self, token: str) -> TrustedClaims:
        self.tokens.append(token)
        return self.claims


class _StubProfile(TokenProfile):
    def __init__(self) -> None:
        self.validated_with: TrustedClaims | None = None
        super().__init__()

    def _build_rules(self) -> list[ClaimRule]:
        return []

    def validate(
        self,
        claims: TrustedClaims,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> None:
        self._validator.validate(claims)

        if extra_rules:
            ClaimValidator(list(extra_rules)).validate(claims)

        self._custom_validations(claims)

    def _custom_validations(self, claims: TrustedClaims) -> None:
        self.validated_with = claims


class _ConcreteAuthenticator(Authenticator):
    def __init__(self, verifier: _StubVerifier, profile: _StubProfile) -> None:
        super().__init__()
        self._verifier = verifier
        self._profile = profile

    def _create_verifier(self) -> _StubVerifier:  # pragma: no cover - unused
        return self._verifier

    def _create_profile(self) -> _StubProfile:  # pragma: no cover - unused
        return self._profile

    async def validate(
        self,
        token: str,
        extra_rules: Iterable[ClaimRule] | None = None,
    ) -> TrustedClaims:
        claims = await self._verifier.validate(token)
        self._profile.validate(claims, extra_rules=extra_rules)
        return claims


@pytest.mark.asyncio
async def test_authenticator_delegates_to_verifier_and_profile():
    claims = TrustedClaims({"sub": "123"})
    verifier = _StubVerifier(claims)
    profile = _StubProfile()
    authenticator = _ConcreteAuthenticator(verifier, profile)

    result = await authenticator.validate("token-123")

    assert result is claims
    assert verifier.tokens == ["token-123"]
    assert profile.validated_with is claims


@pytest.mark.asyncio
async def test_authenticator_applies_extra_rules():
    claims = TrustedClaims({"foo": "bar"})
    verifier = _StubVerifier(claims)
    profile = _StubProfile()
    authenticator = _ConcreteAuthenticator(verifier, profile)

    await authenticator.validate(
        "token",
        extra_rules=[RequireClaim("foo", "bar")],
    )

    with pytest.raises(InvalidClaimError):
        await authenticator.validate(
            "token",
            extra_rules=[RequireClaim("foo", "baz")],
        )


def test_user_authenticator_uses_defaults():
    authenticator = UserAuthenticator()

    expected_issuer = DEFAULT_USER_ISSUER.rstrip("/") + "/"
    assert authenticator.verifier.issuer == expected_issuer
    assert authenticator.verifier.audience == DEFAULT_USER_AUDIENCE

    profile = authenticator.profile
    assert isinstance(profile, UserTokenProfile)
    assert profile.allowed_connection_methods == ["UIDPWD"]


def test_auth0_authenticator_uses_defaults():
    authenticator = Auth0Authenticator(
        issuer="https://auth.example.com/",
        audience="https://api.example.com",
        profile_kwargs={"app_name": "svc-app"},
    )

    verifier = authenticator.verifier
    assert verifier.issuer == "https://auth.example.com/"
    assert verifier.audience == "https://api.example.com"
    assert verifier.allowed_algorithms == {"RS256"}
    assert verifier.jwks_uri == "https://auth.example.com/.well-known/jwks.json"

    profile = authenticator.profile
    assert profile.expected_app_name == "svc-app"


def test_auth0_authenticator_handles_issuer_without_slash():
    authenticator = Auth0Authenticator(
        issuer="https://auth.example.com",
    )

    verifier = authenticator.verifier
    assert verifier.issuer == "https://auth.example.com/"
    assert verifier.jwks_uri == "https://auth.example.com/.well-known/jwks.json"
