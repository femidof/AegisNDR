"""Authentication and authorization primitives for the customer-resident API."""

from .tokens import (
    DEFAULT_ROLE_PERMISSIONS,
    AuthConfig,
    AuthenticationError,
    HeaderAuthenticator,
    JWKSClient,
    JWTAuthenticator,
    Principal,
    StaticJWKSource,
    build_authenticator,
)

__all__ = [
    "DEFAULT_ROLE_PERMISSIONS",
    "AuthConfig",
    "AuthenticationError",
    "HeaderAuthenticator",
    "JWKSClient",
    "JWTAuthenticator",
    "Principal",
    "StaticJWKSource",
    "build_authenticator",
]
