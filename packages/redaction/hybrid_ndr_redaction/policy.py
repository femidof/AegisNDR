from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


class RedactionError(ValueError):
    pass


class SensitiveDataError(RedactionError):
    pass


class PolicyLevel(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    INVESTIGATIVE = "investigative"
    DISABLED = "disabled"


@dataclass(frozen=True)
class RedactionReport:
    payload: dict[str, Any]
    fields_included: tuple[str, ...]
    fields_removed: tuple[str, ...]
    fields_tokenized: tuple[str, ...]


# Exact key or a separator-prefixed composite ("user_password",
# "x-api-key"); deliberately NOT a substring search, which over-redacted
# fields like "documentation", "somebody", or "content_type".
_DROP_KEY_PATTERN = re.compile(
    r"(?:^|[-_])(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|set-cookie|payload|packet|document|body|content|credential|private[_-]?key)$",
    re.IGNORECASE,
)
_EMAIL = re.compile(
    r'(?<![A-Za-z0-9])(?:[A-Z0-9._%+-]+|"(?:[^"\\]|\\.)*")@[\w.-]+\.[^\W\d_]{2,}\b',
    re.IGNORECASE,
)
_MAC = re.compile(r"\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b", re.IGNORECASE)
# After Unicode format characters are stripped (see _clean_text), a credential
# can be fused to the scheme with no separator at all; both forms are matched.
_BEARER = re.compile(
    r"\bBearer(?:\s+[A-Za-z0-9._~+/-]+=*|[A-Za-z0-9._~+/-]{8,}=*)",
    re.IGNORECASE,
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PATH = re.compile(r"(?<![A-Za-z0-9])(?:/[A-Za-z0-9._ -]+){2,}|\b[A-Za-z]:\\(?:[^\\\s]+\\)+[^\\\s]*")
_DEFAULT_INTERNAL_TLDS = frozenset({
    # Common split-horizon / private DNS namespaces. Custom TLDs can be added
    # per deployment via the Redactor(internal_tlds=...) parameter.
    "corp", "internal", "local", "lan", "home", "intranet",
    "test", "dev", "staging", "private", "lab", "infra", "svc", "k8s",
    "docker", "mgmt", "cluster", "node", "sandbox", "prod", "office", "vpn", "dc", "cloud",
})
_IP_CANDIDATE = re.compile(r"(?<![A-Fa-f0-9:])(?:\d{1,3}\.){3}\d{1,3}(?![A-Fa-f0-9:])")
_INJECTION = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s*prompt|tool[_ -]?call|function[_ -]?call|<\/?(?:system|assistant|tool)>|```(?:json)?\s*\{\s*\"(?:tool|function))",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _is_drop_key(key: str) -> bool:
    # search (not match): the separator alternative must be found anywhere,
    # e.g. "user_password" matches at the underscore.
    return _DROP_KEY_PATTERN.search(key) is not None


def _strip_format_characters(value: str) -> str:
    """Remove Unicode format characters (zero-width spaces/joiners, bidi
    overrides, word joiners) so token/credential patterns cannot be bypassed
    by inserting invisible characters between their parts."""
    return "".join(character for character in value if unicodedata.category(character) != "Cf")


class Redactor:
    """Apply a tenant policy and stable, tenant-local HMAC tokenization."""

    def __init__(
        self,
        token_key: bytes,
        *,
        maximum_string_length: int = 512,
        internal_tlds: Iterable[str] | None = None,
    ) -> None:
        if not isinstance(token_key, bytes) or len(token_key) < 16:
            raise ValueError("token_key must contain at least 16 bytes")
        self._token_key = token_key
        self._maximum_string_length = maximum_string_length
        tlds = _DEFAULT_INTERNAL_TLDS if internal_tlds is None else frozenset(
            str(item).strip().lower() for item in internal_tlds
        )
        if not tlds or any(not item or not item.isascii() or not item.isalnum() for item in tlds):
            raise ValueError("internal_tlds must contain non-empty ASCII word labels")
        self._hostname = re.compile(
            r"\b(?:[A-Za-z0-9-]+\.)*(?:" + "|".join(sorted(tlds)) + r")\b",
            re.IGNORECASE,
        )

    def redact(self, payload: Mapping[str, Any], level: PolicyLevel | str) -> RedactionReport:
        try:
            policy = PolicyLevel(level)
        except ValueError as exc:
            raise RedactionError(f"unknown redaction policy: {level}") from exc
        if policy is PolicyLevel.DISABLED:
            raise RedactionError("external model calls are disabled by policy")
        included: list[str] = []
        removed: list[str] = []
        tokenized: list[str] = []
        result = self._walk(
            dict(payload),
            path="",
            policy=policy,
            included=included,
            removed=removed,
            tokenized=tokenized,
        )
        if not isinstance(result, dict):
            raise RedactionError("evidence package must be an object")
        self.assert_safe(result)
        return RedactionReport(
            payload=result,
            fields_included=tuple(sorted(set(included))),
            fields_removed=tuple(sorted(set(removed))),
            fields_tokenized=tuple(sorted(set(tokenized))),
        )

    def _walk(
        self,
        value: Any,
        *,
        path: str,
        policy: PolicyLevel,
        included: list[str],
        removed: list[str],
        tokenized: list[str],
    ) -> Any:
        if isinstance(value, Mapping):
            output: dict[str, Any] = {}
            for raw_key, child in value.items():
                key = str(raw_key)
                child_path = f"{path}.{key}" if path else key
                if _is_drop_key(key):
                    removed.append(child_path)
                    continue
                if policy is PolicyLevel.STRICT and key == "context":
                    removed.append(child_path)
                    continue
                output[key] = self._walk(
                    child,
                    path=child_path,
                    policy=policy,
                    included=included,
                    removed=removed,
                    tokenized=tokenized,
                )
            return output
        if isinstance(value, list):
            return [
                self._walk(
                    item,
                    path=f"{path}[{index}]",
                    policy=policy,
                    included=included,
                    removed=removed,
                    tokenized=tokenized,
                )
                for index, item in enumerate(value)
            ]
        if isinstance(value, tuple):
            return self._walk(
                list(value), path=path, policy=policy, included=included, removed=removed, tokenized=tokenized
            )
        if isinstance(value, str):
            cleaned = self._clean_text(value)
            transformed, changed = self._redact_text(cleaned, policy)
            if changed:
                tokenized.append(path)
            included.append(path)
            return transformed
        if value is None or isinstance(value, (bool, int, float)):
            included.append(path)
            return value
        removed.append(path)
        return "[removed]"

    def _clean_text(self, value: str) -> str:
        cleaned = _CONTROL.sub("", _strip_format_characters(value))[: self._maximum_string_length]
        return _INJECTION.sub("[untrusted-log-instruction-removed]", cleaned)

    def _redact_text(self, value: str, policy: PolicyLevel) -> tuple[str, bool]:
        changed = False

        def token_replace(kind: str):
            def replace(match: re.Match[str]) -> str:
                nonlocal changed
                changed = True
                return self._token(kind, match.group(0).lower())

            return replace

        value = _BEARER.sub("[credential-removed]", value)
        value, count = _JWT.subn("[credential-removed]", value)
        changed = changed or count > 0
        value = _EMAIL.sub(token_replace("email"), value)
        value = _MAC.sub(token_replace("mac"), value)
        value = _PATH.sub(token_replace("path"), value)
        value = self._hostname.sub(token_replace("host"), value)

        def redact_ip(match: re.Match[str]) -> str:
            nonlocal changed
            candidate = match.group(0)
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                return candidate
            if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                changed = True
                return self._token("ip", candidate)
            if policy is PolicyLevel.STRICT:
                changed = True
                return self._token("ip", candidate)
            return candidate

        value = _IP_CANDIDATE.sub(redact_ip, value)
        return value, changed

    def _token(self, kind: str, value: str) -> str:
        digest = hmac.new(self._token_key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:12]
        return f"{kind}_{digest}"

    @classmethod
    def assert_safe(cls, payload: Mapping[str, Any]) -> None:
        def walk(value: Any, path: str = "") -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    child_path = f"{path}.{key}" if path else str(key)
                    if _is_drop_key(str(key)):
                        raise SensitiveDataError(f"forbidden field remains after redaction: {child_path}")
                    walk(child, child_path)
            elif isinstance(value, (list, tuple)):
                for index, child in enumerate(value):
                    walk(child, f"{path}[{index}]")
            elif isinstance(value, str):
                plain = _strip_format_characters(value)
                if _EMAIL.search(plain) or _MAC.search(plain) or _BEARER.search(plain) or _JWT.search(plain):
                    raise SensitiveDataError(f"sensitive value remains after redaction: {path}")
                for match in _IP_CANDIDATE.finditer(plain):
                    try:
                        address = ipaddress.ip_address(match.group(0))
                    except ValueError:
                        continue
                    if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved:
                        raise SensitiveDataError(f"internal IP remains after redaction: {path}")

        walk(payload)
