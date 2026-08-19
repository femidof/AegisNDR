from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class Readiness:
    backend: str
    ready: bool
    check: str
    detail: str
    latency_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "ready": self.ready,
            "check": self.check,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
        }


class MetadataStorePort(Protocol):
    """Port for alerts, cases, policy, identity bindings, and audit metadata."""

    backend: str

    def readiness(self) -> Readiness: ...


class EventStorePort(Protocol):
    """Port for high-volume normalized event reads and writes."""

    backend: str

    def readiness(self) -> Readiness: ...


class EvidenceStorePort(Protocol):
    """Port for immutable evidence objects, PCAPs, exports, and support bundles."""

    backend: str

    def readiness(self) -> Readiness: ...


class AdapterCapabilityError(RuntimeError):
    pass


class ReadinessOnlyAdapter:
    """Makes the migration boundary explicit instead of silently persisting to the wrong backend."""

    backend = "unconfigured"
    supports_product_io = False

    def put(self, *_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
        raise AdapterCapabilityError(
            f"{self.backend} product I/O is not implemented; this adapter currently provides configuration and readiness only"
        )

    def get(self, *_args: Any, **_kwargs: Any) -> Mapping[str, Any]:
        raise AdapterCapabilityError(
            f"{self.backend} product I/O is not implemented; this adapter currently provides configuration and readiness only"
        )
