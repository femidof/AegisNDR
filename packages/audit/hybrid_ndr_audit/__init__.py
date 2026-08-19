"""Append-only, hash-chained product audit records."""

from .log import AuditIntegrityError, AuditLog

__all__ = ["AuditIntegrityError", "AuditLog"]
