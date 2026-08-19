from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from typing import Any, Iterable, Mapping

from hybrid_ndr_contracts import DetectionResult, NormalizedEvent, canonical_json, utc_now

from .administration import (
    default_detection_rules,
    normalize_detection_rule,
    normalize_integration,
    normalize_suppression,
    normalize_system_settings,
    public_integration,
    suppression_matches,
)
from .local import NotFoundError, validate_export_document


def _json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    return json.loads(value) if isinstance(value, str) else value


def _iso(value: Any) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(value)


class PostgresAdministrationMixin:
    """Durable analyst/admin workflows mixed into the local PostgreSQL metadata adapter."""

    def list_detection_rules(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        defaults = {item["rule_id"]: item for item in default_detection_rules(tenant_id, deployment_id)}
        rows = self._all(
            f"SELECT payload_json FROM {self._table('detection_rules')} WHERE tenant_id = %s AND deployment_id = %s",
            (tenant_id, deployment_id),
        )
        for row in rows:
            item = dict(_json(row["payload_json"], {}))
            defaults[item["rule_id"]] = item
        return sorted(defaults.values(), key=lambda item: (item["name"].lower(), item["rule_id"]))

    def get_detection_rule(self, tenant_id: str, deployment_id: str, rule_id: str) -> dict[str, Any]:
        for item in self.list_detection_rules(tenant_id, deployment_id):
            if item["rule_id"] == rule_id:
                return item
        raise NotFoundError("detection rule not found")

    def create_detection_rule(
        self, tenant_id: str, deployment_id: str, value: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        proposed_id = str(value.get("rule_id", ""))
        item = normalize_detection_rule(tenant_id, deployment_id, value, actor_id=actor_id)
        # Atomic duplicate guard: a check outside the insert has a TOCTOU race
        # with a concurrent create; the unique index plus DO NOTHING closes it.
        affected = self._execute(
            f"""INSERT INTO {self._table('detection_rules')}
                (tenant_id, deployment_id, rule_id, payload_json, updated_at) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, deployment_id, rule_id) DO NOTHING""",
            (tenant_id, deployment_id, item["rule_id"], canonical_json(item), item["updated_at"]),
        )
        if affected != 1:
            raise ValueError("detection rule identifier already exists")
        return item

    def update_detection_rule(
        self, tenant_id: str, deployment_id: str, rule_id: str, changes: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        if "rule_id" in changes and changes["rule_id"] != rule_id:
            raise ValueError("rule_id cannot be changed")
        existing = self.get_detection_rule(tenant_id, deployment_id, rule_id)
        item = normalize_detection_rule(
            tenant_id, deployment_id, {**changes, "rule_id": rule_id}, existing=existing, actor_id=actor_id
        )
        self._execute(
            f"""INSERT INTO {self._table('detection_rules')}
                (tenant_id, deployment_id, rule_id, payload_json, updated_at) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, deployment_id, rule_id) DO UPDATE SET
                  payload_json = EXCLUDED.payload_json, updated_at = EXCLUDED.updated_at""",
            (tenant_id, deployment_id, rule_id, canonical_json(item), item["updated_at"]),
        )
        return item

    def delete_detection_rule(self, tenant_id: str, deployment_id: str, rule_id: str) -> dict[str, Any]:
        item = self.get_detection_rule(tenant_id, deployment_id, rule_id)
        if item.get("builtin"):
            raise ValueError("built-in detection rules cannot be deleted; disable them instead")
        affected = self._execute(
            f"DELETE FROM {self._table('detection_rules')} WHERE tenant_id = %s AND deployment_id = %s AND rule_id = %s",
            (tenant_id, deployment_id, rule_id),
        )
        if affected != 1:
            raise NotFoundError("detection rule not found")
        return item

    def list_suppressions(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT payload_json FROM {self._table('detection_suppressions')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY updated_at DESC",
            (tenant_id, deployment_id),
        )
        return [dict(_json(row["payload_json"], {})) for row in rows]

    def get_suppression(self, tenant_id: str, deployment_id: str, suppression_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT payload_json FROM {self._table('detection_suppressions')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND suppression_id = %s",
            (tenant_id, deployment_id, suppression_id),
        )
        if not row:
            raise NotFoundError("suppression not found")
        return dict(_json(row["payload_json"], {}))

    def create_suppression(
        self, tenant_id: str, deployment_id: str, value: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        item = normalize_suppression(tenant_id, deployment_id, value, actor_id=actor_id)
        self._execute(
            f"""INSERT INTO {self._table('detection_suppressions')}
                (tenant_id, deployment_id, suppression_id, payload_json, updated_at) VALUES (%s, %s, %s, %s, %s)""",
            (tenant_id, deployment_id, item["suppression_id"], canonical_json(item), item["updated_at"]),
        )
        return item

    def update_suppression(
        self, tenant_id: str, deployment_id: str, suppression_id: str, changes: Mapping[str, Any], *, actor_id: str
    ) -> dict[str, Any]:
        if "suppression_id" in changes and changes["suppression_id"] != suppression_id:
            raise ValueError("suppression_id cannot be changed")
        existing = self.get_suppression(tenant_id, deployment_id, suppression_id)
        item = normalize_suppression(
            tenant_id, deployment_id, {**changes, "suppression_id": suppression_id},
            existing=existing, actor_id=actor_id,
        )
        affected = self._execute(
            f"""UPDATE {self._table('detection_suppressions')} SET payload_json = %s, updated_at = %s
                WHERE tenant_id = %s AND deployment_id = %s AND suppression_id = %s""",
            (canonical_json(item), item["updated_at"], tenant_id, deployment_id, suppression_id),
        )
        if affected != 1:
            raise NotFoundError("suppression not found")
        return item

    def delete_suppression(self, tenant_id: str, deployment_id: str, suppression_id: str) -> dict[str, Any]:
        item = self.get_suppression(tenant_id, deployment_id, suppression_id)
        self._execute(
            f"DELETE FROM {self._table('detection_suppressions')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND suppression_id = %s",
            (tenant_id, deployment_id, suppression_id),
        )
        return item

    def is_detection_suppressed(
        self,
        tenant_id: str,
        deployment_id: str,
        detection: DetectionResult,
        evidence: Iterable[NormalizedEvent | Mapping[str, Any]],
        *,
        at: dt.datetime | None = None,
    ) -> bool:
        checked_at = at or dt.datetime.now(dt.timezone.utc)
        rows = [item.to_dict() if isinstance(item, NormalizedEvent) else dict(item) for item in evidence]
        return any(
            suppression_matches(item, detection.detector_id, detection.entity_id, rows, at=checked_at)
            for item in self.list_suppressions(tenant_id, deployment_id)
        )

    def _integration_record(
        self, tenant_id: str, deployment_id: str, integration_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT payload_json, secret_json FROM {self._table('integrations')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND integration_id = %s",
            (tenant_id, deployment_id, integration_id),
        )
        if not row:
            raise NotFoundError("integration not found")
        return dict(_json(row["payload_json"], {})), dict(_json(row["secret_json"], {}))

    def list_integrations(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT payload_json, secret_json FROM {self._table('integrations')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY updated_at DESC",
            (tenant_id, deployment_id),
        )
        return [public_integration(dict(_json(row["payload_json"], {})), dict(_json(row["secret_json"], {}))) for row in rows]

    def get_integration(self, tenant_id: str, deployment_id: str, integration_id: str) -> dict[str, Any]:
        item, secret = self._integration_record(tenant_id, deployment_id, integration_id)
        return public_integration(item, secret)

    def create_integration(self, tenant_id: str, deployment_id: str, value: Mapping[str, Any]) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        item, secret = normalize_integration(tenant_id, deployment_id, value)
        self._execute(
            f"""INSERT INTO {self._table('integrations')}
                (tenant_id, deployment_id, integration_id, payload_json, secret_json, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s)""",
            (tenant_id, deployment_id, item["integration_id"], canonical_json(item), canonical_json(secret), item["updated_at"]),
        )
        return public_integration(item, secret)

    def update_integration(
        self, tenant_id: str, deployment_id: str, integration_id: str, changes: Mapping[str, Any]
    ) -> dict[str, Any]:
        if "integration_id" in changes and changes["integration_id"] != integration_id:
            raise ValueError("integration_id cannot be changed")
        existing, existing_secret = self._integration_record(tenant_id, deployment_id, integration_id)
        item, secret = normalize_integration(
            tenant_id, deployment_id, {**changes, "integration_id": integration_id},
            existing=existing, existing_secret=existing_secret,
        )
        affected = self._execute(
            f"""UPDATE {self._table('integrations')} SET payload_json = %s, secret_json = %s, updated_at = %s
                WHERE tenant_id = %s AND deployment_id = %s AND integration_id = %s""",
            (canonical_json(item), canonical_json(secret), item["updated_at"], tenant_id, deployment_id, integration_id),
        )
        if affected != 1:
            raise NotFoundError("integration not found")
        return public_integration(item, secret)

    def delete_integration(self, tenant_id: str, deployment_id: str, integration_id: str) -> dict[str, Any]:
        item = self.get_integration(tenant_id, deployment_id, integration_id)
        self._execute(
            f"DELETE FROM {self._table('integrations')} WHERE tenant_id = %s AND deployment_id = %s AND integration_id = %s",
            (tenant_id, deployment_id, integration_id),
        )
        return item

    def get_system_settings(self, tenant_id: str, deployment_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT settings_json FROM {self._table('system_settings')} WHERE tenant_id = %s AND deployment_id = %s",
            (tenant_id, deployment_id),
        )
        return normalize_system_settings(
            tenant_id, deployment_id, {}, current=dict(_json(row["settings_json"], {})) if row else None
        )

    def update_system_settings(
        self, tenant_id: str, deployment_id: str, changes: Mapping[str, Any]
    ) -> dict[str, Any]:
        current = self.get_system_settings(tenant_id, deployment_id)
        item = normalize_system_settings(tenant_id, deployment_id, changes, current=current)
        self._execute(
            f"""INSERT INTO {self._table('system_settings')}
                (tenant_id, deployment_id, settings_json, updated_at) VALUES (%s, %s, %s, %s)
                ON CONFLICT (tenant_id, deployment_id) DO UPDATE SET
                  settings_json = EXCLUDED.settings_json, updated_at = EXCLUDED.updated_at""",
            (tenant_id, deployment_id, canonical_json(item), item["updated_at"]),
        )
        return item

    def create_evidence_export(
        self, tenant_id: str, deployment_id: str, value: Mapping[str, Any], *, requested_by: str
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        allowed = {"alert_id", "investigation_id", "evidence_ids", "reason", "format"}
        if set(value) - allowed:
            raise ValueError("unsupported evidence export fields")
        evidence_ids = value.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids or len(evidence_ids) > 100:
            raise ValueError("evidence_ids must contain 1-100 event identifiers")
        if not all(isinstance(item, str) and item.strip() for item in evidence_ids):
            raise ValueError("evidence_ids contains an invalid identifier")
        reason = str(value.get("reason", "")).strip()
        if not 10 <= len(reason) <= 500:
            raise ValueError("reason must contain 10-500 characters")
        if value.get("format", "json") != "json":
            raise ValueError("the MVP evidence export format is json")
        now = utc_now()
        item = {
            "export_id": str(uuid.uuid4()), "tenant_id": tenant_id, "deployment_id": deployment_id,
            "alert_id": str(value.get("alert_id", "")), "investigation_id": str(value.get("investigation_id", "")),
            "evidence_ids": list(dict.fromkeys(evidence_ids)), "reason": reason, "format": "json",
            "status": "pending_approval", "requested_by": requested_by, "approved_by": None,
            "approval_justification": None, "sha256": None, "size_bytes": None,
            "download_count": 0, "last_downloaded_at": None, "created_at": now, "updated_at": now,
        }
        self._execute(
            f"""INSERT INTO {self._table('evidence_exports')}
                (tenant_id, deployment_id, export_id, status, payload_json, export_json, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NULL, %s, %s)""",
            (tenant_id, deployment_id, item["export_id"], item["status"], canonical_json(item), now, now),
        )
        return item

    def list_evidence_exports(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT payload_json FROM {self._table('evidence_exports')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY created_at DESC",
            (tenant_id, deployment_id),
        )
        return [dict(_json(row["payload_json"], {})) for row in rows]

    def get_evidence_export(self, tenant_id: str, deployment_id: str, export_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT payload_json FROM {self._table('evidence_exports')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND export_id = %s",
            (tenant_id, deployment_id, export_id),
        )
        if not row:
            raise NotFoundError("evidence export not found")
        return dict(_json(row["payload_json"], {}))

    def approve_evidence_export(
        self,
        tenant_id: str,
        deployment_id: str,
        export_id: str,
        *,
        approved_by: str,
        justification: str,
        document: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        justification = justification.strip()
        if not 10 <= len(justification) <= 500:
            raise ValueError("approval justification must contain 10-500 characters")
        # Read, document validation, and the conditional transition share one
        # transaction: a concurrent approval cannot both pass the status check
        # and write, and the document cannot drift from the export request.
        with self._transaction() as cursor:
            cursor.execute(
                f"SELECT payload_json FROM {self._table('evidence_exports')} "
                "WHERE tenant_id = %s AND deployment_id = %s AND export_id = %s",
                (tenant_id, deployment_id, export_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise NotFoundError("evidence export not found")
            item = dict(_json(self._mapping(cursor, row)["payload_json"], {}))
            if item["status"] != "pending_approval":
                raise ValueError("only pending evidence exports can be approved")
            validate_export_document(document, export_id, item["evidence_ids"])
            encoded = canonical_json(dict(document)).encode("utf-8")
            now = utc_now()
            item.update({
                "status": "approved", "approved_by": approved_by, "approval_justification": justification,
                "sha256": hashlib.sha256(encoded).hexdigest(), "size_bytes": len(encoded), "updated_at": now,
            })
            cursor.execute(
                f"""UPDATE {self._table('evidence_exports')}
                    SET status = %s, payload_json = %s, export_json = %s, updated_at = %s
                    WHERE tenant_id = %s AND deployment_id = %s AND export_id = %s
                      AND status = 'pending_approval'""",
                (item["status"], canonical_json(item), canonical_json(document), item["updated_at"],
                 tenant_id, deployment_id, export_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("only pending evidence exports can be approved")
        return item

    def get_evidence_export_document(self, tenant_id: str, deployment_id: str, export_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT status, export_json FROM {self._table('evidence_exports')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND export_id = %s",
            (tenant_id, deployment_id, export_id),
        )
        if not row:
            raise NotFoundError("evidence export not found")
        if row["status"] != "approved" or row["export_json"] is None:
            raise ValueError("evidence export is not approved")
        return dict(_json(row["export_json"], {}))

    def mark_evidence_export_downloaded(self, tenant_id: str, deployment_id: str, export_id: str) -> dict[str, Any]:
        item = self.get_evidence_export(tenant_id, deployment_id, export_id)
        if item["status"] != "approved":
            raise ValueError("evidence export is not approved")
        item["download_count"] = int(item.get("download_count", 0)) + 1
        item["last_downloaded_at"] = utc_now()
        item["updated_at"] = item["last_downloaded_at"]
        self._execute(
            f"UPDATE {self._table('evidence_exports')} SET payload_json = %s, updated_at = %s "
            "WHERE tenant_id = %s AND deployment_id = %s AND export_id = %s",
            (canonical_json(item), item["updated_at"], tenant_id, deployment_id, export_id),
        )
        return item

    def create_support_bundle(
        self,
        tenant_id: str,
        deployment_id: str,
        document: Mapping[str, Any],
        *,
        requested_by: str,
        expires_at: str,
        options: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        encoded = canonical_json(dict(document)).encode("utf-8")
        now = utc_now()
        item = {
            "bundle_id": str(uuid.uuid4()), "tenant_id": tenant_id, "deployment_id": deployment_id,
            "status": "ready", "requested_by": requested_by, "options": dict(options),
            "contains_secrets": False, "contains_event_content": False, "sha256": hashlib.sha256(encoded).hexdigest(),
            "size_bytes": len(encoded), "expires_at": expires_at, "download_count": 0,
            "last_downloaded_at": None, "created_at": now,
        }
        self._execute(
            f"""INSERT INTO {self._table('support_bundles')}
                (tenant_id, deployment_id, bundle_id, payload_json, bundle_json, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)""",
            (tenant_id, deployment_id, item["bundle_id"], canonical_json(item), canonical_json(document), now),
        )
        return item

    def list_support_bundles(self, tenant_id: str, deployment_id: str) -> list[dict[str, Any]]:
        self._scope(tenant_id, deployment_id)
        rows = self._all(
            f"SELECT payload_json FROM {self._table('support_bundles')} "
            "WHERE tenant_id = %s AND deployment_id = %s ORDER BY created_at DESC",
            (tenant_id, deployment_id),
        )
        return [dict(_json(row["payload_json"], {})) for row in rows]

    def get_support_bundle(self, tenant_id: str, deployment_id: str, bundle_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT payload_json FROM {self._table('support_bundles')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND bundle_id = %s",
            (tenant_id, deployment_id, bundle_id),
        )
        if not row:
            raise NotFoundError("support bundle not found")
        return dict(_json(row["payload_json"], {}))

    def get_support_bundle_document(self, tenant_id: str, deployment_id: str, bundle_id: str) -> dict[str, Any]:
        self._scope(tenant_id, deployment_id)
        row = self._one(
            f"SELECT bundle_json FROM {self._table('support_bundles')} "
            "WHERE tenant_id = %s AND deployment_id = %s AND bundle_id = %s",
            (tenant_id, deployment_id, bundle_id),
        )
        if not row:
            raise NotFoundError("support bundle not found")
        return dict(_json(row["bundle_json"], {}))

    def mark_support_bundle_downloaded(self, tenant_id: str, deployment_id: str, bundle_id: str) -> dict[str, Any]:
        item = self.get_support_bundle(tenant_id, deployment_id, bundle_id)
        item["download_count"] = int(item.get("download_count", 0)) + 1
        item["last_downloaded_at"] = utc_now()
        self._execute(
            f"UPDATE {self._table('support_bundles')} SET payload_json = %s "
            "WHERE tenant_id = %s AND deployment_id = %s AND bundle_id = %s",
            (canonical_json(item), tenant_id, deployment_id, bundle_id),
        )
        return item
