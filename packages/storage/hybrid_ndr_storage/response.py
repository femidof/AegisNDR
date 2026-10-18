"""Transactional response state shared by SQLite demo and PostgreSQL production.

The action row is also the durable work queue. Scope locks serialize authorization,
capacity checks and worker claims; no external provider call belongs in this lock.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import contextmanager

from hybrid_ndr_contracts import canonical_json, utc_now
from .local import NotFoundError


class ResponseRepository:
    def __init__(self, store):
        self.store = getattr(store, "metadata", store)
        self.postgres = hasattr(self.store, "_transaction")
        if self.postgres:
            self.store.ensure_detection_schema()

    @contextmanager
    def transaction(self, tenant_id, deployment_id):
        if not tenant_id or not deployment_id:
            raise ValueError("response scope is required")
        if self.postgres:
            with self.store._transaction() as cursor:
                cursor.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                               (canonical_json(["response", tenant_id, deployment_id]),))
                yield ResponseSession(cursor, self.store._table("response_records"), "%s",
                                      tenant_id, deployment_id)
        else:
            with self.store._lock:
                connection = self.store.connection
                connection.execute("BEGIN IMMEDIATE")
                try:
                    yield ResponseSession(connection.cursor(), "response_records", "?",
                                          tenant_id, deployment_id)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise


class ResponseSession:
    def __init__(self, cursor, table, placeholder, tenant, deployment):
        self.cursor, self.table, self.p = cursor, table, placeholder
        self.scope = (tenant, deployment)

    def get(self, kind, record_id, default=None):
        p = self.p
        self.cursor.execute(f"SELECT payload_json FROM {self.table} WHERE tenant_id={p} "
                            f"AND deployment_id={p} AND kind={p} AND record_id={p}",
                            (*self.scope, kind, record_id))
        row = self.cursor.fetchone()
        if row is None:
            if default is not None:
                return default
            raise NotFoundError("response resource not found")
        return json.loads(row[0])

    def list(self, kind, *, states=None, limit=100, offset=0):
        p = self.p
        clause, values = "", (*self.scope, kind)
        if states:
            clause = f" AND state IN ({','.join(p for _ in states)})"
            values += tuple(states)
        self.cursor.execute(f"SELECT payload_json FROM {self.table} WHERE tenant_id={p} "
                            f"AND deployment_id={p} AND kind={p}{clause} "
                            f"ORDER BY updated_at DESC, record_id LIMIT {p} OFFSET {p}",
                            (*values, min(max(int(limit), 1), 1001), max(int(offset), 0)))
        return [json.loads(row[0]) for row in self.cursor.fetchall()]

    def put(self, kind, record_id, payload):
        p = self.p
        self.cursor.execute(
            f"INSERT INTO {self.table} (tenant_id,deployment_id,kind,record_id,state,updated_at,payload_json) "
            f"VALUES ({','.join(p for _ in range(7))}) ON CONFLICT "
            "(tenant_id,deployment_id,kind,record_id) DO UPDATE SET "
            "state=excluded.state,updated_at=excluded.updated_at,payload_json=excluded.payload_json",
            (*self.scope, kind, record_id, payload.get("status", ""), utc_now(), canonical_json(payload)))
        return payload

    def journal(self, actor, event, resource_id, metadata):
        head = self.get("journal_head", "head", {"hash": "0" * 64, "sequence": 0})
        record = {
            "event_id": str(uuid.uuid4()), "tenant_id": self.scope[0],
            "deployment_id": self.scope[1], "actor_id": actor, "event": event,
            "resource_id": resource_id, "created_at": utc_now(), "metadata": metadata,
            "sequence": head["sequence"] + 1, "previous_hash": head["hash"],
        }
        record["hash"] = hashlib.sha256(canonical_json(record).encode()).hexdigest()
        self.put("journal", record["event_id"], record)
        self.put("journal_head", "head", {"hash": record["hash"], "sequence": record["sequence"]})
        return record
