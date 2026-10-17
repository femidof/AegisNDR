from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr

import support  # noqa: F401
from hybrid_ndr_auth import HeaderAuthenticator
from hybrid_ndr_local_api import LocalAPI, create_application
from hybrid_ndr_observability.ratelimit import FixedWindowLimiter
from hybrid_ndr_storage import LocalStore


class APIOperationalBoundariesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = LocalStore(":memory:")
        self.store.reset_demo()
        # Explicit demo-only auth for unit tests; production defaults to JWT.
        self.api = create_application(self.store, authenticator=HeaderAuthenticator()).api
        self.headers = support.analyst_headers()

    def tearDown(self) -> None:
        self.store.close()

    def test_rate_limiter_blocks_and_reports_retry_after(self) -> None:
        limiter = FixedWindowLimiter(3, window_seconds=60, now=lambda: 1000.0)
        self.assertTrue(limiter.allow("tenant:actor"))
        self.assertTrue(limiter.allow("tenant:actor"))
        self.assertTrue(limiter.allow("tenant:actor"))
        self.assertFalse(limiter.allow("tenant:actor"))
        self.assertGreaterEqual(limiter.retry_after("tenant:actor"), 1)
        # A fresh key is not blocked.
        self.assertTrue(limiter.allow("tenant:other-actor"))
        # The window resets.
        limiter = FixedWindowLimiter(3, window_seconds=60, now=lambda: 1000.0)
        limiter.allow("tenant:actor")
        limiter.allow("tenant:actor")
        limiter.allow("tenant:actor")
        limiter.allow("tenant:actor")
        advancing = [1000.0, 1000.0, 1000.0, 1000.0, 1061.0, 1061.0, 1061.0, 1061.0]
        limiter = FixedWindowLimiter(3, window_seconds=60, now=lambda: advancing.pop(0))
        limiter.allow("tenant:actor")
        limiter.allow("tenant:actor")
        limiter.allow("tenant:actor")
        self.assertFalse(limiter.allow("tenant:actor"))
        self.assertTrue(limiter.allow("tenant:actor"))

    def test_api_enforces_rate_limit_with_429(self) -> None:
        self.api.rate_limiter = FixedWindowLimiter(2, window_seconds=60)
        for _ in range(2):
            result = self.api.handle("GET", "/api/v1/alerts", headers=self.headers)
            self.assertEqual(result.status, 200)
        limited = self.api.handle("GET", "/api/v1/alerts", headers=self.headers)
        self.assertEqual(limited.status, 429)
        self.assertEqual(limited.body["error"]["code"], "rate_limit_exceeded")
        retry = dict(limited.headers).get("Retry-After")
        self.assertTrue(retry and retry.isdigit())

    def test_oversized_request_body_is_rejected_before_parsing(self) -> None:
        oversized = json.dumps({"query": "x" * 2_000_000}).encode("utf-8")
        result = self.api.handle("POST", "/api/v1/events/search", headers=self.headers, body=oversized)
        self.assertEqual(result.status, 413)
        self.assertEqual(result.body["error"]["code"], "body_too_large")

    def test_wsgi_layer_rejects_oversized_content_length_without_reading(self) -> None:
        from hybrid_ndr_auth import HeaderAuthenticator

        application = create_application(self.store, authenticator=HeaderAuthenticator())
        captured: list = []
        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/api/v1/events/search",
            "CONTENT_LENGTH": str(5_000_000),
            "CONTENT_TYPE": "application/json",
            "wsgi.input": io.BytesIO(b""),
        }

        def start_response(status: str, headers: list) -> None:
            captured.append((status, headers))

        chunks = b"".join(application(environ, start_response))
        self.assertEqual(captured[0][0], "413 Request Entity Too Large")
        self.assertEqual(json.loads(chunks)["error"]["code"], "body_too_large")

    def test_unexpected_errors_are_logged_as_structured_json(self) -> None:
        original = self.api.store.search_events

        def broken(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("simulated failure detail")

        self.api.store.search_events = broken  # type: ignore[attr-defined]
        try:
            with redirect_stderr(io.StringIO()) as captured:
                result = self.api.handle("POST", "/api/v1/events/search", headers=self.headers, body={"query": "x"})
        finally:
            self.api.store.search_events = original  # type: ignore[attr-defined]
        self.assertEqual(result.status, 500)
        records = [json.loads(line) for line in captured.getvalue().strip().splitlines()]
        error_records = [record for record in records if record.get("level") == "error"]
        self.assertTrue(error_records, "expected a structured error log line")
        record = error_records[-1]
        self.assertEqual(record["event"], "api.internal_error")
        self.assertEqual(record["error_type"], "RuntimeError")
        self.assertIn("simulated failure detail", record["error_message"])
        self.assertEqual(record["route"], "/api/v1/events/search")
        # The completed-request record is also structured.
        self.assertTrue(any(record.get("event") == "api.request.completed" for record in records))


if __name__ == "__main__":
    unittest.main()
