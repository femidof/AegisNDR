from __future__ import annotations

import json
import unittest

import support  # noqa: F401
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from hybrid_ndr_control_api import ControlAPI, ControlStore
from hybrid_ndr_gateway import DeterministicAssessmentProvider, ModelGateway


def make_csr(*, key=None, common_name="hybrid-ndr-client"):
    key = key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(key, hashes.SHA256())
    )
    return key, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


class ControlAPITests(unittest.TestCase):
    def setUp(self):
        self.store = ControlStore(":memory:")
        self.store.create_enrollment_token(
            "tenant-a",
            token="one-time-enrollment-token",
            model_policy={
                "policy_id": "policy-v1",
                "level": "balanced",
                "provider": "demo-zero-retention",
                "model": "evidence-assessor-v1",
                "region": "us",
                "retention_mode": "zero",
                "enabled": True,
            },
        )
        gateway = ModelGateway(
            DeterministicAssessmentProvider(), signing_key=b"control-test-signing-key-0123456789", usage_sink=self.store.save_gateway_usage
        )
        self.api = ControlAPI(self.store, gateway)
        self.private_key, self.csr = make_csr()

    def tearDown(self):
        self.store.close()

    def enroll(self):
        response = self.api.handle(
            "POST", "/v1/enrollment/exchange", headers={"Idempotency-Key": "enroll-attempt-0001"},
            body={"enrollment_token": "one-time-enrollment-token", "csr": self.csr},
        )
        self.assertEqual(response.status, 201, response.body)
        return response.body

    @staticmethod
    def headers(enrollment):
        return {
            "X-Tenant-ID": enrollment["tenant_id"], "X-Deployment-ID": enrollment["deployment_id"],
            "X-Verified-Client-Certificate-Fingerprint": enrollment["certificate_fingerprint"],
        }

    def assert_valid_deployment_certificate(self, enrollment, expected_key):
        certificate = x509.load_pem_x509_certificate(enrollment["deployment_certificate"].encode("ascii"))
        authority = self.store.certificate_authority.certificate
        authority.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            ec.ECDSA(certificate.signature_hash_algorithm),
        )
        self.assertEqual(certificate.issuer, authority.subject)
        self.assertEqual(
            certificate.public_key().public_numbers(),
            expected_key.public_key().public_numbers(),
        )
        self.assertEqual(
            certificate.fingerprint(hashes.SHA256()).hex(),
            enrollment["certificate_fingerprint"],
        )
        self.assertEqual(certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, enrollment["deployment_id"])
        self.assertFalse(certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertEqual(
            certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
        )
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(
            san.get_values_for_type(x509.UniformResourceIdentifier),
            [f"spiffe://hybrid-ndr/tenant/tenant-a/deployment/{enrollment['deployment_id']}"],
        )
        self.assertNotIn("DEMO", enrollment["deployment_certificate"])
        return certificate

    def test_enrollment_is_one_time_and_idempotent(self):
        enrollment = self.enroll()
        replay = self.api.handle(
            "POST", "/v1/enrollment/exchange", headers={"Idempotency-Key": "enroll-attempt-0001"},
            body={"enrollment_token": "one-time-enrollment-token", "csr": self.csr},
        )
        self.assertEqual(replay.status, 200)
        self.assertEqual(replay.body["deployment_id"], enrollment["deployment_id"])
        reused = self.api.handle(
            "POST", "/v1/enrollment/exchange", headers={"Idempotency-Key": "enroll-attempt-0002"},
            body={"enrollment_token": "one-time-enrollment-token", "csr": self.csr},
        )
        self.assertEqual(reused.status, 400)
        self.assertEqual(reused.body["error"]["code"], "enrollment_token_used")
        self.assert_valid_deployment_certificate(enrollment, self.private_key)

    def test_invalid_and_non_p256_csrs_are_rejected_without_consuming_token(self):
        malformed = self.api.handle(
            "POST", "/v1/enrollment/exchange", headers={"Idempotency-Key": "malformed-csr-0001"},
            body={"enrollment_token": "one-time-enrollment-token", "csr": "-----BEGIN CERTIFICATE REQUEST-----\nDEMO-CSR\n-----END CERTIFICATE REQUEST-----"},
        )
        self.assertEqual(malformed.status, 400)
        self.assertEqual(malformed.body["error"]["code"], "invalid_certificate_request")

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _, rsa_csr = make_csr(key=rsa_key)
        wrong_curve = self.api.handle(
            "POST", "/v1/enrollment/exchange", headers={"Idempotency-Key": "rsa-csr-attempt-01"},
            body={"enrollment_token": "one-time-enrollment-token", "csr": rsa_csr},
        )
        self.assertEqual(wrong_curve.status, 400)
        self.assertEqual(wrong_curve.body["error"]["code"], "invalid_certificate_request")

        # Invalid attempts do not burn the one-time token.
        self.assertEqual(self.enroll()["tenant_id"], "tenant-a")

    def test_strict_verified_certificate_auth_and_rotation(self):
        enrollment = self.enroll()
        self.assert_valid_deployment_certificate(enrollment, self.private_key)

        legacy = {
            "X-Tenant-ID": enrollment["tenant_id"],
            "X-Deployment-ID": enrollment["deployment_id"],
            "X-Client-Certificate-Fingerprint": enrollment["certificate_fingerprint"],
        }
        rejected = self.api.handle(
            "GET", f"/v1/deployments/{enrollment['deployment_id']}/entitlements", headers=legacy
        )
        self.assertEqual(rejected.status, 401)

        new_key, new_csr = make_csr(common_name="rotated-client")
        rotated = self.api.handle(
            "POST", "/v1/certificates/rotate",
            headers={**self.headers(enrollment), "Idempotency-Key": "certificate-rotate-0001"},
            body={"csr": new_csr},
        )
        self.assertEqual(rotated.status, 200, rotated.body)
        rotated_enrollment = {**enrollment, **rotated.body}
        self.assert_valid_deployment_certificate(rotated_enrollment, new_key)
        self.assertNotEqual(rotated.body["certificate_fingerprint"], enrollment["certificate_fingerprint"])

        replay_after_lost_response = self.api.handle(
            "POST", "/v1/certificates/rotate",
            headers={**self.headers(enrollment), "Idempotency-Key": "certificate-rotate-0001"},
            body={"csr": new_csr},
        )
        self.assertEqual(replay_after_lost_response.status, 200)
        self.assertEqual(replay_after_lost_response.body, rotated.body)

        old_certificate = self.api.handle(
            "GET", f"/v1/deployments/{enrollment['deployment_id']}/entitlements",
            headers=self.headers(enrollment),
        )
        self.assertEqual(old_certificate.status, 401)
        current_certificate = self.api.handle(
            "GET", f"/v1/deployments/{enrollment['deployment_id']}/entitlements",
            headers=self.headers(rotated_enrollment),
        )
        self.assertEqual(current_certificate.status, 200)

    def test_heartbeat_entitlements_and_model_metadata_only(self):
        enrollment = self.enroll()
        headers = self.headers(enrollment)
        heartbeat = self.api.handle(
            "POST", f"/v1/deployments/{enrollment['deployment_id']}/heartbeat",
            headers={**headers, "Idempotency-Key": "heartbeat-0000001"},
            body={"software_version": "0.1.0", "sensor_health": {"zeek": "online"}, "event_count": 1200, "storage_percent": 21.3},
        )
        self.assertEqual(heartbeat.status, 200, heartbeat.body)
        entitlements = self.api.handle("GET", f"/v1/deployments/{enrollment['deployment_id']}/entitlements", headers=headers)
        self.assertTrue(entitlements.body["local_detection"])
        request = {
            "request_id": "request-001", "tenant_policy_id": "policy-v1", "alert_type": "port-scan-v1",
            "severity": "high", "entity_type": "host",
            "observations": [{"evidence_id": "event-1", "feature": "unique_ports", "observed": 81, "baseline_p99": 10}],
            "allowed_actions": ["inspect_endpoint"],
        }
        model = self.api.handle("POST", "/v1/model/investigate", headers=headers, body=request)
        self.assertEqual(model.status, 200, model.body)
        usage = self.store.connection.execute("SELECT * FROM gateway_usage").fetchone()
        self.assertIsNotNone(usage)
        self.assertNotIn("payload", usage.keys())
        self.assertNotIn("response", usage.keys())

    def test_forbidden_cloud_data_and_invalid_certificate_are_rejected(self):
        enrollment = self.enroll()
        headers = self.headers(enrollment)
        heartbeat = self.api.handle(
            "POST", f"/v1/deployments/{enrollment['deployment_id']}/heartbeat",
            headers={**headers, "Idempotency-Key": "heartbeat-0000002"},
            body={"raw_events": [{"src_ip": "10.0.0.1"}]},
        )
        self.assertEqual(heartbeat.status, 400)
        invalid = self.api.handle(
            "GET", f"/v1/deployments/{enrollment['deployment_id']}/entitlements",
            headers={**headers, "X-Verified-Client-Certificate-Fingerprint": "wrong"},
        )
        self.assertEqual(invalid.status, 401)


if __name__ == "__main__":
    unittest.main()
