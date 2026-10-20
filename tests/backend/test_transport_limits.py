"""Exercise connection limits and TLS availability using real local sockets."""
from __future__ import annotations

import socket
import ssl
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from pathlib import Path
from urllib.request import build_opener, HTTPSHandler

import support
from hybrid_ndr_transport import JSONHTTPClient, make_server
from hybrid_ndr_transport.http import _ProductionWSGIServer


def issue_client(authority, directory, stem):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, stem)])).sign(key, hashes.SHA256())
    certificate = authority.issue_deployment_certificate(csr.public_bytes(serialization.Encoding.PEM).decode(),
        tenant_id="lab", deployment_id=stem)
    cert_path, key_path = Path(directory) / (stem + "-cert.pem"), Path(directory) / (stem + "-key.pem")
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return str(cert_path), str(key_path), certificate.fingerprint(hashes.SHA256()).hex()


def make_pki(directory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from hybrid_ndr_control_api.pki import CertificateAuthority

    authority = CertificateAuthority.create("Disposable response test CA")
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = authority.issue_server_certificate(key, ["127.0.0.1"])
    paths = {name: str(Path(directory) / (name + ".pem")) for name in ("ca", "server_certificate", "server_key")}
    Path(paths["ca"]).write_bytes(authority.certificate_pem())
    Path(paths["server_certificate"]).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    Path(paths["server_key"]).write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    paths["client_certificate"], paths["client_key"], paths["client_pin"] = issue_client(authority, directory, "controller")
    return authority, paths


class TransportLimitTests(unittest.TestCase):
    def test_connection_limit_is_held_until_worker_finishes(self):
        release, saturated = threading.Event(), threading.Event()
        count, lock = 0, threading.Lock()

        def application(environ, start_response):
            nonlocal count
            with lock:
                count += 1
                if count == 4:
                    saturated.set()
            release.wait(10)
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b"{}"]

        server = _ProductionWSGIServer(("127.0.0.1", 0), application, maximum_concurrent_requests=4)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        def get():
            connection = HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
            try:
                connection.request("GET", "/", headers={"Connection": "close"})
                response = connection.getresponse()
                response.read()
                return response.status
            finally:
                connection.close()

        try:
            with ThreadPoolExecutor(max_workers=4) as pool:
                pending = [pool.submit(get) for _ in range(4)]
                try:
                    self.assertTrue(saturated.wait(3))
                    with self.assertRaises((OSError, ConnectionError)):
                        get()
                    self.assertEqual(count, 4)
                finally:
                    release.set()
                self.assertEqual([future.result() for future in pending], [200] * 4)
            self.assertEqual(get(), 200, "capacity must recover after requests finish")
        finally:
            release.set()
            server.shutdown()
            server.server_close()

    def test_stalled_tls_handshake_does_not_block_verified_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            authority, paths = make_pki(directory)

            def application(environ, start_response):
                start_response("200 OK", [("Content-Type", "application/json")])
                return [b"{}"]

            with make_server("127.0.0.1", 0, application, certificate_file=paths["server_certificate"],
                             private_key_file=paths["server_key"], client_ca_file=paths["ca"]) as server:
                threading.Thread(target=server.serve_forever, daemon=True).start()
                stalled = socket.create_connection(server.server_address, timeout=2)
                try:
                    context = ssl.create_default_context(cafile=paths["ca"])
                    context.verify_flags |= ssl.VERIFY_X509_STRICT
                    context.load_cert_chain(paths["client_certificate"], paths["client_key"])
                    client = JSONHTTPClient("https://127.0.0.1:" + str(server.server_address[1]),
                        opener=build_opener(HTTPSHandler(context=context)), timeout_seconds=2)
                    self.assertEqual(client.request("GET", "/"), {})
                finally:
                    stalled.close()
                    server.shutdown()


if __name__ == "__main__":
    unittest.main()
