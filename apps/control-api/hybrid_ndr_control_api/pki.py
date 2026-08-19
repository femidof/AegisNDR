from __future__ import annotations

import base64
import ipaddress
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CertificateError(ValueError):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _write_private(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _write_public(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o644)
    finally:
        temporary.unlink(missing_ok=True)


class CertificateAuthority:
    """Small P-256 deployment CA used for enrollment and certificate rotation."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, certificate: x509.Certificate) -> None:
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise CertificateError("certificate authority key must use P-256")
        if certificate.public_key().public_numbers() != private_key.public_key().public_numbers():
            raise CertificateError("certificate authority key does not match its certificate")
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        if not constraints.ca:
            raise CertificateError("certificate authority certificate is not a CA")
        self.private_key = private_key
        self.certificate = certificate

    @classmethod
    def create(cls, common_name: str = "Hybrid NDR Deployment CA") -> "CertificateAuthority":
        key = ec.generate_private_key(ec.SECP256R1())
        now = _utc_now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return cls(key, certificate)

    @classmethod
    def load_or_create(cls, private_key_path: str | Path, certificate_path: str | Path) -> "CertificateAuthority":
        key_path, cert_path = Path(private_key_path), Path(certificate_path)
        if key_path.exists() != cert_path.exists():
            raise CertificateError("deployment CA key and certificate must either both exist or both be absent")
        if not key_path.exists():
            authority = cls.create()
            _write_private(key_path, authority.private_key_pem())
            _write_public(cert_path, authority.certificate_pem())
            return authority
        if key_path.is_symlink() or cert_path.is_symlink() or not key_path.is_file() or not cert_path.is_file():
            raise CertificateError("deployment CA paths must be regular non-symlink files")
        if key_path.stat().st_mode & 0o077:
            raise CertificateError("deployment CA private key permissions must not allow group or other access")
        try:
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
        except (TypeError, ValueError) as exc:
            raise CertificateError("deployment CA material is invalid") from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CertificateError("deployment CA key must be elliptic curve")
        return cls(key, certificate)

    def private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)

    def update_signing_public_key_pem(self) -> str:
        return self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def issue_deployment_certificate(
        self,
        csr_pem: str,
        *,
        tenant_id: str,
        deployment_id: str,
        validity_days: int = 90,
    ) -> x509.Certificate:
        if not 1 <= validity_days <= 365:
            raise CertificateError("deployment certificate validity is outside the supported range")
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except (UnicodeEncodeError, ValueError) as exc:
            raise CertificateError("certificate signing request is not valid PEM") from exc
        if not csr.is_signature_valid:
            raise CertificateError("certificate signing request signature is invalid")
        public_key = csr.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
            raise CertificateError("deployment certificate requests must use ECDSA P-256")

        now = _utc_now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, deployment_id)])
        identity = f"spiffe://hybrid-ndr/tenant/{tenant_id}/deployment/{deployment_id}"
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.private_key.public_key()), critical=False)
            .sign(self.private_key, hashes.SHA256())
        )

    def issue_server_certificate(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        hostnames: Iterable[str],
        *,
        validity_days: int = 90,
    ) -> x509.Certificate:
        names = [name.strip() for name in hostnames if name.strip()]
        if not names:
            raise CertificateError("at least one server hostname is required")
        san: list[x509.GeneralName] = []
        for name in names:
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(name)))
            except ValueError:
                san.append(x509.DNSName(name))
        now = _utc_now()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(self.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(self.private_key, hashes.SHA256())
        )

    def sign_update_manifest(self, payload: bytes) -> str:
        signature = self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def verify_update_signature(public_key_pem: str | bytes, payload: bytes, signature: str) -> bool:
    try:
        raw_key = public_key_pem.encode("ascii") if isinstance(public_key_pem, str) else public_key_pem
        key = serialization.load_pem_public_key(raw_key)
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            return False
        padding = "=" * (-len(signature) % 4)
        decoded = base64.urlsafe_b64decode(signature + padding)
        key.verify(decoded, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False
