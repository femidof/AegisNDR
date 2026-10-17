"""Provision the Compose vendor endpoints using the existing deployment CA."""
from pathlib import Path
import importlib.util
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

spec = importlib.util.spec_from_file_location("pki", Path(__file__).parent / "hybrid_ndr_control_api/pki.py")
pki = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pki)
root = Path(os.environ["CONTROL_API_CA_KEY_FILE"]).parent
authority = pki.CertificateAuthority.load_or_create(root / "deployment-ca-key.pem", root / "deployment-ca-cert.pem")
for name in ("control-api", "model-gateway", "health-client"):
    key_path = root / f"{name}-key.pem"
    if key_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        pki._write_private(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    if name == "health-client":
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).sign(key, hashes.SHA256())
        cert = authority.issue_deployment_certificate(csr.public_bytes(serialization.Encoding.PEM).decode("ascii"), tenant_id="internal-health", deployment_id="gateway-health")
    else:
        cert = authority.issue_server_certificate(key, [name, "localhost", "127.0.0.1"])
    pki._write_public(root / f"{name}-cert.pem", cert.public_bytes(serialization.Encoding.PEM))
pki._write_public(Path("/var/lib/hybrid-ndr/trust/deployment-ca-cert.pem"), authority.certificate_pem())
print("Vendor server certificates and public trust bundle provisioned")
