#!/usr/bin/env python3
"""Create signed time/revocation faults only in an isolated credential test state."""
import datetime
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

state = Path(sys.argv[1])
if state.parent != Path("/var/lib/twinet") or not state.name.startswith("credential-test-"):
    raise SystemExit("Refusing a non-test state directory")
operation, device = sys.argv[2:4]
ca_dir = state / "ca/credential-test"
ca = x509.load_pem_x509_certificate((ca_dir / "ca.pem").read_bytes())
key = serialization.load_pem_private_key((ca_dir / "ca-key.pem").read_bytes(), None)
now = datetime.datetime.now(datetime.timezone.utc)
leaf_path = state / "devices" / device / "swanctl/x509/cert.pem"

if operation == "age-leaf":
    cert = x509.load_pem_x509_certificate(leaf_path.read_bytes())
    builder = x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
    builder = builder.public_key(cert.public_key()).serial_number(cert.serial_number)
    builder = builder.not_valid_before(now - datetime.timedelta(days=29))
    builder = builder.not_valid_after(now + datetime.timedelta(days=1))
    for extension in cert.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    encoded = builder.sign(key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM)
    leaf_path.write_bytes(encoded)
    (state / "retired-leaf.pem").write_bytes(encoded)
elif operation in {"expire-crl", "revoke-retired"}:
    path = ca_dir / "crl.pem"
    old = x509.load_pem_x509_crl(path.read_bytes())
    serial = 424242
    if operation == "revoke-retired":
        serial = x509.load_pem_x509_certificate((state / "retired-leaf.pem").read_bytes()).serial_number
    builder = x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
    builder = builder.last_update(now - datetime.timedelta(days=8) if operation == "expire-crl" else now - datetime.timedelta(minutes=1))
    builder = builder.next_update(now - datetime.timedelta(days=1) if operation == "expire-crl" else now + datetime.timedelta(days=7))
    for item in old:
        builder = builder.add_revoked_certificate(item)
    if not any(item.serial_number == serial for item in old):
        entry = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now - datetime.timedelta(days=9)).build()
        builder = builder.add_revoked_certificate(entry)
    number = old.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number + 1
    builder = builder.add_extension(x509.CRLNumber(number), False)
    #* Preserve the CA's actual identifier; Go can derive it using SHA-256.
    ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), False)
    encoded = builder.sign(key, hashes.SHA384()).public_bytes(serialization.Encoding.PEM)
    path.write_bytes(encoded)
    if operation == "expire-crl":
        for target in state.glob("devices/*/swanctl/x509crl/ca.crl.pem"):
            target.write_bytes(encoded)
else:
    raise SystemExit("Unknown test operation")
