"""Create disposable test certificates and real signed OCSP responses."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class Identity:
    cert: x509.Certificate
    key: rsa.RSAPrivateKey

    @property
    def pem(self):
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def fingerprint(self):
        return self.cert.fingerprint(hashes.SHA256()).hex()


def issue(name, issuer=None, *, ca=False, tls=False, expired=False, crl_url=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ProofSieve Acceptance"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=-1 if expired else 2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=not ca and not tls,
            key_encipherment=tls, data_encipherment=False, key_agreement=False,
            key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer.key.public_key() if issuer else key.public_key(),
        ), critical=False)
    )
    if tls:
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ip_address("127.0.0.1")), x509.DNSName("localhost"),
        ]), critical=False).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False,
        )
    if crl_url:
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_url)], relative_name=None,
                reasons=None, crl_issuer=None,
            ),
        ]), critical=False)
    return Identity(builder.sign(issuer.key if issuer else key, hashes.SHA256()), key)


def write_tls(directory: Path, identity: Identity, issuer: Identity, password: str):
    certificate = directory / "tls.pem"
    key = directory / "tls.key"
    store = directory / "tls.p12"
    certificate.write_bytes(identity.pem + issuer.pem)
    key.write_bytes(identity.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ))
    write_store(store, identity, password, issuer)
    return certificate, key, store


def write_store(path, identity, password, issuer=None):
    path.write_bytes(pkcs12.serialize_key_and_certificates(
        b"test-identity", identity.key, identity.cert, [issuer.cert] if issuer else None,
        serialization.BestAvailableEncryption(password.encode("ascii")),
    ))


def certificate_revocation_list(issuer, revoked):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.cert.subject)
        .last_update(now - timedelta(minutes=10))
        .next_update(now + timedelta(hours=1))
        .add_extension(x509.CRLNumber(1), critical=False)
    )
    for identity in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(identity.cert.serial_number)
            .revocation_date(now - timedelta(minutes=5))
            .add_extension(x509.CRLReason(x509.ReasonFlags.key_compromise), critical=False)
            .build(),
        )
    return builder.sign(issuer.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def ocsp_response(request_der, identity, issuer, status, *, stale=False, wrong_nonce=False, rogue=None):
    request = ocsp.load_der_ocsp_request(request_der)
    if request.serial_number != identity.cert.serial_number:
        raise ValueError("unexpected OCSP certificate")
    nonce = request.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    now = datetime.now(timezone.utc)
    revoked = status == ocsp.OCSPCertStatus.REVOKED
    signer = rogue or issuer
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=identity.cert, issuer=issuer.cert, algorithm=request.hash_algorithm,
            cert_status=status, this_update=now - timedelta(hours=2 if stale else 0, minutes=1),
            next_update=now + timedelta(minutes=-1 if stale else 10),
            revocation_time=now - timedelta(minutes=5) if revoked else None,
            revocation_reason=x509.ReasonFlags.key_compromise if revoked else None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, signer.cert)
        .add_extension(x509.OCSPNonce(b"wrong-test-nonce" if wrong_nonce else nonce), critical=False)
        .sign(signer.key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
