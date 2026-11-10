#!/usr/bin/env python3
"""Exercise extended document formats over TLS using real DSS and disposable PKI."""

import argparse
import base64
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
from zipfile import ZipFile

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE.parents[2])]
from pki import Identity, certificate_revocation_list, issue, write_store, write_tls
from services import available_port, secure_json, service, wait_http
from proofsieve.checks import load_check_registry
from proofsieve.evidence import EvidenceStore
from proofsieve.guard import DEFAULT_RULE, Guard


def timestamp_authority(ca):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ProofSieve test TSA")]))
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.key.public_key()), critical=False)
        .sign(ca.key, hashes.SHA256())
    )
    return Identity(certificate, key)


def data(document, signature=None):
    def encode(value):
        return base64.b64encode(value).decode("ascii")

    proof = {"signer": "authority"}
    if signature is not None:
        proof["signature"] = encode(signature)
    return {"document": encode(document), "proofs": [proof]}


def rewrite_container(document, *, add_unsigned=False):
    output = BytesIO()
    with ZipFile(BytesIO(document)) as old, ZipFile(output, "w") as new:
        for entry in old.infolist():
            content = old.read(entry)
            if not add_unsigned and entry.filename == "order.json":
                content = b'{"amountMinor":99999}'
            new.writestr(entry, content)
        if add_unsigned:
            new.writestr("unsigned.txt", b"Unsigned payload")
    return output.getvalue()


def change_central_filename(archive):
    central = int.from_bytes(archive[-6:-2], "little")
    index = archive.index(b"order.json", central)
    return archive[:index] + b"other.json" + archive[index + len(b"order.json"):]


def probe(directory, registry, signer, tsa):
    evidence = EvidenceStore(directory / "evidence.sqlite")
    guard = Guard(directory / "rules.json", {}, evidence=evidence, registry=registry)
    order = (directory / "order.json").read_bytes()
    changed_order = b'{"amountMinor":99999}'
    variants = {
        "xades-detached": "xades.xml",
        "jades-detached": "jades.jws",
        "cbades-detached": "cbades.cose",
        "rfc3161": "timestamp.tst",
        "asic-s": "signed.asics",
        "asic-e": "signed.asice",
    }
    expected_evidence = {}
    for kind, filename in variants.items():
        certificate = tsa if kind == "rfc3161" else signer
        endpoint = f"/verify/document/{kind}"
        rule = deepcopy(DEFAULT_RULE)
        rule["responseMode"] = "decision"
        rule["verification"] = {"threshold": 1, "signers": [{
            "id": "authority", "kind": "dss", "connector": "test-dss",
            "format": kind, "certificatePem": certificate.pem.decode("ascii"),
        }]}
        rule["policy"]["permission"][0]["constraint"][0] = (
            {"leftOperand": "field:timestampVerified", "operator": "eq", "rightOperand": True}
            if kind == "rfc3161"
            else {"leftOperand": "field:validSignerCount", "operator": "gteq", "rightOperand": 1}
        )
        guard.update(rule, endpoint)
        artifact = (directory / filename).read_bytes()
        if kind.startswith("asic-"):
            positive = data(artifact)
            negative = [
                data(rewrite_container(artifact)),
                data(rewrite_container(artifact, add_unsigned=True)),
                data(artifact + b"trailing-bytes"),
                data(change_central_filename(artifact)),
            ]
        else:
            positive = data(order, artifact)
            negative = [data(changed_order, artifact)]
        for index, candidate in enumerate([positive, *negative]):
            operation = f"{kind}-{index}"
            outcome = "allow" if index == 0 else "deny"
            expected_reason = "policy_allowed" if index == 0 else "check_failed"
            status, result = guard.verify(candidate, endpoint, operation_id=operation, caller="test-verifier")
            if status != 200 or result.get("outcome") != outcome or result.get("reason") != expected_reason:
                raise RuntimeError(f"{operation} expected {outcome}/{expected_reason}, received {status} {result}")
            expected_evidence[operation] = (result["decisionId"], outcome)
        print(f"{kind}: original passed, {len(negative)} changed inputs rejected", flush=True)
    with closing(evidence.connect()) as database:
        rows = database.execute("SELECT operation_id, id, outcome, checks FROM decisions").fetchall()
    if len(rows) != len(expected_evidence):
        raise RuntimeError("Unexpected count in Guard evidence database")
    for operation, decision, outcome, checks in rows:
        if ((decision, outcome) != expected_evidence[operation]
                or not json.loads(checks)[0].get("reportId", "").startswith("dss-")):
            raise RuntimeError(f"Missing DSS provenance for {operation}")
    print(f"Guard decisions and DSS reports matched all {len(rows)} evidence records.", flush=True)


def run(directory, java_home):
    build = directory / "build"
    java = str(java_home / "bin" / "java") if java_home else "java"
    password = secrets.token_urlsafe(32)
    env = {**os.environ, "PROOFSIEVE_ACCEPTANCE_STORE_PASSWORD": password,
           "PROOFSIEVE_ACCEPTANCE_DSS_TOKEN": secrets.token_urlsafe(32)}
    if java_home:
        env["JAVA_HOME"] = str(java_home)
    subprocess.run([
        "mvn", "-B", "-q", "-f", str(HERE / "pom.xml"), f"-Dacceptance.buildDirectory={build}",
        "compile", "dependency:copy-dependencies",
    ], env=env, check=True, timeout=150)
    classpath = os.pathsep.join((str(build / "classes"), str(build / "dependency" / "*")))

    ca = issue("ProofSieve document test root", ca=True)
    signer = issue("ProofSieve document test signer", ca, crl_url="https://invalid.example/test.crl")
    tsa = timestamp_authority(ca)
    (directory / "trust.pem").write_bytes(ca.pem)
    (directory / "revocations.crl").write_bytes(certificate_revocation_list(ca, []))
    (directory / "order.json").write_bytes(b'{"order":"1042","currency":"EUR","amountMinor":12500}')
    write_store(directory / "signer.p12", signer, password, ca)
    write_store(directory / "tsa.p12", tsa, password, ca)
    subprocess.run([java, "-cp", classpath, "org.proofsieve.acceptance.ExtendedFixtures", str(directory)],
                   env=env, check=True, timeout=40)

    tls_ca = issue("ProofSieve TLS test root", ca=True)
    tls_trust = directory / "tls-trust.pem"
    tls_trust.write_bytes(tls_ca.pem)
    _, _, store = write_tls(directory, issue("ProofSieve test localhost", tls_ca, tls=True), tls_ca, password)
    port = available_port()
    url = f"https://127.0.0.1:{port}/validate"
    config = directory / "checks.json"
    secure_json(config, {"version": 1, "connectors": {"test-dss": {
        "kind": "dss", "url": url, "caFile": str(tls_trust), "allowedNetworks": ["127.0.0.1/32"],
        "bearerEnv": "PROOFSIEVE_ACCEPTANCE_DSS_TOKEN", "timeoutSeconds": 8,
    }}})
    os.environ["PROOFSIEVE_ACCEPTANCE_DSS_TOKEN"] = env["PROOFSIEVE_ACCEPTANCE_DSS_TOKEN"]
    registry = load_check_registry(config)
    logfile = directory / "bridge.log"
    with service([java, "-cp", classpath, "org.proofsieve.acceptance.Bridge", str(port), str(store),
                  str(directory / "trust.pem"), str(directory / "revocations.crl")], logfile, env=env) as process:
        wait_http(url, 404, process, ssl.create_default_context(cafile=tls_trust))
        try:
            probe(directory, registry, signer, tsa)
        except RuntimeError:
            print(logfile.read_text(errors="replace"), file=sys.stderr)
            raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, help="JDK home for both Maven and the DSS bridge")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="proofsieve-document-formats-") as folder:
        run(Path(folder), args.java_home)
