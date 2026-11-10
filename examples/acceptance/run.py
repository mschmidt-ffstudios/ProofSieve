#!/usr/bin/env python3
"""Exercise real Keycloak, ProofSieve, DSS and signed test PKI over HTTP."""

import argparse
import base64
import hashlib
import json
import os
from contextlib import ExitStack, closing
from pathlib import Path
import secrets
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509 import ocsp

from pki import certificate_revocation_list, issue, write_store, write_tls
from services import (
    AUDIENCE, EXPIRING, NO_GRANT, SUPPLIER_ROLE, VERIFIER, WRONG_AUDIENCE, access_token, available_port, keycloak,
    https_proxy, ocsp_responder, request, secure_json, service, unix_request, wait_http,
)


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
from examples.company.run import issue as issue_sd_jwt, ISSUER, replace_disclosed_role


SUPPLIER = "/verify/supplier-orders"
ORDER = "/verify/order-approval"
SEAL = "/verify/sealed-pdf"
WRONG_SEAL = "/verify/wrong-seal-signer"
SELF_SIGNED = "/verify/self-signed"
REVOKED = "/verify/revoked-signature"
EXPIRED = "/verify/expired-certificate"
POLICY = "/verify/extra-policy"
ENDPOINTS = (SUPPLIER, ORDER, SEAL, WRONG_SEAL, SELF_SIGNED, REVOKED, EXPIRED, POLICY)
GRANTS = {f"verify-{endpoint.rsplit('/', 1)[1]}": endpoint for endpoint in ENDPOINTS}


def b64(data):
    return base64.b64encode(data).decode("ascii")


def proof(signer, signature=None):
    return {"signer": signer, **({"signature": b64(signature)} if signature is not None else {})}


def document(data, *proofs):
    return {"document": b64(data), "proofs": list(proofs)}


def signer(identity, id_, kind="local", **options):
    return {"id": id_, "kind": kind, "certificatePem": identity.pem.decode("ascii"), **options}


def verification_policy(id_, signers, threshold=1, *, minimum=None):
    policy = {
        "@context": ["http://www.w3.org/ns/odrl.jsonld", {"field": "https://proofsieve.example/facts/"}],
        "@type": "Set",
        "uid": f"urn:proofsieve:acceptance:policy:{id_}",
        "profile": "https://proofsieve.example/profiles/basic/v1",
        "permission": [{
            "target": f"urn:proofsieve:acceptance:operation:{id_}",
            "action": "use",
            "constraint": [{
                "leftOperand": "field:validSignerCount", "operator": "gteq",
                "rightOperand": threshold if minimum is None else minimum,
            }],
        }],
    }
    return {
        "language": "odrl", "responseMode": "decision", "policy": policy,
        "verification": {"threshold": threshold, "signers": signers},
    }


def raw_signature(identity, payload):
    return identity.key.sign(payload, padding.PKCS1v15(), hashes.SHA256())


class Acceptance:
    def __init__(self, api, admin, tokens, *, tls_context=None, operator=None):
        self.api = api
        self.admin = admin
        self.tokens = tokens
        self.tls_context = tls_context
        self.operator = operator
        self.results = []
        self.decisions = {}

    def call(self, path, method="GET", *, data=None, token=None, extra=None, operator=False):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        headers.update(extra or {})
        body = json.dumps(data).encode() if data is not None else None
        if operator and self.operator:
            status, payload, _ = unix_request(*self.operator, path, method, body, headers)
        else:
            status, payload = request(self.api + path, method, body, headers, self.tls_context)
        return status, json.loads(payload) if payload.startswith((b"{", b"[", b"t", b"f")) else None

    def expect(self, label, result, status, **fields):
        actual, payload = result
        if actual != status or any(not isinstance(payload, dict) or payload.get(k) != v for k, v in fields.items()):
            summary = {key: payload.get(key) for key in ("code", "outcome", "reason")
                       if isinstance(payload, dict) and key in payload}
            raise RuntimeError(f"{label} expected {status} {fields}, received {actual} {summary}")
        self.results.append({
            "case": label, "httpStatus": actual,
            **{key: payload[key] for key in ("code", "outcome", "reason", "decisionId", "operationId", "ruleVersion")
               if isinstance(payload, dict) and key in payload},
        })
        return payload

    def set_rule(self, endpoint, rule, *, status=200):
        authenticated, admin = self.call("/auth/me", token=self.admin, operator=True)
        if authenticated != 200 or admin.get("role") != "admin":
            raise RuntimeError("The operator did not authenticate with its private admin token")
        result = self.call(
            "/admin/rule?" + urlencode({"endpoint": endpoint}), "PUT", data=rule, token=self.admin,
            extra={"X-ProofSieve-Token": admin["csrfToken"], "If-None-Match": "*"}, operator=True,
        )
        if result[0] != status:
            raise RuntimeError(f"Configuring {endpoint} expected {status}, received {result[0]}")

    def decision(self, label, endpoint, data, outcome, reason, *, operation=None):
        operation = operation or f"order-{label}"
        result = self.call(endpoint, "POST", token=self.tokens[VERIFIER], data={
            "operationId": operation, "data": data,
        })
        payload = self.expect(label, result, 503 if outcome == "indeterminate" else 200,
                              operationId=operation, outcome=outcome, reason=reason, valid=outcome == "allow")
        decision_id = payload.get("decisionId")
        if uuid.UUID(decision_id).version != 4 or decision_id in self.decisions or len(payload["ruleVersion"]) != 64:
            raise RuntimeError("Invalid or repeated decision identity")
        self.decisions[decision_id] = (endpoint, operation, payload)
        return payload

    def verify_evidence(self, path, sentinel):
        with closing(sqlite3.connect(path)) as db:
            rows = db.execute(
                "SELECT id,endpoint,caller,operation_id,rule_version,input_mac,outcome,reason,checks FROM decisions"
            ).fetchall()
        if len(rows) != len(self.decisions):
            raise RuntimeError("The evidence count did not match the decision count")
        external_provenance = False
        for identifier, endpoint, caller, operation, version, fingerprint, outcome, reason, checks in rows:
            expected_endpoint, expected_operation, expected = self.decisions[identifier]
            if ((endpoint, operation, caller) != (expected_endpoint, expected_operation, VERIFIER)
                or (version, outcome, reason) != (expected["ruleVersion"], expected["outcome"], expected["reason"])
                or len(fingerprint) != 64):
                raise RuntimeError("An evidence record did not match its caller, operation or decision")
            if "dss-" in checks and "dss-6.5.1-test-v1" in checks:
                external_provenance = True
        if not external_provenance or sentinel in path.read_bytes():
            raise RuntimeError("External provenance is missing or an original document leaked into evidence")
        self.results.append({"case": "durable-evidence", "records": len(rows), "includesDssProvenance": True})


def exercise(suite, identities, ca, files, ocsp_config, dss_process, evidence):
    document_data = (files / "order.json").read_bytes()
    alt_document = document_data.replace(b"1042", b"9999")
    a, b, c, seal, revoked, self_signed, expired = (
        identities[name] for name in ("signer-a", "signer-b", "signer-c", "seal", "revoked", "self-signed", "expired")
    )
    local_a = signer(a, "a")
    dss_b = signer(b, "b", "dss", connector="dss-demo", format="cades-detached")
    status_c = signer(c, "c", "ocsp", connector="ocsp-demo", issuerCertificatePem=ca.pem.decode("ascii"))
    suite.set_rule(ORDER, verification_policy("order", [local_a, dss_b, status_c], 2))
    suite.set_rule(POLICY, verification_policy("extra-policy", [local_a, dss_b, status_c], 2, minimum=3))
    suite.set_rule(SEAL, verification_policy("seal", [signer(seal, "seal", "dss", connector="dss-demo", format="pades")]))
    suite.set_rule(WRONG_SEAL, verification_policy("wrong-seal", [signer(a, "seal", "dss", connector="dss-demo", format="pades")]))
    suite.set_rule(SELF_SIGNED, verification_policy("self-signed", [signer(self_signed, "self-signed")]))
    suite.set_rule(EXPIRED, verification_policy("expired", [signer(expired, "expired")]))
    suite.set_rule(REVOKED, verification_policy("revoked", [
        signer(revoked, "revoked", "dss", connector="dss-demo", format="cades-detached"),
    ]))
    suite.set_rule("/verify/disabled-connector", verification_policy("disabled", [
        signer(seal, "seal", "dss", connector="dss-not-enabled", format="pades"),
    ]), status=400)
    suite.results.append({"case": "unconfigured-dss-connector-rejected", "httpStatus": 400})

    sd_jwt_key = ec.generate_private_key(ec.SECP256R1())
    public_key = sd_jwt_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    suite.set_rule(SUPPLIER, {
        "language": "odrl", "responseMode": "decision",
        "policy": json.loads((HERE.parent / "company" / "policy.json").read_text(encoding="utf-8")),
        "credential": {"format": "sd-jwt", "publicKeyPem": public_key, "issuer": ISSUER},
    })
    sd_jwt = issue_sd_jwt(sd_jwt_key, "procurement", mfa_enrolled=None)
    body = {"operationId": "order-1042", "data": sd_jwt}
    suite.expect("missing-token", suite.call(SUPPLIER, "POST", data=body), 401, code="unauthenticated")
    suite.expect("wrong-audience", suite.call(SUPPLIER, "POST", data=body, token=suite.tokens[WRONG_AUDIENCE]),
                 401, code="unauthenticated")
    suite.expect("missing-grant", suite.call(SUPPLIER, "POST", data=body, token=suite.tokens[NO_GRANT]),
                 403, code="forbidden")
    suite.expect("scope-is-exact", suite.call("/verify", "POST", data=body, token=suite.tokens[VERIFIER]),
                 403, code="forbidden")
    suite.expect("admin-is-separated", suite.call(
        "/admin/rule", token=suite.tokens[VERIFIER], operator=True,
    ), 403, code="forbidden")
    jwt = suite.tokens[VERIFIER]
    head, payload, signature = jwt.split(".")
    forged = ".".join((head, payload, ("B" if signature[0] == "A" else "A") + signature[1:]))
    suite.expect("modified-keycloak-token", suite.call(SUPPLIER, "POST", data=body, token=forged), 401,
                 code="unauthenticated")
    expiring = suite.tokens[EXPIRING]
    expiring_payload = expiring.split(".")[1]
    expiring_claims = json.loads(base64.urlsafe_b64decode(expiring_payload + "=" * (-len(expiring_payload) % 4)))
    if expiring_claims["exp"] - expiring_claims["iat"] != 1:
        raise RuntimeError("The Keycloak expiry fixture requires an actual one-second access token")
    time.sleep(max(0, expiring_claims["exp"] - time.time() + 0.1))
    suite.expect("expired-keycloak-token", suite.call(SUPPLIER, "POST", data=body, token=expiring), 401,
                 code="unauthenticated")
    decision = suite.decision("signed-supplier", SUPPLIER, sd_jwt, "allow", "policy_allowed", operation="order-1042")
    blocked = issue_sd_jwt(sd_jwt_key, "reviewer", mfa_enrolled=False)
    suite.decision("supplier-policy-denial", SUPPLIER, blocked, "deny", "policy_denied")
    suite.decision("supplier-manipulated-disclosure", SUPPLIER, replace_disclosed_role(blocked), "deny",
                   "credential_rejected")

    pending = {"order-1042": hashlib.sha256(sd_jwt.encode("ascii")).digest()}

    def authorize_order(operation, submitted, result):
        if (result["outcome"] != "allow" or operation != result["operationId"]
                or pending.get(operation) != hashlib.sha256(submitted.encode("ascii")).digest()):
            return False
        pending.pop(operation)
        return True

    if (authorize_order("order-9999", sd_jwt, decision) or authorize_order("order-1042", blocked, decision)
        or not authorize_order("order-1042", sd_jwt, decision) or authorize_order(
        "order-1042", sd_jwt, decision,
    )):
        raise RuntimeError("Portal did not bind the decision to one specific order")
    suite.results.append({"case": "portal-rejects-cross-order-input-substitution-and-replay", "outcome": "passed"})

    pa = proof("a", raw_signature(a, document_data))
    cades = (files / "signer-b.p7s").read_bytes()
    pb = proof("b", cades)
    pc = proof("c", raw_signature(c, document_data))
    suite.decision("two-of-three-local-and-cades", ORDER, document(document_data, pa, pb), "allow", "policy_allowed")
    suite.decision("two-of-three-local-and-ocsp", ORDER, document(document_data, pa, pc), "allow", "policy_allowed")
    suite.decision("three-distinct-signers", ORDER, document(document_data, pa, pb, pc), "allow", "policy_allowed")
    suite.decision("local-only-below-threshold", ORDER, document(document_data, pa), "deny", "check_failed")
    suite.decision("signature-on-other-order", ORDER, document(alt_document, pa, pb), "deny", "check_failed")
    suite.decision("cades-tampered-signature", ORDER, document(document_data, pa, proof(
        "b", cades[:-1] + bytes([cades[-1] ^ 1]),
    )), "deny", "check_failed")
    suite.decision("cades-from-unlisted-certificate", ORDER,
                   document(document_data, pa, proof("b", (files / "revoked.p7s").read_bytes())), "deny", "check_failed")
    suite.decision("checks-passed-but-odrl-denies", POLICY, document(document_data, pa, pb), "deny", "policy_denied")
    suite.expect("duplicate-signer-is-malformed", suite.call(ORDER, "POST", token=jwt, data={
        "operationId": "order-duplicate", "data": document(document_data, pa, pa),
    }), 400)

    for name, status, options, outcome in [
        ("revoked", ocsp.OCSPCertStatus.REVOKED, {}, "deny"),
        ("unknown", ocsp.OCSPCertStatus.UNKNOWN, {}, "indeterminate"),
        ("stale", ocsp.OCSPCertStatus.GOOD, {"stale": True}, "indeterminate"),
        ("wrong-nonce", ocsp.OCSPCertStatus.GOOD, {"wrong_nonce": True}, "indeterminate"),
        ("unauthorized-signer", ocsp.OCSPCertStatus.GOOD, {"rogue": a}, "indeterminate"),
    ]:
        ocsp_config.update(status=status, options=options)
        reason = "check_failed" if outcome == "deny" else "check_indeterminate"
        suite.decision(f"ocsp-{name}", ORDER, document(document_data, pa, pc), outcome, reason)
    ocsp_config.update(status=ocsp.OCSPCertStatus.GOOD, options={})

    pdf = (files / "sealed-order.pdf").read_bytes()
    suite.decision("pades-organization-seal", SEAL, document(pdf, proof("seal")), "allow", "policy_allowed")
    if b"ProofSieve order 1042" not in pdf:
        raise RuntimeError("The PAdES test PDF lacks the expected signed page content")
    tampered = pdf.replace(b"ProofSieve order 1042", b"ProofSieve order 9999", 1)
    suite.decision("pades-tampered-signed-data", SEAL, document(tampered, proof("seal")), "deny", "check_failed")
    suite.decision("pades-appended-unsigned-bytes", SEAL, document(pdf + b"\n% added\n", proof("seal")),
                   "deny", "check_failed")
    suite.decision("pades-wrong-signing-cert", WRONG_SEAL, document(pdf, proof("seal")), "deny", "check_failed")
    suite.decision("pinned-self-signed-certificate", SELF_SIGNED, document(
        document_data, proof("self-signed", raw_signature(self_signed, document_data)),
    ), "allow", "policy_allowed")
    suite.decision("self-signed-wrong-key", SELF_SIGNED, document(
        document_data, proof("self-signed", raw_signature(a, document_data)),
    ), "deny", "check_failed")
    suite.decision("expired-certificate", EXPIRED, document(
        document_data, proof("expired", raw_signature(expired, document_data)),
    ), "deny", "check_failed")
    suite.decision("dss-revocation-inconclusive", REVOKED, document(
        document_data, proof("revoked", (files / "revoked.p7s").read_bytes()),
    ), "indeterminate", "check_indeterminate")

    dss_process.terminate()
    dss_process.wait(timeout=10)
    suite.decision("dss-outage-below-threshold", ORDER, document(document_data, pa, pb), "indeterminate",
                   "check_indeterminate")
    suite.decision("dss-outage-two-confirmed", ORDER, document(document_data, pa, pb, pc), "allow", "policy_allowed")
    suite.verify_evidence(evidence, document_data)


def setup_fixtures(directory, password, java, classpath, env):
    ca = issue("ProofSieve signing root", ca=True)
    identities = {name: issue(name, ca) for name in ("signer-a", "signer-b", "signer-c", "seal", "revoked")}
    identities["self-signed"] = issue("Self-signed approval")
    identities["expired"] = issue("Expired approval", ca, expired=True)
    (directory / "trust.pem").write_bytes(ca.pem)
    (directory / "revocations.crl").write_bytes(certificate_revocation_list(ca, [identities["revoked"]]))
    (directory / "order.json").write_bytes(b'{"order":"1042","currency":"EUR","amountMinor":12500}')
    names = ["signer-b", "seal", "revoked"]
    for name in names:
        write_store(directory / f"{name}.p12", identities[name], password, ca)
    subprocess.run([
        java, "-cp", classpath, "org.proofsieve.acceptance.Fixtures", str(directory), *names,
    ], env=env, check=True, timeout=30)
    return ca, identities


def run_acceptance(directory, args):
    java = str(args.keycloak_java_home / "bin" / "java")
    build = directory / "dss-build"
    subprocess.run([
        "mvn", "-B", "-q", "-f", str(HERE / "dss" / "pom.xml"), f"-Dacceptance.buildDirectory={build}",
        "compile", "dependency:copy-dependencies",
    ], check=True, timeout=150)
    classpath = os.pathsep.join((str(build / "classes"), str(build / "dependency" / "*")))
    password = secrets.token_urlsafe(32)
    dss_env = "PROOFSIEVE_ACCEPTANCE_DSS_TOKEN"
    env = {**os.environ, "PROOFSIEVE_ACCEPTANCE_STORE_PASSWORD": password, dss_env: secrets.token_urlsafe(32)}
    tls_ca = issue("ProofSieve TLS root", ca=True)
    trust = directory / "tls-trust.pem"
    trust.write_bytes(tls_ca.pem)
    cert, key, store = write_tls(directory, issue("ProofSieve test localhost", tls_ca, tls=True), tls_ca, password)
    context = ssl.create_default_context(cafile=trust)
    signature_ca, identities = setup_fixtures(directory, password, java, classpath, env)
    with ExitStack() as services:
        issuer, credentials, version = services.enter_context(
            keycloak(args.keycloak_home, args.keycloak_java_home, directory, cert, key, context, GRANTS.keys()),
        )
        tokens = {name: access_token(issuer, name, pair[1], context) for name, pair in credentials.items()}
        admin = secrets.token_urlsafe(32)
        auth = directory / "access.json"
        secure_json(auth, {
            "version": 2,
            "principals": [{"id": "test-admin", "role": "admin", "tokenSha256": hashlib.sha256(admin.encode()).hexdigest(),
                            "endpoints": ["*"]}],
            "oauth": {"issuer": issuer, "audience": AUDIENCE, "serviceAccounts": [
                {"id": name, "clientId": name, "subject": pair[0], "grants": {
                    VERIFIER: GRANTS, EXPIRING: {SUPPLIER_ROLE: SUPPLIER},
                }.get(name, {})}
                for name, pair in credentials.items()
            ]},
        })
        dss_port = available_port()
        dss_url = f"https://127.0.0.1:{dss_port}/validate"
        dss_process = services.enter_context(service([
            java, "-cp", classpath, "org.proofsieve.acceptance.Bridge", str(dss_port), str(store),
            str(directory / "trust.pem"), str(directory / "revocations.crl"),
        ], directory / "dss.log", env=env))
        wait_http(dss_url, 404, dss_process, context)
        ocsp_url, status = services.enter_context(ocsp_responder(cert, key, signature_ca, {
            identities["signer-c"].cert.serial_number: identities["signer-c"],
        }))
        checks = directory / "checks.json"
        secure_json(checks, {"version": 1, "connectors": {
            "dss-demo": {"kind": "dss", "url": dss_url, "allowedNetworks": ["127.0.0.1/32"], "caFile": str(trust),
                         "bearerEnv": dss_env, "profileVersion": "dss-6.5.1-test-v1"},
            "ocsp-demo": {"kind": "ocsp", "url": ocsp_url, "allowedNetworks": ["127.0.0.1/32"], "caFile": str(trust),
                          "profileVersion": "test-ocsp-v1"},
        }})
        evidence = directory / "evidence.sqlite3"
        guard_port = available_port()
        operator = None
        transport_flags = []
        if args.transport == "https":
            socket_dir = directory / "s"
            socket_dir.mkdir(mode=0o700)
            operator = (socket_dir / "admin", f"127.0.0.1:{guard_port}")
            api_socket = socket_dir / "api"
            api = services.enter_context(https_proxy(cert, key, api_socket))
            transport_flags = [
                "--socket", str(operator[0]), "--proxy-socket", str(api_socket), "--proxy-origin", api,
            ]
        else:
            api = f"http://127.0.0.1:{guard_port}"
        guard = services.enter_context(service([
            sys.executable, "-m", "proofsieve", "--port", str(guard_port), "--auth-config", str(auth),
            "--checks-config", str(checks), "--evidence", str(evidence), "--state", str(directory / "rules.json"),
            *transport_flags,
        ], directory / "guard.log", env={**env, "SSL_CERT_FILE": str(trust)}, cwd=ROOT))
        wait_http(api + "/openapi.json", 401, guard, context)
        suite = Acceptance(api, admin, tokens, tls_context=context, operator=operator)
        if operator:
            suite.expect("https-excludes-admin", suite.call("/admin/rule", token=admin), 404)
            direct_status, _, _ = unix_request(api_socket, api.removeprefix("https://"), "/admin/rule",
                                               headers={"Authorization": "Bearer " + admin})
            suite.expect("api-socket-excludes-admin", (direct_status, None), 403)
        exercise(suite, identities, signature_ca, directory, status, dss_process, evidence)
        return suite.results, version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-home", type=Path, required=True, help="Extracted Keycloak distribution (tested with 26.8.2)")
    parser.add_argument("--keycloak-java-home", type=Path, required=True, help="JDK 25 directory with bin/java")
    parser.add_argument("--transport", choices=("https", "loopback"), default="https",
                        help="Test TLS with separate sockets, or the loopback reference listener")
    parser.add_argument("--report", type=Path, help="Write the sanitized report to a new JSON file")
    args = parser.parse_args()
    if not (args.keycloak_home / "bin" / "kc.sh").is_file() or not (args.keycloak_java_home / "bin" / "java").is_file():
        parser.error("Supply an extracted Keycloak server and its supported JDK")
    args.keycloak_home = args.keycloak_home.resolve()
    args.keycloak_java_home = args.keycloak_java_home.resolve()
    with tempfile.TemporaryDirectory(prefix="proofsieve-acceptance-") as scratch:
        directory = Path(scratch)
        try:
            results, version = run_acceptance(directory, args)
        except Exception:
            for name in ("keycloak.log", "dss.log", "guard.log"):
                log = directory / name
                if log.is_file():
                    print(f"--- {name} ---\n{log.read_text(errors='replace')[-5000:]}", file=sys.stderr)
            raise
    report = {"keycloak": version, "dss": "6.5.1", "transport": args.transport, "cases": len(results), "results": results}
    if args.report:
        secure_json(args.report, report)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
