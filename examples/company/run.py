"""Exercise a synthetic supplier entitlement policy through the public Guard API."""

import base64
import hashlib
import http.client
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


ENDPOINT = "/verify/supplier-orders"
ISSUER = "https://issuer.supplier.example.invalid"
CREDENTIAL_TYPE = "urn:proofsieve:example:supplier-access:v1"
RETURN_URL = "https://portal.example.invalid/orders"
FAIL_URL = "https://portal.example.invalid/eligibility-denied"


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def encode_json(value):
    return b64url(json.dumps(value, separators=(",", ":")).encode())


def issue(key, role="reviewer", *, mfa_enrolled=True, supplier_status="active",
          issuer=ISSUER, credential_type=CREDENTIAL_TYPE, expires_in=300):
    now = int(time.time())
    disclosed_claims = {"role": role}
    if mfa_enrolled is not None:
        disclosed_claims["mfa_enrolled"] = mfa_enrolled
    disclosures = [encode_json([secrets.token_urlsafe(16), claim, value])
                   for claim, value in disclosed_claims.items()]
    claims = {
        "iss": issuer,
        "vct": credential_type,
        "iat": now - 30,
        "exp": now + expires_in,
        "supplier_status": supplier_status,
        "_sd_alg": "sha-256",
        "_sd": [b64url(hashlib.sha256(item.encode("ascii")).digest()) for item in disclosures],
    }
    header = encode_json({"alg": "ES256", "typ": "dc+sd-jwt"})
    signing_input = f"{header}.{encode_json(claims)}"
    signature = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    jose_signature = b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return "~".join([f"{signing_input}.{jose_signature}", *disclosures, ""])


def replace_disclosed_role(credential):
    jws, role, *other_parts = credential.split("~")
    decoded = base64.urlsafe_b64decode(role + "=" * (-len(role) % 4))
    salt, name, _ = json.loads(decoded)
    return "~".join([jws, encode_json([salt, name, "procurement"]), *other_parts])


def request(port, method, path, *, data=None, token=None):
    headers = {"Content-Type": "application/json"} if data is not None else {}
    if token is not None:
        headers.update({"X-ProofSieve-Token": token, "If-None-Match": "*"})
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        body = json.dumps(data).encode() if data is not None else None
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.load(response)
    finally:
        connection.close()


def configure(port, issuer_key):
    status, admin = request(port, "GET", "/admin/rule")
    if status != 200:
        raise RuntimeError(f"Rule API returned HTTP {status}")
    key_pem = issuer_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    rule = {
        "language": "odrl",
        "responseMode": "url",
        "returnUrl": RETURN_URL,
        "failUrl": FAIL_URL,
        "policy": json.loads(Path(__file__).with_name("policy.json").read_text(encoding="utf-8")),
        "credential": {"format": "sd-jwt", "publicKeyPem": key_pem, "issuer": ISSUER},
    }
    query = urlencode({"endpoint": ENDPOINT})
    status, body = request(port, "PUT", f"/admin/rule?{query}", data=rule, token=admin["csrfToken"])
    if status != 200:
        raise RuntimeError(f"Could not configure {ENDPOINT}: HTTP {status}, {body}")


def exercise(port, issuer_key):
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    reviewer_not_enrolled = issue(issuer_key, mfa_enrolled=False)
    cases = [
        ("procurement", issue(issuer_key, "procurement", mfa_enrolled=None), "allow"),
        ("reviewer_enrolled", issue(issuer_key), "allow"),
        ("reviewer_not_enrolled", reviewer_not_enrolled, "policy"),
        ("reviewer_enrollment_wrong_type", issue(issuer_key, mfa_enrolled="true"), "policy"),
        ("inactive_supplier", issue(issuer_key, "procurement", supplier_status="inactive"), "policy"),
        ("wrong_credential_type", issue(issuer_key, credential_type="urn:example:other"), "policy"),
        ("wrong_issuer", issue(issuer_key, issuer="https://other.example.invalid"), "credential"),
        ("forged_signature", issue(rogue_key), "credential"),
        ("tampered_disclosure", replace_disclosed_role(reviewer_not_enrolled), "credential"),
        ("expired", issue(issuer_key, expires_in=-1), "credential"),
        ("unsigned_claims", {"vct": CREDENTIAL_TYPE, "supplier_status": "active", "role": "procurement"}, "credential"),
    ]
    for name, credential, expected in cases:
        status, decision = request(port, "POST", ENDPOINT, data={"data": credential})
        if expected == "credential":
            if (status != 403 or not isinstance(decision, dict)
                    or decision.get("stage") != "credential" or decision.get("code") != "credential_rejected"
                    or "redirectUrl" in decision):
                raise RuntimeError(f"{name}: expected credential rejection, got HTTP {status} {decision}")
        else:
            valid = expected == "allow"
            expected_decision = {"valid": valid, "redirectUrl": RETURN_URL if valid else FAIL_URL}
            if status != 200 or decision != expected_decision:
                raise RuntimeError(f"{name}: expected HTTP 200 {expected_decision}, got HTTP {status} {decision}")
        print(json.dumps({"case": name, "httpStatus": status, "decision": decision}))


def main():
    with tempfile.TemporaryDirectory(prefix="proofsieve-supplier-") as directory:
        state = Path(directory) / "rules.json"
        command = [sys.executable, "-m", "proofsieve", "--port", "0", "--state", str(state)]
        with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as server:
            try:
                startup = server.stdout.readline().strip()
                if not startup:
                    raise RuntimeError("ProofSieve did not report a listener")
                address = urlsplit(startup.split()[-1])
                if address.scheme != "http" or address.hostname != "127.0.0.1" or address.port is None:
                    raise RuntimeError("ProofSieve did not report a loopback listener")
                key = ec.generate_private_key(ec.SECP256R1())
                configure(address.port, key)
                exercise(address.port, key)
            finally:
                if server.poll() is None:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()


if __name__ == "__main__":
    main()
