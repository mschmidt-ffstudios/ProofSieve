#!/usr/bin/env python3
"""Run Guard and the real DSS bridge with disposable signed inputs."""

import argparse
from contextlib import ExitStack, contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(HERE.parent), str(ROOT)]
from pki import issue, write_tls
from run import document, proof, setup_fixtures
from services import available_port, secure_json, service, wait_http


@contextmanager
def start_demo(java_home=None):
    """Yield the private demo directory and Guard origin until teardown."""
    env = dict(os.environ)
    java = "java"
    if java_home is not None:
        java_home = Path(java_home).resolve()
        env["JAVA_HOME"] = str(java_home)
        java = str(java_home / "bin" / "java")

    with tempfile.TemporaryDirectory(prefix="proofsieve-dss-demo-") as folder, ExitStack() as services:
        directory = Path(folder).resolve()
        build = directory / "build"
        subprocess.run([
            "mvn", "-B", "-q", "-f", str(HERE / "pom.xml"), f"-Dacceptance.buildDirectory={build}",
            "compile", "dependency:copy-dependencies",
        ], env=env, check=True, timeout=150)
        classpath = os.pathsep.join((str(build / "classes"), str(build / "dependency" / "*")))
        password = secrets.token_urlsafe(32)
        bearer_env = "PROOFSIEVE_ACCEPTANCE_DSS_TOKEN"
        env.update({"PROOFSIEVE_ACCEPTANCE_STORE_PASSWORD": password, bearer_env: secrets.token_urlsafe(32)})
        _, identities = setup_fixtures(directory, password, java, classpath, env)

        signer_id = "finance"
        signature = proof(signer_id, (directory / "signer-b.p7s").read_bytes())
        order = (directory / "order.json").read_bytes()
        changed = json.loads(order)
        changed["amountMinor"] += 1
        modified = json.dumps(changed, separators=(",", ":")).encode("utf-8")
        secure_json(directory / "original.json", document(order, signature))
        secure_json(directory / "modified.json", document(modified, signature))
        secure_json(directory / "verification-profile.json", {"threshold": 1, "signers": [{
            "id": signer_id,
            "kind": "dss",
            "format": "cades-detached",
            "connector": "dss-demo",
            "certificatePem": identities["signer-b"].pem.decode("ascii"),
        }]})

        tls_ca = issue("ProofSieve demo TLS root", ca=True)
        tls_trust = directory / "tls-trust.pem"
        tls_trust.write_bytes(tls_ca.pem)
        _, _, store = write_tls(directory, issue("ProofSieve demo localhost", tls_ca, tls=True), tls_ca, password)
        dss_port = available_port()
        verifier_url = f"https://127.0.0.1:{dss_port}/validate"
        checks = directory / "checks.json"
        secure_json(checks, {"version": 1, "connectors": {"dss-demo": {
            "kind": "dss",
            "url": verifier_url,
            "allowedNetworks": ["127.0.0.1/32"],
            "caFile": str(tls_trust),
            "bearerEnv": bearer_env,
            "profileVersion": "dss-6.5.1-demo",
        }}})
        bridge = services.enter_context(service([
            java, "-cp", classpath, "org.proofsieve.acceptance.Bridge", str(dss_port), str(store),
            str(directory / "trust.pem"), str(directory / "revocations.crl"),
        ], directory / "bridge.log", env=env))
        wait_http(verifier_url, 404, bridge, ssl.create_default_context(cafile=tls_trust))

        admin = secrets.token_urlsafe(32)
        with os.fdopen(os.open(directory / "admin.token", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
            output.write(admin + "\n")
        auth = directory / "access.json"
        secure_json(auth, {"version": 1, "principals": [{
            "id": "demo-admin", "role": "admin", "endpoints": ["*"],
            "tokenSha256": sha256(admin.encode("ascii")).hexdigest(),
        }]})
        guard_port = available_port()
        address = f"http://127.0.0.1:{guard_port}"
        guard = services.enter_context(service([
            sys.executable, "-m", "proofsieve", "--port", str(guard_port),
            "--auth-config", str(auth), "--checks-config", str(checks),
            "--evidence", str(directory / "evidence.sqlite3"), "--evidence-export",
            "--state", str(directory / "rules.json"),
        ], directory / "guard.log", env=env, cwd=ROOT))
        wait_http(address + "/openapi.json", 401, guard)
        yield directory, address


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, help="JDK home for Maven and the DSS bridge")
    args = parser.parse_args()
    with start_demo(args.java_home) as (directory, address):
        config = json.loads((directory / "checks.json").read_text(encoding="utf-8"))
        print(f"Guard: {address}/apps/guard/")
        print(f"DSS verifier: {config['connectors']['dss-demo']['url']}")
        print(f"Private demo files: {directory}")
        print("Use admin.token to sign in and verification-profile.json to configure the rule.")
        print("Use original.json and modified.json as verification inputs.")
        try:
            input("Press Enter to stop the services and remove the demo files.\n")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    main()
