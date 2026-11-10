"""Run the release checkout with disposable Credo and EUDI wallet verifiers."""

import argparse
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from eudi_runtime import JAR_SHA256, UPSTREAM_COMMIT, verify_jar
from services import secure_json, service
from wallet_cases import DOC_TYPE, ISSUER, SURNAME, VCT, WalletTarget, initialize, origin, request


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))
from proofsieve.evidence import EvidenceStore
from proofsieve.guard import DEFAULT_RULE
from upgrade_rollback import rehearse


LOOPBACK = "127.0.0.1"
CREDO_USE = "proofsieve-internal-test"
EUDI_USE = "test-profile"
CREDO_BEARER = "PROOFSIEVE_CREDO_BEARER"
EUDI_BEARER = "PROOFSIEVE_EUDI_BEARER"
CREDO_PRIVATE_PATH = "/internal/proofsieve/wallet/transactions"
EUDI_PRIVATE_PATH = "/ui/presentations/acceptance-probe"
BRIDGE_FILES = ("package.json", "package-lock.json", "server.mjs", "storage.mjs", "storage.test.mjs")


def separate_ports():
    with ExitStack() as stack:
        listeners = [stack.enter_context(socket.socket()) for _ in range(6)]
        for listener in listeners:
            listener.bind((LOOPBACK, 0))
        return [listener.getsockname()[1] for listener in listeners]


def checkout_revision(expected):
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, timeout=10,
    ).strip()
    if actual != expected:
        raise ValueError("Wallet release checkout does not match the requested revision")
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, timeout=10).returncode != 0:
        raise ValueError("Wallet release checkout contains modified tracked files")
    return actual


def clean_environment():
    return {
        key: value for key, value in os.environ.items()
        if key in {"HOME", "PATH", "LANG", "TZ", "TMPDIR", "XDG_CACHE_HOME", "PLAYWRIGHT_BROWSERS_PATH"}
        or key.startswith("LC_")
    } | {"NO_PROXY": LOOPBACK, "PYTHONDONTWRITEBYTECODE": "1"}


def https(port):
    return f"https://{LOOPBACK}:{port}"


def configure(root, fixture, ports):
    credo_public, credo_private, eudi_public, eudi_private = ports
    pin = json.loads((fixture / "metadata.json").read_text())["clientId"]
    ca_path = str(fixture / "tls-ca.pem")
    credo_token = secrets.token_urlsafe(32)
    eudi_token = secrets.token_urlsafe(32)
    verifier_token = secrets.token_urlsafe(32)
    (root / "verifier-token").write_text(verifier_token + "\n", encoding="ascii")
    (root / "eudi-bearer").write_text(eudi_token + "\n", encoding="ascii")
    secure_json(root / "credo.json", {
        "publicOrigin": https(credo_public), "publicHost": LOOPBACK,
        "publicPort": credo_public, "privatePort": credo_private,
        "tlsCertFile": str(fixture / "tls.pem"), "tlsKeyFile": str(fixture / "tls-key.pem"),
        "verifierCertFile": str(fixture / "verifier.pem"),
        "verifierKeyFile": str(fixture / "verifier-key.pem"),
        "intendedUseId": CREDO_USE, "bearerEnv": CREDO_BEARER,
    })

    connectors = {
        identifier: {
            "kind": kind, "url": https(private_port), "allowedNetworks": [LOOPBACK + "/32"],
            "bearerEnv": bearer, "publicOrigin": https(public_port), "clientId": pin, "caFile": ca_path,
        }
        for identifier, kind, private_port, public_port, bearer in (
            ("credo", "credo", credo_private, credo_public, CREDO_BEARER),
            ("eudi-reference", "eudi", eudi_private, eudi_public, EUDI_BEARER),
        )
    }
    rules = {"/verify": DEFAULT_RULE}
    endpoints = {}
    issuer_ca = (fixture / "issuer-ca.pem").read_text()
    for name, form, credential_type, claim_path in (
        ("sd-jwt", "dc+sd-jwt", VCT, ["family_name"]),
        ("mdoc", "mso_mdoc", DOC_TYPE, [DOC_TYPE, "family_name"]),
    ):
        rule = deepcopy(DEFAULT_RULE)
        rule.update(responseMode="decision", wallet=True)
        rule["policy"]["uid"] = f"urn:proofsieve:comparison:{name}"
        rule["policy"]["permission"][0]["constraint"] = [
            {"leftOperand": "field:surname", "operator": "eq", "rightOperand": SURNAME}
        ]
        for slug, connector, intended_use in (
            ("credo", "credo", CREDO_USE), ("eudi", "eudi-reference", EUDI_USE),
        ):
            path = f"/verify/compare/{slug}-{name}"
            rules[path] = rule
            profile = {
                "format": form, "credentialType": credential_type, "issuerChainPem": issuer_ca,
                "intendedUseId": intended_use, "claims": {"surname": {"path": claim_path, "type": "string"}},
                "status": {"mode": "not-required"},
            }
            if name == "sd-jwt":
                profile["issuer"] = ISSUER
            endpoints[path] = {"connector": connector, "profile": profile}

    def grant(role, token, paths):
        return {
            "id": f"compare-{role}", "role": role, "endpoints": paths,
            "tokenSha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        }

    secure_json(root / "wallet.json", {"version": 1, "connectors": connectors, "endpoints": endpoints})
    secure_json(root / "rules.json", {"version": 1, "rules": rules})
    secure_json(root / "access.json", {"version": 1, "principals": [
        grant("admin", secrets.token_urlsafe(32), ["*"]), grant("verifier", verifier_token, sorted(endpoints)),
    ]})
    store = EvidenceStore(root / "evidence.db")
    (root / "evidence-public-key").write_text(store.export_public_key + "\n", encoding="ascii")
    return {CREDO_BEARER: credo_token, EUDI_BEARER: eudi_token}


def wait_ready(process, url, expected, *, tls=None):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Service for {url} stopped with status {process.returncode}")
        try:
            status, _ = request(url, origin(url), context=tls)
            if status == expected:
                return
            raise RuntimeError(f"Service for {url} returned HTTP {status} instead of {expected}")
        except (ConnectionRefusedError, TimeoutError):
            # The TLS listener can bind before the EUDI backend is ready to serve.
            time.sleep(0.2)
    raise RuntimeError(f"Service readiness timed out at {url}")


def check_status(url, expected, tls):
    status, _ = request(url, origin(url), context=tls)
    if status != expected:
        raise RuntimeError(f"Listener boundary check for {url} returned HTTP {status} instead of {expected}")


def run(args):
    revision = checkout_revision(args.revision)
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Wallet output directory must be new")
    if not args.askar_library_dir.is_dir():
        raise ValueError("Askar native library directory is missing")
    os.umask(0o077)
    env = clean_environment()
    metadata = {
        "revision": revision, "eudiReferenceRevision": UPSTREAM_COMMIT, "eudiJarSha256": JAR_SHA256,
        "stage": "eudi-jar", "complete": False,
    }
    try:
        verify_jar(args.eudi_jar)
        with TemporaryDirectory(prefix="proofsieve-wallet-release-") as temporary, ExitStack() as stack:
            root = Path(temporary)
            fixture = root / "fixtures"
            metadata["stage"] = "fixtures"
            initialize(fixture, LOOPBACK)
            guard_port, credo_public, credo_private, eudi_public, eudi_private, eudi_backend = separate_ports()
            guard = f"http://{LOOPBACK}:{guard_port}"
            tokens = configure(root, fixture, (credo_public, credo_private, eudi_public, eudi_private))
            tls = ssl.create_default_context(cafile=str(fixture / "tls-ca.pem"))

            metadata["stage"] = "locked-credo-install"
            bridge = root / "credo"
            bridge.mkdir(mode=0o700)
            for name in BRIDGE_FILES:
                shutil.copyfile(ROOT / "integrations" / "credo" / name, bridge / name)
            lock = json.loads((bridge / "package-lock.json").read_text())
            metadata["credoVersion"] = lock["packages"]["node_modules/@credo-ts/core"]["version"]
            subprocess.run(
                [args.npm, "ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
                cwd=bridge, env=env, check=True, timeout=180,
            )

            metadata["stage"] = "credo-storage-reopen"
            subprocess.run(
                [args.node, "--test", "storage.test.mjs"], cwd=bridge,
                env=env | {"LIB_ASKAR_PATH": str(args.askar_library_dir)}, check=True, timeout=45,
            )
            metadata["credoStoragePoolTurnover"] = "passed"

            metadata["stage"] = "credo-readiness"
            credo = stack.enter_context(service(
                [args.node, str(bridge / "server.mjs"), str(root / "credo.json")],
                root / "credo.log", cwd=bridge,
                env=env | {CREDO_BEARER: tokens[CREDO_BEARER], "LIB_ASKAR_PATH": str(args.askar_library_dir)},
            ))
            wait_ready(credo, https(credo_private) + CREDO_PRIVATE_PATH, 401, tls=tls)
            check_status(https(credo_public) + CREDO_PRIVATE_PATH, 404, tls)

            metadata["stage"] = "eudi-readiness"
            eudi = stack.enter_context(service(
                [sys.executable, str(HERE / "eudi_runtime.py"), "--directory", str(fixture),
                 "--jar", str(args.eudi_jar), "--java", args.java, "--wallet-port", str(eudi_public),
                 "--private-port", str(eudi_private), "--backend-port", str(eudi_backend),
                 "--bearer-file", str(root / "eudi-bearer")],
                root / "eudi.log", cwd=root, env=env,
            ))
            wait_ready(eudi, https(eudi_public) + "/wallet/public-keys.json", 200, tls=tls)
            check_status(https(eudi_private) + EUDI_PRIVATE_PATH, 401, tls)
            check_status(https(eudi_public) + EUDI_PRIVATE_PATH, 404, tls)

            metadata["stage"] = "guard-readiness"
            guard_process = stack.enter_context(service(
                [sys.executable, "-m", "proofsieve", "--port", str(guard_port),
                 "--auth-config", str(root / "access.json"), "--state", str(root / "rules.json"),
                 "--evidence", str(root / "evidence.db"), "--evidence-export",
                 "--wallet-config", str(root / "wallet.json"), "--wallet-sessions", str(root / "wallet-sessions.db")],
                root / "guard.log", cwd=ROOT, env=env | tokens,
            ))
            wait_ready(guard_process, guard + "/auth/me", 401)

            metadata["stage"] = "browser-comparison"
            ca = str(fixture / "tls-ca.pem")
            reader = str(fixture / "verifier.pem")
            subprocess.run(
                [sys.executable, str(HERE / "run_wallet_comparison.py"),
                 "--guard", guard, "--credentials", str(fixture),
                 "--credo", https(credo_public), ca, reader, "--eudi", https(eudi_public), ca, reader,
                 "--token-file", str(root / "verifier-token"), "--evidence-key-file", str(root / "evidence-public-key"),
                 "--output", str(args.output), "--check-credo-envelope"],
                cwd=ROOT, env=env, check=True, timeout=240,
            )
            if args.previous_binary:
                metadata["stage"] = "installed-release-recovery"
                candidate_version = json.loads((ROOT / "openapi.json").read_text())["info"]["version"]
                target = WalletTarget.from_files(
                    https(credo_public), fixture / "tls-ca.pem", fixture / "verifier.pem", "credo",
                )
                rehearse(
                    args.previous_binary, args.candidate_binary, candidate_version, root, fixture, target,
                    env | tokens, args.output / "upgrade-rollback.json",
                )
            for adapter in (credo, eudi, guard_process):
                if adapter.poll() is not None:
                    raise RuntimeError("A wallet acceptance service exited during the run")
        metadata.update(stage="completed", complete=True)
    finally:
        args.output.mkdir(mode=0o700, exist_ok=True)
        secure_json(args.output / "wallet-run.json", metadata)


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="Exact checked out Git commit SHA")
    parser.add_argument("--eudi-jar", type=Path, required=True, help="Pinned EUDI Reference Verifier JAR")
    parser.add_argument("--java", default="java", help="Java 25 executable")
    parser.add_argument("--node", default="node", help="Node.js 22 or 24 executable")
    parser.add_argument("--npm", default="npm", help="npm executable for the configured Node.js")
    parser.add_argument("--askar-library-dir", type=Path, required=True, help="Verified native Askar library directory")
    parser.add_argument("--output", type=Path, required=True, help="New directory for public-key, reports and sanitized evidence")
    parser.add_argument("--previous-binary", type=Path, help="Installed rc11 CLI for the state recovery check")
    parser.add_argument("--candidate-binary", type=Path, help="Installed candidate CLI for the state recovery check")
    args = parser.parse_args()
    if bool(args.previous_binary) != bool(args.candidate_binary):
        parser.error("Provide both installed release CLIs for the state recovery check")
    for name in ("previous_binary", "candidate_binary"):
        binary = getattr(args, name)
        if binary is not None:
            if not binary.is_file() or not os.access(binary, os.X_OK):
                parser.error(f"--{name.replace('_', '-')} must point to an installed CLI")
            setattr(args, name, binary.absolute())
    for name in ("eudi_jar", "askar_library_dir", "output"):
        setattr(args, name, getattr(args, name).absolute())
    for name in ("java", "node", "npm"):
        executable = shutil.which(getattr(args, name))
        if executable is None:
            parser.error(f"--{name} does not point to an executable")
        setattr(args, name, str(Path(executable).resolve()))
    signal.signal(signal.SIGTERM, interrupted)
    run(args)


if __name__ == "__main__":
    main()
