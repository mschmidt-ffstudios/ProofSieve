#!/usr/bin/env python3
"""Loopback-only harness for the pinned upstream EUDI verifier in synthetic demos."""

import argparse
import base64
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import subprocess
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import pkcs12

JAR_SHA256 = "bd7c3748ac00eb872c6cb4bc0070c34992b96519ad4b9617fd4e383c6664ee34"
UPSTREAM_COMMIT = "fd46c1fdba404f44607591ac3574af9a6da222d8"
MAX_BODY = 512 * 1024
TX = r"[A-Za-z0-9_-]{16,128}"
WALLET_ROUTES = {
    "GET": [rf"/wallet/request[.]jwt/{TX}", r"/wallet/public-keys[.]json"],
    "POST": [rf"/wallet/direct_post/{TX}"],
}
PRIVATE_ROUTES = {
    "GET": [rf"/ui/presentations/{TX}"],
    "POST": [
        r"/ui/presentations/v2",
        r"/utilities/validations/sdJwtVc",
        r"/utilities/validations/msoMdoc/deviceResponse",
    ],
}


def b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def json_segment(value):
    return b64(json.dumps(value, separators=(",", ":")).encode("ascii"))


def verify_jar(jar):
    digest = hashlib.sha256()
    with jar.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != JAR_SHA256:
        raise ValueError("The upstream verifier JAR checksum does not match")


def configure(args):
    directory = args.directory.resolve()
    if directory.stat().st_mode & 0o077:
        raise ValueError("Synthetic config directory must be private")
    ca = x509.load_pem_x509_certificate((directory / "issuer-ca.pem").read_bytes())
    leaf = x509.load_pem_x509_certificate((directory / "verifier.pem").read_bytes())
    leaf.verify_directly_issued_by(ca)
    key = serialization.load_pem_private_key(
        (directory / "verifier-key.pem").read_bytes(), password=None
    )
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise ValueError("Synthetic reader must use ES256")
    if key.public_key() != leaf.public_key():
        raise ValueError("Synthetic reader key does not match its certificate")
    password = secrets.token_hex(24)
    keystore = directory / "eudi-access.p12"
    keystore.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b"test", key, leaf, [ca],
            serialization.BestAvailableEncryption(password.encode("ascii")),
        )
    )
    client_id = b64(leaf.fingerprint(hashes.SHA256()))
    wallet = f"https://127.0.0.1:{args.wallet_port}"
    private = f"https://127.0.0.1:{args.private_port}"
    claims = {
        "iss": "https://issuer.example.test",
        "sub": wallet,
        "exp": min(int(time.time()) + 86400, int(leaf.not_valid_after_utc.timestamp())),
    }
    if claims["exp"] <= time.time():
        raise ValueError("Synthetic reader certificate has expired")
    header = {
        "typ": "rc-wrp+jwt",
        "alg": "ES256",
        "x5c": [
            base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode("ascii")
            for c in (leaf, ca)
        ],
    }
    signing_input = json_segment(header) + "." + json_segment(claims)
    der_signature = key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_signature)
    registration = signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    settings = {
        "server.address": "127.0.0.1",
        "server.port": str(args.backend_port),
        "logging.level.root": "WARN",
        "logging.level.eu.europa.ec.eudi.verifier.endpoint": "OFF",
        "verifier.originalClientId": client_id,
        "verifier.clientIdPrefix": "x509_hash",
        "verifier.publicUrl": wallet,
        "verifier.access-certificate.keystore": keystore.as_uri(),
        "verifier.access-certificate.keystore.type": "PKCS12",
        "verifier.access-certificate.keystore.password": password,
        "verifier.access-certificate.alias": "test",
        "verifier.access-certificate.password": password,
        "verifier.access-certificate.signing-algorithm": "ES256",
        "verifier.intended-uses[0].id": "test-profile",
        "verifier.intended-uses[0].description": "Synthetic ProofSieve comparison",
        "verifier.intended-uses[0].registration-certificate": registration,
        "verifier.validation.statusCheck.enabled": "false",
        "verifier.attestation-classifications": json.dumps({
            "pid": {"vcts": ["urn:eudi:pid:1"], "docTypes": ["eu.europa.ec.eudi.pid.1"]},
            "qeaa": {"vcts": [], "docTypes": []},
            "pubeaa": {"vcts": [], "docTypes": []},
            "eaa": [],
        }),
    }
    options = directory / "eudi-application.properties"
    options.write_text(
        "\n".join(f"{key}={value}" for key, value in settings.items()) + "\n",
        encoding="ascii",
    )
    metadata = {
        "upstreamCommit": UPSTREAM_COMMIT,
        "jarSha256": JAR_SHA256,
        "publicOrigin": wallet,
        "privateOrigin": private,
        "clientId": f"x509_hash:{client_id}",
        "intendedUseId": "test-profile",
    }
    (directory / "eudi-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return options, metadata


class LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False

    def __init__(self, port, routes, backend_port, token, tls):
        self.routes = routes
        self.backend_port = backend_port
        self.expected_authorization = f"Bearer {token}" if token is not None else None
        self.tls = tls
        super().__init__(("127.0.0.1", port), Proxy)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return self.tls.wrap_socket(connection, server_side=True, do_handshake_on_connect=False), address


class Proxy(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.proxy()

    def do_POST(self):
        self.proxy()

    def proxy(self):
        self.close_connection = True
        if not any(re.fullmatch(route, self.path) for route in self.server.routes[self.command]):
            self.send_error(404)
            return
        expected = self.server.expected_authorization
        credentials = self.headers.get_all("Authorization") or []
        if expected is not None and (
            len(credentials) != 1 or not credentials[0].isascii()
            or not hmac.compare_digest(credentials[0], expected)
        ):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        lengths = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or len(lengths) > 1 or (
            lengths and not re.fullmatch(r"[0-9]{1,7}", lengths[0])
        ):
            self.send_error(400)
            return
        length = int(lengths[0]) if lengths else 0
        if length > MAX_BODY:
            self.send_error(413)
            return
        if length and self.command != "POST":
            self.send_error(400)
            return
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.backend_port, timeout=5
        )
        try:
            body = self.rfile.read(length) if length else None
            if length and len(body) != length:
                self.send_error(400)
                return
            headers = {
                key: self.headers[key]
                for key in ("Accept", "Content-Type")
                if self.headers.get(key)
            }
            connection.request(self.command, self.path, body=body, headers=headers)
            with connection.getresponse() as response:
                result = response.read(MAX_BODY + 1)
                if len(result) > MAX_BODY or 300 <= response.status < 400:
                    self.send_error(502)
                    return
                self.send_response(response.status)
                self.send_header("Content-Length", str(len(result)))
                self.send_header("Cache-Control", "no-store")
                for key in ("Content-Type", "Transaction-Id", "Authorization-Request-Uri"):
                    if response.getheader(key):
                        self.send_header(key, response.getheader(key))
                self.end_headers()
                self.wfile.write(result)
        except (ConnectionError, TimeoutError, ssl.SSLError):
            self.close_connection = True
        except (OSError, http.client.HTTPException):
            self.send_error(502)
        finally:
            connection.close()


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run(args):
    if len({args.backend_port, args.wallet_port, args.private_port}) != 3:
        raise ValueError("Each listener requires a different port")
    os.umask(0o077)
    verify_jar(args.jar)
    if args.bearer_file.stat().st_mode & 0o077:
        raise ValueError("Bearer file must be private")
    token = args.bearer_file.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        raise ValueError("Bearer must be a strong URL-safe token")
    options, metadata = configure(args)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(args.directory / "tls.pem", args.directory / "tls-key.pem")
    closing = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: closing.set())
    servers = []
    threads = []
    process = None
    try:
        servers.append(LocalHTTPServer(args.private_port, PRIVATE_ROUTES, args.backend_port, token, tls))
        servers.append(LocalHTTPServer(args.wallet_port, WALLET_ROUTES, args.backend_port, None, tls))
        with (args.directory / "eudi-upstream.log").open("ab") as log:
            process = subprocess.Popen(
                [args.java, "-Xms64m", "-Xmx512m", "-jar", str(args.jar.resolve()),
                 f"--spring.config.additional-location={options.as_uri()}"],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            )
        for _ in range(300):
            if closing.is_set() or process.poll() is not None:
                raise RuntimeError("Upstream verifier stopped before it could bind")
            try:
                with socket.create_connection(("127.0.0.1", args.backend_port), timeout=0.2):
                    break
            except ConnectionRefusedError:
                closing.wait(0.1)
        else:
            raise RuntimeError("Upstream verifier never bound to loopback")
        for server in servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        print(json.dumps(metadata), flush=True)
        while process.poll() is None and not closing.wait(0.5):
            pass
        if not closing.is_set():
            raise RuntimeError("Upstream verifier stopped unexpectedly")
    finally:
        for server in servers[:len(threads)]:
            server.shutdown()
        for server in servers:
            server.server_close()
        if process is not None:
            stop(process)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--directory", type=Path, required=True)
    cli.add_argument("--jar", type=Path, required=True)
    cli.add_argument("--java", default="java")
    cli.add_argument("--private-port", type=int, required=True)
    cli.add_argument("--wallet-port", type=int, required=True)
    cli.add_argument("--backend-port", type=int, required=True)
    cli.add_argument("--bearer-file", type=Path, required=True)
    run(cli.parse_args())
