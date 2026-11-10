"""Run isolated acceptance dependencies and make loopback requests."""

import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import time
import uuid
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.x509 import ocsp

from pki import ocsp_response


REALM = "proofsieve-acceptance"
AUDIENCE = "proofsieve-api"
VERIFIER = "supplier-portal"
NO_GRANT = "other-service"
WRONG_AUDIENCE = "wrong-audience"
EXPIRING = "expiring-service"
SUPPLIER_ROLE = "verify-supplier-orders"


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(url, method="GET", body=None, headers=None, context=None):
    req = Request(url, data=body, headers=headers or {}, method=method)
    try:
        response = urlopen(req, context=context, timeout=8)
    except HTTPError as error:
        response = error
    with response:
        return response.status, response.read(256 * 1024)


def wait_http(url, expected, process=None, context=None, *, startup_timeout=45):
    deadline = time.monotonic() + startup_timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{process.args[0]} exited during startup with status {process.returncode}")
        try:
            status, _ = request(url, context=context)
            if status == expected:
                return
        except (OSError, URLError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Service readiness timed out at {url}")


@contextmanager
def service(command, logfile, *, env=None, cwd=None):
    with logfile.open("wb") as output:
        process = subprocess.Popen(
            command, stdout=output, stderr=subprocess.STDOUT, cwd=cwd,
            env=env, start_new_session=True,
        )
        try:
            yield process
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()


def secure_json(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        json.dump(value, output)


def realm_config(roles):
    credentials = {}
    client_roles = {AUDIENCE: [{"name": role} for role in roles]}
    clients = [{
        "clientId": AUDIENCE, "enabled": True, "protocol": "openid-connect",
        "publicClient": False, "bearerOnly": True, "standardFlowEnabled": False,
    }]
    users = []
    scope_mappings = []
    for name in (VERIFIER, NO_GRANT, WRONG_AUDIENCE, EXPIRING):
        subject = str(uuid.uuid4())
        secret = secrets.token_urlsafe(32)
        credentials[name] = (subject, secret)
        audience = "another-api" if name == WRONG_AUDIENCE else AUDIENCE
        assigned = {VERIFIER: list(roles), EXPIRING: [SUPPLIER_ROLE]}.get(name)
        clients.append({
            "clientId": name, "enabled": True, "protocol": "openid-connect",
            "secret": secret, "publicClient": False, "serviceAccountsEnabled": True,
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            **({"attributes": {"access.token.lifespan": "1"}} if name == EXPIRING else {}),
            "protocolMappers": [{
                "name": "acceptance-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": audience, "access.token.claim": "true"},
            }],
        })
        user = {
            "id": subject, "username": f"service-account-{name}", "enabled": True,
            "serviceAccountClientId": name,
        }
        if assigned:
            user["clientRoles"] = {AUDIENCE: assigned}
            scope_mappings.append({"client": name, "roles": assigned})
        users.append(user)
    realm = {
        "realm": REALM, "enabled": True, "sslRequired": "all", "roles": {"client": client_roles},
        "clients": clients, "users": users, "accessTokenLifespan": 300,
        "clientScopeMappings": {AUDIENCE: scope_mappings},
    }
    return realm, credentials


@contextmanager
def keycloak(distribution: Path, java_home: Path, directory: Path, certificate, key, context, roles):
    extracted = directory / "keycloak"
    shutil.copytree(distribution, extracted, ignore=shutil.ignore_patterns("data"))
    imports = extracted / "data" / "import"
    imports.mkdir(mode=0o700, parents=True)
    realm, credentials = realm_config(roles)
    secure_json(imports / f"{REALM}-realm.json", realm)
    port = available_port()
    issuer = f"https://127.0.0.1:{port}/realms/{REALM}"
    command = [
        str(extracted / "bin" / "kc.sh"), "start", "--import-realm", "--db=dev-mem", "--cache=local",
        "--http-host=127.0.0.1", "--http-enabled=false", f"--https-port={port}",
        f"--hostname=https://127.0.0.1:{port}", "--tracing-enabled=false",
        f"--https-certificate-file={certificate}", f"--https-certificate-key-file={key}",
    ]
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("KC_", "KCK_", "JAVA_OPTS"))
        and key not in {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"}
    }
    env["JAVA_HOME"] = str(java_home)
    version_output = subprocess.check_output(
        [command[0], "--version"], env=env, text=True, timeout=20,
    )
    version = next(line.split()[1] for line in version_output.splitlines() if line.startswith("Keycloak "))
    with service(command, directory / "keycloak.log", env=env) as process:
        # The isolated Keycloak copy can need cold Quarkus augmentation before binding.
        wait_http(f"{issuer}/.well-known/openid-configuration", 200, process, context, startup_timeout=120)
        yield issuer, credentials, version


def access_token(issuer, client, secret, context):
    body = urlencode({
        "grant_type": "client_credentials", "client_id": client, "client_secret": secret,
    }).encode("ascii")
    status, data = request(
        f"{issuer}/protocol/openid-connect/token", "POST", body,
        {"Content-Type": "application/x-www-form-urlencoded"}, context,
    )
    if status != 200:
        raise RuntimeError(f"Keycloak refused client {client} with HTTP {status}")
    return json.loads(data)["access_token"]


def unix_request(socket_path, host, path, method="GET", body=None, headers=None):
    class Connection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.settimeout(self.timeout)
            self.sock.connect(str(socket_path))

    with closing(Connection(host, timeout=8)) as connection:
        connection.request(method, path, body=body, headers={"Host": host, **(headers or {})})
        with connection.getresponse() as response:
            return response.status, response.read(256 * 1024), response.getheader("Content-Type")


@contextmanager
def https_proxy(certificate, key, api_socket):
    """TLS topology fixture that forwards only the externally exposed Guard API."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path != "/openapi.json":
                self.send_error(404)
                return
            self.forward()

        def do_POST(self):
            if self.path != "/verify" and not self.path.startswith("/verify/"):
                self.send_error(404)
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                self.send_error(400)
                return
            size = int(lengths[0])
            if not 0 < size <= 96 * 1024 or self.headers.get("Transfer-Encoding") is not None:
                self.send_error(400)
                return
            self.forward(self.rfile.read(size))

        def forward(self, body=None):
            host = f"127.0.0.1:{self.server.server_port}"
            if self.headers.get_all("Host") != [host]:
                self.send_error(400)
                return
            headers = {}
            for name in ("Authorization", "Content-Type"):
                values = self.headers.get_all(name, [])
                if len(values) > 1:
                    self.send_error(400)
                    return
                if values:
                    headers[name] = values[0]
            try:
                status, result, content_type = unix_request(
                    api_socket, host, self.path, self.command, body, headers,
                )
            except (OSError, http.client.HTTPException):
                self.send_error(502)
                return
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"https://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join(timeout=5)


@contextmanager
def ocsp_responder(certificate, key, issuer, identities):
    """A bounded loopback responder that signs each requested certificate status."""
    config = {"status": ocsp.OCSPCertStatus.GOOD, "options": {}}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            if self.path != "/ocsp" or self.headers.get("Content-Type") != "application/ocsp-request":
                self.send_error(404)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    raise ValueError("Invalid OCSP request size")
                query = self.rfile.read(size)
                serial = ocsp.load_der_ocsp_request(query).serial_number
                response = ocsp_response(query, identities[serial], issuer, config["status"], **config["options"])
            except (KeyError, ValueError):
                self.send_error(400)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"https://127.0.0.1:{server.server_port}/ocsp", config
        finally:
            server.shutdown()
            thread.join(timeout=5)
