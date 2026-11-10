"""Exercise the packaged Guard through the published Nginx configuration."""

import argparse
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode

from proofsieve.evidence import verify_evidence_export
from proofsieve.guard import DEFAULT_RULE


DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
ENDPOINT = "/verify/deploy-smoke"
SIGNED_DEMO = "/verify/demo/eudi-sd-jwt"
OPERATOR_HOST = "127.0.0.1:24180"


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path, host):
        super().__init__(host, timeout=5)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(os.fspath(self.path))


def request(connection, method, path, *, token=None, data=None, host=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if host:
        headers["Host"] = host
    body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")
    try:
        connection.request(method, path, body=body, headers=headers)
        with connection.getresponse() as response:
            return response.status, response.read()
    finally:
        connection.close()


def checked(connection, method, path, status, **options):
    actual, body = request(connection, method, path, **options)
    if actual != status:
        raise RuntimeError(f"{method} {path} returned HTTP {actual}, expected {status}")
    return body


@contextmanager
def service(command, work, name):
    logfile = work / f"{name}.log"
    environment = {**os.environ, "PYTHONNOUSERSITE": "1"}
    environment.pop("PYTHONPATH", None)
    with logfile.open("wb") as log:
        process = subprocess.Popen(command, cwd=work, env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            yield process
        except Exception:
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited with status {process.returncode}: {logfile.read_text()}") from None
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def wait_for(connection, process):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The listener exited during startup")
        try:
            if request(connection(), "GET", "/openapi.json")[0] == 401:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    raise RuntimeError("Timed out waiting for the protected listener")


def configure(work, nginx):
    cert, key = work / "tls.pem", work / "tls.key"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"localhost:{port}"
    admin, ingress = work / "admin", work / "ingress"
    admin.mkdir(mode=0o700)
    ingress.mkdir(mode=0o710)
    ingress.chmod(0o710)
    api_socket = ingress / "api.sock"
    config = (DEPLOY / "nginx.conf.example").read_text(encoding="utf-8")
    for original, replacement in (
        ("listen 443 ssl;", f"listen 127.0.0.1:{port} ssl;"),
        ("server_name proofsieve-api.example.test;", "server_name localhost;"),
        ("$host != proofsieve-api.example.test", "$host != localhost"),
        ("proxy_set_header Host proofsieve-api.example.test;", f"proxy_set_header Host {origin};"),
        ("/run/proofsieve-ingress/api.sock", str(api_socket)),
        ("/etc/proofsieve/tls/fullchain.pem", str(cert)),
        ("/etc/proofsieve/tls/privkey.pem", str(key)),
        ("192.0.2.0/24", "127.0.0.1/32"),
    ):
        if original not in config:
            raise RuntimeError(f"The deploy template is missing {original}")
        config = config.replace(original, replacement)
    temp_paths = ""
    for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        directory = work / f"{kind}_temp"
        directory.mkdir(mode=0o700)
        temp_paths += f"    {kind}_temp_path {directory};\n"
    rendered = work / "nginx.conf"
    rendered.write_text(
        f"daemon off;\nmaster_process off;\npid {work}/nginx.pid;\nerror_log stderr;\n"
        f"events {{}}\nhttp {{\n{temp_paths}{config}\n}}\n", encoding="utf-8",
    )
    nginx_command = [str(nginx), "-p", f"{work}/", "-c", str(rendered)]
    subprocess.run([*nginx_command, "-t"], check=True, capture_output=True)
    tls = ssl.create_default_context(cafile=str(cert))
    return origin, admin / "guard.sock", api_socket, nginx_command, tls


def verify_installed(work, proofsieve, nginx):
    origin, admin_socket, api_socket, nginx_command, tls = configure(work, nginx)
    identities = {
        "operator": ("admin", ["*"]),
        "verifier": ("verifier", [ENDPOINT]),
        "other": ("verifier", ["/verify"]),
    }
    tokens = {identity: secrets.token_urlsafe(32) for identity in identities}
    auth_file, rule_file = work / "access.json", work / "rules.json"
    auth_file.write_text(json.dumps({"version": 1, "principals": [
        {"id": identity, "role": role, "endpoints": endpoints,
         "tokenSha256": hashlib.sha256(tokens[identity].encode("ascii")).hexdigest()}
        for identity, (role, endpoints) in identities.items()
    ]}), encoding="utf-8")
    auth_file.chmod(0o600)
    rule_file.write_text(json.dumps({"version": 1, "rules": {
        "/verify": DEFAULT_RULE, ENDPOINT: {**DEFAULT_RULE, "responseMode": "decision"},
    }}), encoding="utf-8")
    version_line = subprocess.check_output([str(proofsieve), "--version"], cwd=work, text=True, timeout=10).strip()
    if not version_line.startswith("ProofSieve "):
        raise RuntimeError("The installed CLI did not report a ProofSieve release")
    version = version_line.removeprefix("ProofSieve ")
    guard_command = [str(proofsieve), "--port", "24180", "--socket", str(admin_socket),
                     "--proxy-socket", str(api_socket), "--proxy-origin", f"https://{origin}",
                     "--proxy-gid", str(api_socket.parent.stat().st_gid), "--auth-config", str(auth_file),
                     "--state", str(rule_file), "--evidence", str(work / "evidence.sqlite3"), "--evidence-export"]

    def https():
        return http.client.HTTPSConnection(origin, context=tls, timeout=5)

    def operator():
        return UnixConnection(admin_socket, OPERATOR_HOST)

    admin, verifier, other = (tokens[identity] for identity in identities)
    approval = {"operationId": "deploy-smoke-allowed", "data": {"status": "active"}}
    refusal = {"operationId": "deploy-smoke-denied", "data": {"status": "blocked"}}
    with service(nginx_command, work, "nginx") as proxy:
        with service(guard_command, work, "guard") as guard:
            wait_for(operator, guard)
            wait_for(https, proxy)
            if (stat.S_IMODE(admin_socket.stat().st_mode), stat.S_IMODE(api_socket.stat().st_mode)) != (0o600, 0o660):
                raise RuntimeError("The installed runtime did not separate socket permissions")
            spec = json.loads(checked(https(), "GET", "/openapi.json", 200, token=verifier))
            if spec["info"]["version"] != version or set(spec["paths"]) != {ENDPOINT}:
                raise RuntimeError("HTTPS returned a different release or unexpected endpoint grants")
            checked(https(), "GET", "/openapi.json", 421, token=verifier, host="another.example.test")
            checked(https(), "POST", ENDPOINT, 401, data=approval)
            checked(https(), "POST", ENDPOINT, 403, token=other, data=approval)
            allowed = json.loads(checked(https(), "POST", ENDPOINT, 200, token=verifier, data=approval))
            denied = json.loads(checked(https(), "POST", ENDPOINT, 200, token=verifier, data=refusal))
            if (allowed["outcome"], denied["outcome"]) != ("allow", "deny"):
                raise RuntimeError("The installed rule returned unexpected outcomes")
            checked(https(), "POST", f"{ENDPOINT}?unexpected=1", 400, token=verifier, data=approval)
            checked(https(), "POST", ENDPOINT, 413, token=verifier, data={"data": "x" * (96 * 1024)})
            checked(https(), "POST", SIGNED_DEMO, 403, token=admin, data=approval)
            for path in ("/apps/guard/", "/apps/api-docs/", "/admin/rule", "/auth/me", "/evidence"):
                checked(https(), "GET", path, 404, token=admin)
                checked(UnixConnection(api_socket, origin), "GET", path, 403, token=admin)
            checked(operator(), "GET", "/apps/guard/", 200)
            checked(operator(), "GET", "/apps/api-docs/", 200)
            checked(operator(), "GET", "/admin/rule", 200, token=admin)
            checked(operator(), "GET", "/admin/rule", 403, token=verifier)
            evidence_path = "/evidence?" + urlencode({"endpoint": ENDPOINT, "operationId": approval["operationId"],
                                                     "decisionId": allowed["decisionId"]})
            evidence = json.loads(checked(operator(), "GET", evidence_path, 200, token=verifier))
            pin = evidence["integrity"]["publicKey"]
            if not verify_evidence_export(evidence, public_key=pin):
                raise RuntimeError("The installed runtime did not export a valid evidence signature")
        # systemd removes RuntimeDirectory contents when a stopped service is restarted.
        admin_socket.unlink(missing_ok=True)
        api_socket.unlink(missing_ok=True)
        with service(guard_command, work, "guard-restarted") as guard:
            wait_for(operator, guard)
            retained = json.loads(checked(operator(), "GET", evidence_path, 200, token=verifier))
            if retained["decisions"] != evidence["decisions"] or not verify_evidence_export(retained, public_key=pin):
                raise RuntimeError("Restart changed the decision or its evidence signing identity")
            checked(https(), "GET", "/openapi.json", 200, token=verifier)
    return {"status": "pass", "apiVersion": version, "platform": os.uname().sysname,
            "checks": ["trusted-nginx-https", "scoped-openapi", "allow-and-deny", "api-operator-isolation",
                       "signed-evidence-after-process-restart"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proofsieve", type=Path, required=True, help="Installed CLI outside the source checkout")
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    binary = args.proofsieve.resolve(strict=True)
    if binary.is_relative_to(DEPLOY.parent):
        parser.error("Install the release into a virtual environment outside the checkout")
    with tempfile.TemporaryDirectory(prefix="ps-deploy-", dir="/tmp") as directory:
        report = verify_installed(Path(directory).resolve(), binary, args.nginx.resolve(strict=True))
    output = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
