"""Check release contents and smoke-test the installed CLI outside the checkout."""

import json
import os
import re
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from importlib.metadata import version as installed_version
from urllib.request import Request, urlopen

from packaging.version import Version


def check_archive(path, names):
    for name in names:
        for part in PurePosixPath(name).parts:
            if part in {"internal", "instance", ".git", ".."} or part == ".env" or part.startswith(".env."):
                raise AssertionError(f"Unexpected private path in {path.name}: {name}")


def check_distributions(wheel_path, source_path):
    with zipfile.ZipFile(wheel_path) as wheel:
        paths = wheel.namelist()
        check_archive(wheel_path, paths)
        assert "proofsieve/assets/openapi.json" in paths
        assert "proofsieve/assets/examples/signed/guard.json" in paths
        for asset in ("index.html", "api-docs.js", "swagger-language.js",
                      "vendor/swagger-ui-bundle.js", "vendor/swagger-ui.css"):
            assert f"proofsieve/assets/apps/api-docs/{asset}" in paths
        for license_path in ("LICENSE", "NOTICE", "examples/signed/LICENSE-EUDI-OPENID4VP.txt",
                             "examples/signed/LICENSE-RFC9901.txt", "apps/api-docs/vendor/LICENSE",
                             "apps/api-docs/vendor/swagger-ui-bundle.js.LICENSE.txt",
                             "apps/api-docs/vendor/THIRD-PARTY.LICENSE.txt"):
            assert any(path.endswith(f"/licenses/{license_path}") for path in paths), license_path
    with tarfile.open(source_path, "r:gz") as source:
        paths = source.getnames()
        check_archive(source_path, paths)
        assert any(path.endswith("/requirements.txt") for path in paths)
        assert any(path.endswith("/examples/company/run.py") for path in paths)
        for entry in ("docs/diagrams/keycloak-verification-flow.puml", "docs/MANUAL.md",
                      "deploy/README.md", "deploy/proofsieve.service", "deploy/nginx.conf.example",
                      "deploy/service.env.example", "deploy/access.json.example"):
            assert any(path.endswith(f"/{entry}") for path in paths), entry
        for acceptance_path in (
            "dss/pom.xml", "run_testset.py", "run_wallet_release.py",
            "run_wallet_comparison.py", "wallet_cases.py", "eudi_runtime.py", "upgrade_rollback.py",
        ):
            assert any(path.endswith(f"/examples/acceptance/{acceptance_path}") for path in paths), acceptance_path
        assert all("/release-artifacts/" not in path for path in paths)
        assert any(path.endswith("/apps/api-docs/vendor/NOTICE") for path in paths)
        assert all("/target/" not in path for path in paths)


def request(url, *, method=None, data=None, headers=None):
    body = json.dumps(data).encode("utf-8") if data is not None else None
    options = {"Content-Type": "application/json", **(headers or {})}
    with urlopen(Request(url, data=body, method=method, headers=options), timeout=5) as response:
        return response.read()


def find_url(process, log_path):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        output = log_path.read_text(encoding="utf-8")
        match = re.search(r"http://127\.0\.0\.1:\d+", output)
        if match:
            return match.group()
        if process.poll() is not None:
            raise AssertionError(f"Installed CLI exited before startup:\n{output}")
        time.sleep(0.05)
    raise AssertionError(f"Installed CLI did not start:\n{output}")


def check_cli():
    suffix = ".exe" if os.name == "nt" else ""
    launcher = Path(sysconfig.get_path("scripts")) / f"proofsieve{suffix}"
    with tempfile.TemporaryDirectory() as work:
        directory = Path(work)
        log_path = directory / "server.log"
        state = directory / "state"
        environment = {**os.environ, "XDG_STATE_HOME": str(state)}
        environment.pop("PYTHONPATH", None)
        version = subprocess.check_output([str(launcher), "--version"], cwd=directory,
                                          env=environment, text=True, timeout=5).strip()
        assert not state.exists()
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [str(launcher), "--port", "0"], cwd=directory, env=environment, stdout=log, stderr=subprocess.STDOUT,
            )
        try:
            base = find_url(process, log_path)
            for route, marker in {
                "/apps/": b"ProofSieve",
                "/apps/guard/": b"guard.js",
                "/apps/builder/": b"builder.js",
                "/apps/lab/": b"app.js",
                "/apps/guard/rule-tester.js": b"createRuleTester",
                "/apps/api-docs/": b"Swagger UI",
                "/apps/api-docs/swagger-language.js": b"localizeSwagger",
                "/apps/api-docs/vendor/swagger-ui-bundle.js": b"SwaggerUIBundle",
                "/examples/01-two-of-three.json": b"two-of-three",
                "/examples/credentials.json": b"eudi-pid-sd-jwt",
                "/openapi.json": b"/verify/demo/eudi-mdoc",
            }.items():
                assert marker in request(base + route), route
            api_version = json.loads(request(base + "/openapi.json"))["info"]["version"]
            assert version == "ProofSieve " + api_version
            assert Version(installed_version("proofsieve")) == Version(api_version)
            assert json.loads(request(base + "/verify", data={"data": {"status": "active"}})) is True
            config = json.loads(request(base + "/admin/rule"))
            request(base + "/admin/rule", method="PUT", data=config["rule"],
                    headers={"X-ProofSieve-Token": config["csrfToken"]})
            assert (state / "proofsieve" / "rule.json").is_file()
            assert not (directory / "instance").exists()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    check_distributions(Path(sys.argv[1]), Path(sys.argv[2]))
    check_cli()
    print("Public wheel and source archive checked. Installed CLI serves assets and writes user state.")
