"""Run the ProofSieve verification workflow test layers from one checkout."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
BROWSER_TESTS = (
    "workspace_browser",
    "guard_browser",
    "guard_editor_browser",
    "operator_workflow_browser",
    "verifier_handoff_browser",
    "api_docs_browser",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keycloak-home", type=Path, help="Extracted Keycloak distribution")
    parser.add_argument("--java-home", type=Path, help="JDK home for Keycloak and DSS")
    parser.add_argument("--supplier-report", type=Path, help="New JSON path for the supplier HTTPS report")
    parser.add_argument("--report", type=Path, help="New JSON path for the test layer outcomes")
    args = parser.parse_args()
    if bool(args.keycloak_home) != bool(args.java_home):
        parser.error("--keycloak-home and --java-home must be supplied together")
    if args.supplier_report and not args.keycloak_home:
        parser.error("--supplier-report requires the Keycloak and Java homes")
    if args.report and (args.report.exists() or (
        args.supplier_report and args.report.resolve() == args.supplier_report.resolve()
    )):
        parser.error("--report must be a new path separate from --supplier-report")

    layers = [
        ("Python unit and HTTP", ["-m", "unittest", "discover", "-s", "tests", "-v"]),
        ("Company HTTP", ["examples/company/run.py"]),
        *((f"Chromium {module}", ["-m", f"tests.{module}"]) for module in BROWSER_TESTS),
    ]
    if args.keycloak_home:
        supplier = [
            "examples/acceptance/run.py", "--keycloak-home", str(args.keycloak_home.resolve()),
            "--keycloak-java-home", str(args.java_home.resolve()),
        ]
        if args.supplier_report:
            supplier += ["--report", str(args.supplier_report.resolve())]
        layers.extend((
            ("Keycloak, DSS and OCSP over HTTPS", supplier),
            ("Extended document signatures", [
                "examples/acceptance/dss/extended.py", "--java-home", str(args.java_home.resolve()),
            ]),
        ))

    results = {name: {"status": "not-run", "exitCode": None} for name, _ in layers}
    if not args.keycloak_home:
        for name in ("Keycloak, DSS and OCSP over HTTPS", "Extended document signatures"):
            results[name] = {"status": "skip", "exitCode": None}

    try:
        for name, command in layers:
            print(f"\n=== {name} ===", flush=True)
            code = subprocess.run([sys.executable, *command], cwd=ROOT, check=False).returncode
            results[name] = {"status": "pass" if code == 0 else "fail", "exitCode": code}
    finally:
        failed = any(layer["status"] not in {"pass", "skip"} for layer in results.values())
        if args.report:
            with args.report.open("x", encoding="utf-8") as report:
                json.dump({"version": 1, "status": "fail" if failed else "pass", "layers": results},
                          report, indent=2)
                report.write("\n")

    print("\nTest set results")
    for name, result in results.items():
        print(f"{result['status'].upper()} {name}")
    print("Wallet deployment comparison runs separately via run_wallet_comparison.py.")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
