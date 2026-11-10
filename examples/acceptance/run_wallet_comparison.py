"""Compare Credo and EUDI Reference wallet cases in the live Guard and Swagger UI."""

import argparse
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import Error, expect, sync_playwright

from wallet_cases import (
    CREDO_ADVISORY_CASES, MAX_RESPONSE, SURNAME, SyntheticCredential, WalletTarget,
    json_bytes, origin, present, request, require,
)


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from proofsieve.evidence import verify_evidence_export


ADAPTERS = {"credo": "credo", "eudi-reference": "eudi"}
FORMATS = {"dc+sd-jwt": "sd-jwt", "mso_mdoc": "mdoc"}
CASES = ("valid", "policy-denied", "wrong-nonce")


def endpoint_for(prefix, adapter, format_name):
    return f"{prefix}/{ADAPTERS[adapter]}-{FORMATS[format_name]}"


def read_token(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
            "Verifier token must be an owner-only regular file")
    token = path.read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[A-Za-z0-9_-]{43}", token), "Invalid verifier token")
    return token


def guard_control(page, name):
    return page.locator(f'[data-access="{name}"]')


def assert_secret_absent(page, token):
    require(token not in page.locator("body").inner_text(), "Token appeared in browser text")
    storage = page.evaluate("JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])")
    require(token not in storage, "Token appeared in browser storage")


def sign_in_guard(page, base, token, endpoints):
    page.goto(base + "/apps/guard/")
    token_input = guard_control(page, "token")
    expect(token_input).to_be_visible()
    token_input.fill(token)
    with page.expect_response(lambda response: response.url == base + "/auth/me") as auth, \
            page.expect_response(lambda response: response.url == base + "/openapi.json") as schema:
        guard_control(page, "login-button").click()
    require(auth.value.status == 200 and schema.value.status == 200, "Verifier session could not start")
    account, api = auth.value.json(), schema.value.json()
    require(account["role"] == "verifier" and endpoints == set(account["endpoints"])
            and "*" not in account["endpoints"] and set(api["paths"]) == set(account["endpoints"]) | {"/evidence"},
            "Verifier role or scoped paths were unexpected")
    for endpoint in endpoints:
        require(api["paths"][endpoint]["post"]["x-proofsieve-input"] == "wallet", "Expected a wallet endpoint")
    expect(token_input).to_have_value("")
    require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", account["id"])
            and token not in account["id"]
            and re.fullmatch(r"[0-9][A-Za-z0-9_.+-]{0,39}", api["info"]["version"]),
            "Invalid browser report metadata")
    return account["id"], api["info"]["version"]


def guard_submit(page, base, endpoint, token, data, operation_id, expected_status):
    require(json.loads(guard_control(page, "input").input_value()) == data,
            "Guard did not prepare the expected wallet action")
    with page.expect_response(lambda response: response.url == base + endpoint
                              and response.request.method == "POST") as check:
        guard_control(page, "verify").click()
    response = check.value
    require(response.request.post_data_json == {"data": data, "operationId": operation_id}
            and response.request.all_headers().get("authorization") == "Bearer " + token,
            "Guard changed the wallet payload or verifier scope")
    require(response.status == expected_status, f"Guard returned HTTP {response.status}; expected {expected_status}")
    result = response.json()
    expect(guard_control(page, "http-status")).to_have_text(f"HTTP {expected_status}")
    require(json.loads(guard_control(page, "response").inner_text()) == result, "Guard displayed a different response")
    return result


def wallet_case(page, args, token, target, endpoint, credential, case, operation_id, label, nonces):
    guard_control(page, "endpoint").select_option(endpoint)
    expect(guard_control(page, "format")).to_have_value(re.compile(r"Wallet[- ][Ss]itzung|Wallet session"))
    guard_control(page, "operation").fill(operation_id)
    started = guard_submit(page, args.guard, endpoint, token, {"action": "start"}, operation_id, 201)
    complete = {"action": "complete", "sessionId": started["sessionId"]}
    guard_submit(page, args.guard, endpoint, token, complete, operation_id, 202)
    check_envelope = args.check_credo_envelope and target.adapter == "credo" and case == "valid"
    advisory_case = case if case in CREDO_ADVISORY_CASES else None
    wallet_http = present(target, started["authorizationRequestUri"], credential,
                          wrong_nonce=case == "wrong-nonce", observed_nonces=nonces,
                          check_credo_envelope=check_envelope, credo_advisory_case=advisory_case)
    rejected = case == "wrong-nonce" or advisory_case is not None
    require(wallet_http == (400 if rejected else 200), "Unexpected wallet HTTP status")
    # The reference verifier does not publish a terminal result on wrong nonce.
    if case == "wrong-nonce" and target.adapter == "eudi-reference":
        expected_status, outcome, reason = 202, "pending", "wallet_post_rejected"
    elif rejected:
        expected_status, outcome, reason = 403, "deny", "wallet_rejected"
    elif case == "policy-denied":
        expected_status, outcome, reason = 403, "deny", "policy_denied"
    else:
        expected_status, outcome, reason = 200, "allow", "policy_allowed"
    result = guard_submit(page, args.guard, endpoint, token, complete, operation_id, expected_status)
    require(result["operationId"] == operation_id, "Guard changed the operation reference")
    if outcome == "pending":
        require(result == {"operationId": operation_id, "state": "pending"},
                "Expected no terminal decision after the rejected wallet POST")
    else:
        require(result.keys() == {"decisionId", "operationId", "outcome", "reason", "ruleVersion", "valid"}
                and result["outcome"] == outcome and result["reason"] == reason and result["valid"] is (outcome == "allow")
                and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", result["decisionId"])
                and re.fullmatch(r"[0-9a-f]{64}", result["ruleVersion"]),
                "Guard did not record the expected wallet decision")
    replay = {}
    if advisory_case is not None:
        replay_status, replay_body = request(
            args.guard + endpoint, origin(args.guard),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            body=json_bytes({"data": complete, "operationId": operation_id}),
        )
        require(replay_status == 409 and json.loads(replay_body).get("code") == "wallet_session_conflict",
                "Guard accepted a replayed advisory-case completion")
        replay = {"guardReplayHttp": replay_status, "walletCallbackReplay": "refused"}
    assert_secret_absent(page, token)
    screenshot = f"guard-{label}.png"
    capture = page.screenshot(full_page=True, mask=[guard_control(page, "input")], mask_color="#e6edf5")
    return {
        "walletHttp": wallet_http,
        **({"malformedEnvelopeRecovery": "passed"} if check_envelope else {}),
        **replay,
        "guardHttp": expected_status,
        "guardScreenshot": screenshot,
        "operationId": operation_id,
        "outcome": outcome,
        "reason": reason,
        "decisionId": result.get("decisionId"),
        "ruleVersion": result.get("ruleVersion"),
    }, {screenshot: capture}


def open_swagger(page, base, token):
    page.goto(base + "/apps/api-docs/")
    token_input = page.locator("#api-token")
    expect(token_input).to_be_visible()
    token_input.fill(token)
    token_input.press("Enter")
    operation = page.locator(".opblock-get").filter(has_text="/evidence")
    expect(operation.locator(".opblock-summary-path")).to_have_text("/evidence")
    expect(token_input).to_have_value("")
    operation.locator(".opblock-summary-control").click()
    operation.locator("button.try-out__btn").click()
    return operation


def swagger_case(page, swagger, args, token, pin, caller, endpoint, adapter, format_name, decision, label, *,
                 whole_operation=False):
    query = {"endpoint": endpoint, "operationId": decision["operationId"]}
    if decision["decisionId"] is not None and not whole_operation:
        query["decisionId"] = decision["decisionId"]
    for key in ("endpoint", "operationId", "decisionId"):
        swagger.locator(f'[data-param-name="{key}"] input').fill(query.get(key, ""))
    with page.expect_response(lambda response: response.url.startswith(args.guard + "/evidence?")
                              and response.request.method == "GET") as check:
        swagger.locator("button.execute").click()
    response = check.value
    expected_status = 404 if decision["outcome"] == "pending" else 200
    require(response.status == expected_status and parse_qs(urlsplit(response.url).query, strict_parsing=True)
            == {key: [value] for key, value in query.items()}
            and response.request.all_headers().get("authorization") == "Bearer " + token,
            "Swagger requested a different evidence scope")
    export = response.json()
    rendered = swagger.locator(".live-responses-table .highlight-code pre")
    expect(rendered).to_contain_text(decision["decisionId"] or "evidence_not_found")
    require(json.loads(rendered.inner_text()) == export, "Swagger displayed a different response")
    assert_secret_absent(page, token)
    screenshot = f"swagger-{label}.png"
    confidential = (token, "family_name", SURNAME, "Anders", "sessionId", "authorizationRequestUri")
    require(not any(field in rendered.inner_text() for field in confidential),
            "Swagger response contained confidential fixture material")
    if expected_status == 404:
        require(export.get("code") == "evidence_not_found", "Expected evidence to be absent for a pending session")
        capture = swagger.locator(".live-responses-table").screenshot(
            style=".highlight-code pre { max-height: none !important; }",
        )
        return {"swaggerHttp": 404, "swaggerScreenshot": screenshot, "evidence": None, "signatureVerified": False}, {
            screenshot: capture,
        }
    require(export["scope"] == {"caller": caller, "endpoint": endpoint, "operationId": decision["operationId"]},
            "Evidence scope changed")
    [record] = export["decisions"]
    [source] = record["checks"]
    require(all(record[field] == decision[field] for field in ("decisionId", "outcome", "reason", "ruleVersion"))
            and source["adapter"] == adapter and source["format"] == format_name
            and source["kind"] == "wallet_presentation"
            and source["outcome"] == ("failed" if decision["reason"] == "wallet_rejected" else "passed"),
            "Evidence provenance was not the Wallet decision")
    with page.expect_download() as download:
        swagger.locator(".live-responses-table button.download-contents").click()
    artifact = f"evidence-{label}.json"
    with Path(download.value.path()).open("rb") as downloaded_file:
        data = downloaded_file.read(MAX_RESPONSE + 1)
    require(len(data) <= MAX_RESPONSE, "Downloaded export exceeded the acceptance limit")
    downloaded = json.loads(data)
    require(not any(field.encode("ascii") in data for field in confidential) and downloaded == export
            and verify_evidence_export(downloaded, public_key=pin),
            "Downloaded export leaked the token, changed the decision or failed its pinned signature")
    downloaded["decisions"][0]["outcome"] = "deny" if decision["outcome"] == "allow" else "allow"
    require(not verify_evidence_export(downloaded, public_key=pin), "Changed decision passed signature verification")
    capture = swagger.locator(".live-responses-table").screenshot(
        style=".highlight-code pre { max-height: none !important; }",
    )
    return {
        "swaggerHttp": 200,
        "swaggerScreenshot": screenshot,
        "evidence": artifact,
        "signatureVerified": True,
        "walletCheckOutcome": source["outcome"],
    }, {artifact: data, screenshot: capture}


def publish_case(directory, artifacts):
    try:
        for name, contents in artifacts.items():
            (directory / name).write_bytes(contents)
    except OSError:
        for name in artifacts:
            (directory / name).unlink(missing_ok=True)
        raise


def run(args):
    os.umask(0o077)
    args.output.mkdir(mode=0o700, exist_ok=False)
    nonces = set()
    advisory_nonces = set()
    report = {"status": "fail", "expectedCases": len(ADAPTERS) * len(FORMATS) * len(CASES), "cases": []}
    if args.check_credo_envelope:
        report.update(expectedCredoAdvisoryCases=len(CREDO_ADVISORY_CASES), credoAdvisoryCases=[])
    outside_origin = []
    errors = []
    stage = "configuration"
    try:
        require(origin(args.guard)[0:2] == ("http", "127.0.0.1") and not urlsplit(args.guard).path
                and not urlsplit(args.guard).query, "Browser acceptance expects the private loopback tunnel")
        token = read_token(args.token_file)
        pin = args.evidence_key_file.read_text(encoding="ascii").strip()
        require(pin != token, "The evidence key must be separate from the verifier token")
        targets = {
            "credo": WalletTarget.from_files(*args.credo, "credo"),
            "eudi-reference": WalletTarget.from_files(*args.eudi, "eudi-reference"),
        }
        endpoints = {
            endpoint_for(args.endpoint_prefix, adapter, format_name)
            for adapter in targets for format_name in FORMATS
        }
        stage = "launch"
        with sync_playwright() as playwright, playwright.chromium.launch() as browser, \
                browser.new_context(accept_downloads=True, viewport={"width": 1160, "height": 900}) as context:
            def restrict(route):
                if route.request.url.startswith(args.guard + "/"):
                    route.continue_()
                else:
                    outside_origin.append(True)
                    route.abort()
            context.route("**/*", restrict)
            guard_page, swagger_page = context.new_page(), context.new_page()
            for page in (guard_page, swagger_page):
                page.on("pageerror", lambda _: errors.append(True))
            stage = "scoped verifier sign in"
            caller, version = sign_in_guard(guard_page, args.guard, token, endpoints)
            swagger = open_swagger(swagger_page, args.guard, token)
            report.update(version=version, guard=args.guard, caller=caller)
            for format_name, format_label in FORMATS.items():
                fixtures = {
                    "matching": SyntheticCredential.issue(format_name, args.credentials, SURNAME),
                    "other": SyntheticCredential.issue(format_name, args.credentials, "Anders"),
                }
                cases = CASES
                if args.check_credo_envelope and format_name == "dc+sd-jwt":
                    cases += CREDO_ADVISORY_CASES
                for case in cases:
                    advisory = case in CREDO_ADVISORY_CASES
                    fixture = fixtures["other" if case == "policy-denied" else "matching"]
                    case_id = f"{format_label}/{case}"
                    results = report["credoAdvisoryCases"] if advisory else report["cases"]
                    for adapter, target in targets.items():
                        if advisory and adapter != "credo":
                            continue
                        endpoint = endpoint_for(args.endpoint_prefix, adapter, format_name)
                        label = f"{adapter}-{format_label}-{case}"
                        operation_id = f"compare-{label}-{secrets.token_hex(4)}"
                        stage = f"Guard {label}"
                        decision, guard_artifacts = wallet_case(
                            guard_page, args, token, target, endpoint, fixture, case, operation_id, label,
                            advisory_nonces if advisory else nonces,
                        )
                        stage = f"Swagger {label}"
                        evidence, swagger_artifacts = swagger_case(
                            swagger_page, swagger, args, token, pin, caller, endpoint, adapter, format_name,
                            decision, label, whole_operation=advisory,
                        )
                        publish_case(args.output, {**guard_artifacts, **swagger_artifacts})
                        results.append({
                            "adapter": adapter, "case": case, "caseId": case_id, "format": format_name,
                            "endpoint": endpoint, **decision, **evidence,
                        })
                        export_result = ("signed Swagger download verified" if evidence["signatureVerified"]
                                         else "no Swagger export (HTTP 404)")
                        print(label, decision["outcome"], export_result, flush=True)
                    if not advisory and case != "wrong-nonce":
                        stage = f"rule comparison {case_id}"
                        left, right = results[-2:]
                        require(left["ruleVersion"] == right["ruleVersion"], "Adapters used different ODRL rules")
            stage = "wallet challenge isolation"
            require(nonces.isdisjoint(advisory_nonces), "A comparison and advisory case reused a wallet challenge")
            stage = "browser isolation"
            require(not outside_origin and not errors, "Browser attempted an external request or raised an error")
    except Error:
        raise RuntimeError(f"Chromium acceptance failed during {stage}") from None
    except RuntimeError as exc:
        raise RuntimeError(f"{stage}: {exc}") from None
    else:
        report["status"] = "pass"
    finally:
        if report["status"] == "fail":
            report["failedStage"] = stage
        report["distinctNonces"] = len(nonces)
        if args.check_credo_envelope:
            report["credoAdvisoryDistinctNonces"] = len(advisory_nonces)
        if any(case["signatureVerified"] for case in report["cases"]):
            (args.output / "evidence-public-key.txt").write_text(pin + "\n", encoding="ascii")
        (args.output / "browser-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True, type=Path, help="Directory holding the test issuer files")
    parser.add_argument("--credo", required=True, nargs=3, metavar=("ORIGIN", "TLS_CA", "REQUEST_CERT"),
                        help="HTTPS wallet origin, TLS CA PEM and pinned Request Object signer PEM")
    parser.add_argument("--eudi", required=True, nargs=3, metavar=("ORIGIN", "TLS_CA", "REQUEST_CERT"),
                        help="HTTPS wallet origin, TLS CA PEM and pinned Request Object signer PEM")
    parser.add_argument("--guard", default="http://127.0.0.1:4180")
    parser.add_argument("--endpoint-prefix", default="/verify/compare")
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--evidence-key-file", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check-credo-envelope", action="store_true",
                        help="Run Credo malformed-envelope, replay and advisory regression checks")
    args = parser.parse_args()
    for name in ("credo", "eudi"):
        url, ca, verifier = getattr(args, name)
        setattr(args, name, (url, Path(ca), Path(verifier)))
    run(args)


if __name__ == "__main__":
    main()
