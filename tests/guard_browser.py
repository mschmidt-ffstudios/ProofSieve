"""Chromium acceptance for Guard decisions and opt-in document previews.

Run from the checkout with the installed package dependencies, Playwright
1.60.0 and its Chromium browser using `python -m tests.guard_browser`.
"""

import base64
import hashlib
import json
import secrets
import tempfile
import threading
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from playwright.sync_api import expect, sync_playwright

from proofsieve.access import AccessPolicy
from proofsieve.checks import CheckRegistry
from proofsieve.evidence import EvidenceStore, verify_evidence_export
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.server import Handler, LoopbackHTTPServer
from proofsieve.wallet_protocol import WalletRejected, WalletUnavailable
from tests.test_wallet import ENDPOINT as WALLET, WalletHTTPTest


ORDER = "/verify/orders"
DOCUMENT = "/verify/signed-order"


class UncertainConnector:
    kind = "remote"
    profile_version = "browser-acceptance-v1"

    def __init__(self):
        self.calls = 0
        self.verdict = "indeterminate"

    def post(self, body, media_type, accept, *, deadline):
        self.calls += 1
        request = json.loads(body)
        context = {key: request[key] for key in (
            "version", "nonce", "documentSha256", "certificateSha256", "signatureSha256",
        )}
        return json.dumps({**context, "verdict": self.verdict, "reportId": "browser-report"}).encode()


def document_profile():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ProofSieve browser signer")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    document = b'{"order":"order-1042","amount":800}'
    signature = key.sign(document, ec.ECDSA(hashes.SHA256()))
    profile = {"threshold": 1, "signers": [{
        "id": "browser-signer", "kind": "remote", "format": "raw", "connector": "browser-check",
        "certificatePem": cert.public_bytes(Encoding.PEM).decode("ascii"),
    }]}
    data = {
        "document": base64.b64encode(document).decode("ascii"),
        "proofs": [{"signer": "browser-signer", "signature": base64.b64encode(signature).decode("ascii")}],
    }
    return profile, data


def account(token, identity, role, endpoints):
    return {"id": identity, "role": role, "endpoints": endpoints,
            "tokenSha256": hashlib.sha256(token.encode("ascii")).hexdigest()}


def sign_in(page, token):
    page.locator('[data-access="token"]').fill(token)
    page.locator('[data-access="login-button"]').click()


def download_evidence(page, address, button, token, caller, endpoint, decision, public_key):
    expected = {"endpoint": endpoint, "operationId": decision["operationId"], "decisionId": decision["decisionId"]}
    with page.expect_download() as downloaded:
        with page.expect_response(lambda reply: reply.url.startswith(address + "/evidence?")) as exported:
            button.click()
    response = exported.value
    assert response.status == 200
    assert parse_qs(urlsplit(response.url).query) == {key: [value] for key, value in expected.items()}
    assert response.request.header_value("authorization") == f"Bearer {token}"
    assert token not in response.url and token not in page.url
    assert not page.evaluate("token => [localStorage, sessionStorage].some(storage => "
                             "JSON.stringify(storage).includes(token))", token)
    assert downloaded.value.suggested_filename == f"proofsieve-evidence-{decision['decisionId']}.json"
    downloaded_body = downloaded.value.path().read_bytes()
    assert downloaded_body == response.body()
    bundle = json.loads(downloaded_body)
    assert bundle["scope"] == {"caller": caller, "endpoint": endpoint, "operationId": decision["operationId"]}
    assert not bundle["truncated"] and len(bundle["decisions"]) == 1
    assert all(bundle["decisions"][0][key] == decision[key] for key in ("decisionId", "ruleVersion", "outcome"))
    assert verify_evidence_export(bundle, public_key=public_key)


def verify_ui(browser, address, admin, verifier, scoped, connector, profile, data, public_key):
    page = browser.new_page(viewport={"width": 1160, "height": 940})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto(address + "/apps/guard/?endpoint=" + ORDER)
    expect(page.get_by_role("heading", level=1)).to_have_attribute("id", "guard-access-heading")
    sign_in(page, admin)
    expect(page.get_by_role("heading", level=1)).to_be_focused()
    expect(page.locator("#guard-mode")).to_have_value("boolean")
    page.locator("#guard-mode").select_option("decision")
    page.locator("#guard-save").click()
    expect(page.locator("#guard-status")).to_have_attribute("data-state", "success")
    page.locator("#guard-operation").fill("order-1042")
    evidence = page.locator("#guard-evidence")
    expect(evidence).to_be_hidden()
    page.locator("#guard-verify").click()
    expect(page.locator("#guard-response")).to_contain_text('"outcome": "allow"')
    result = json.loads(page.locator("#guard-response").inner_text())
    assert result["operationId"] == "order-1042" and result["decisionId"], result
    download_evidence(page, address, evidence, admin, "operator", ORDER, result, public_key)
    page.locator("#guard-test-rule").click()
    expect(page.locator('[data-role="evaluation-mode"]')).to_have_text("Live")
    expect(page.locator('[data-role="status"]')).to_contain_text("Freigegeben")
    page.locator('[data-role="close"]').click()

    page.locator("#guard-endpoint-picker").select_option(DOCUMENT)
    expect(evidence).to_be_hidden()
    expect(page.locator("#guard-mode")).to_have_value("decision")
    page.locator("#guard-document-profile > summary").click()
    expect(page.locator("#guard-profile-signers")).to_contain_text("browser-check")
    page.locator("select[data-language]").select_option("en")
    expect(page.locator("#guard-profile-signers")).to_contain_text("External")
    page.locator("#guard-data").fill(json.dumps(data))
    page.locator("#guard-test-rule").click()
    expect(page.locator('[data-role="evaluation-mode"]')).to_have_text("Manual")
    preview_requests = []
    page.on("request", lambda request: preview_requests.append(request.url)
            if "/admin/test-rule" in request.url else None)
    page.locator('[data-role="data"]').fill(json.dumps(data, indent=2))
    page.wait_for_timeout(450)
    assert not preview_requests and connector.calls == 0
    page.locator('[data-role="run"]').click()
    expect(page.locator('[data-role="status"]')).to_contain_text("Inconclusive")
    expect(page.locator(".rule-tester-check")).to_contain_text("browser-report")
    assert len(preview_requests) == connector.calls == 1
    connector.verdict = "passed"
    page.locator('[data-role="run"]').click()
    expect(page.locator('[data-role="status"]')).to_contain_text("Allowed")
    expect(page.locator(".rule-tester-comparison")).to_contain_text("thresholdMet")
    assert len(preview_requests) == connector.calls == 2
    page.locator('[data-role="close"]').click()
    replacement = deepcopy(profile)
    replacement["signers"][0]["connector"] = "unregistered-connector"
    page.locator("#guard-verification").fill(json.dumps(replacement))
    page.locator("#guard-test-rule").click()
    page.locator('[data-role="run"]').click()
    expect(page.locator('[data-role="status"]')).to_contain_text("Save the changed verification profile")
    assert len(preview_requests) == connector.calls == 2
    page.locator('[data-role="close"]').click()
    page.locator("#guard-save").click()
    expect(page.locator("#guard-status")).to_have_attribute("data-state", "error")
    assert connector.calls == 2
    replacement["signers"][0]["connector"] = "browser-check"
    replacement["signers"][0]["id"] = "renamed-signer"
    page.locator("#guard-verification").fill(json.dumps(replacement))
    page.locator("#guard-save").click()
    expect(page.locator("#guard-status")).to_have_attribute("data-state", "success")
    expect(page.locator("#guard-profile-signers")).to_contain_text("renamed-signer")
    page.locator('[data-access="logout"]').click()

    page.goto(address + "/apps/guard/?endpoint=" + DOCUMENT)
    sign_in(page, scoped)
    page.locator("#guard-document-profile > summary").click()
    expect(page.locator("#guard-verification")).to_have_attribute("readonly", "")
    expect(page.locator("#guard-profile-signers")).to_contain_text("browser-check")
    expect(page.locator("#guard-profile-signers")).to_contain_text("renamed-signer")
    page.locator('[data-access="logout"]').click()
    page.goto(address + "/apps/guard/")
    sign_in(page, verifier)
    expect(page.locator('[data-access="endpoint"]')).to_have_value(ORDER)
    expect(page.get_by_role("heading", level=1)).to_be_focused()
    expect(page.locator("#guard-editor")).to_be_hidden()
    page.locator('[data-access="operation"]').fill("order-1043")
    page.locator('[data-access="input"]').fill('{"status":"inactive"}')
    page.locator('[data-access="verify"]').click()
    expect(page.locator('[data-access="response"]')).to_contain_text('"outcome": "deny"')
    denial = json.loads(page.locator('[data-access="response"]').inner_text())
    evidence = page.locator('[data-access="evidence"]')
    expect(evidence).to_have_text("Download signed evidence")
    download_evidence(page, address, evidence, verifier, "verifier", ORDER, denial, public_key)
    page.locator('[data-access="input"]').fill('{"status":"active"}')
    expect(evidence).to_be_hidden()
    page.locator('[data-access="verify"]').click()
    expect(page.locator('[data-access="response"]')).to_contain_text('"outcome": "allow"')
    approval = json.loads(page.locator('[data-access="response"]').inner_text())
    assert approval["operationId"] == denial["operationId"] and approval["decisionId"] != denial["decisionId"]
    download_evidence(page, address, evidence, verifier, "verifier", ORDER, approval, public_key)
    page.locator('[data-access="logout"]').click()
    expect(evidence).to_be_hidden()
    assert not errors, errors
    page.close()


def verify_endpoint_deep_links(browser, address, admin, verifier):
    for token, picker, status, verify in (
        (admin, "#guard-endpoint-picker", "#guard-status", "#guard-verify"),
        (verifier, '[data-access="endpoint"]', '[data-access="endpoint-status"]', '[data-access="verify"]'),
    ):
        page = browser.new_page()
        requests = []
        page.on("request", lambda request: requests.append(request.url) if request.method == "POST" else None)
        page.goto(address + "/apps/guard/?endpoint=" + DOCUMENT)
        sign_in(page, token)
        expect(page.locator(picker)).to_have_value(DOCUMENT)
        expect(page.locator(verify)).to_be_enabled()

        forbidden = address + "/apps/guard/?endpoint=/verify"
        page.goto(forbidden)
        sign_in(page, token)
        expect(page.locator(status)).to_contain_text("Der verlinkte Prüfendpunkt ist für dieses Konto nicht verfügbar.")
        expect(page.locator(picker)).to_have_value("")
        expect(page.locator(verify)).to_be_disabled()
        expect(page).to_have_url(forbidden)
        page.locator("select[data-language]").select_option("en")
        expect(page.locator(status)).to_contain_text("The linked verification endpoint is unavailable for this account.")
        assert not requests, requests

        page.locator(picker).select_option(ORDER)
        expect(page.locator(picker)).to_have_value(ORDER)
        expect(page.locator(verify)).to_be_enabled()
        expect(page).to_have_url(address + "/apps/guard/?endpoint=%2Fverify%2Forders")
        assert not requests, requests
        page.close()


def verify_admin_wallet(browser):
    fixture = WalletHTTPTest()
    try:
        fixture.setUp()
        fixture.server.evidence_export = True
        clock = datetime.now(timezone.utc).timestamp()
        fixture.sessions.clock = lambda: clock
        address = f"http://127.0.0.1:{fixture.server.server_port}"
        page = browser.new_page(viewport={"width": 320, "height": 700})
        try:
            page.goto(address + "/apps/guard/?endpoint=" + WALLET)
            sign_in(page, fixture.tokens["admin"])
            expect(page.locator("#guard-endpoint-picker")).to_have_value(WALLET)
            expect(page.locator("#guard-verify")).to_be_enabled()
            expect(page.locator("#guard-test-rule")).to_be_hidden()
            expect(page.locator("#guard-input-caption")).to_have_text("Wallet-Sitzung (JSON)")
            page.locator("#guard-operation").fill("browser-wallet")
            result = page.locator("#guard-response")
            verify = page.locator("#guard-verify")
            deadline = page.locator("#guard-wallet-expiry time")
            evidence = page.locator("#guard-evidence")
            verify.click()
            expect(page.locator("#guard-status")).to_contain_text("Wallet-Sitzung gestartet")
            expect(page.locator("#guard-http-status")).to_have_text("HTTP 201")
            session = json.loads(result.inner_text())
            assert session["authorizationRequestUri"] == "haip-vp://?example=internal"
            assert session["operationId"] == "browser-wallet"
            expect(deadline).to_have_attribute("datetime", session["expiresAt"])
            expect(deadline).to_be_visible()
            expect(evidence).to_be_hidden()
            complete = {"action": "complete", "sessionId": session["sessionId"]}
            assert json.loads(page.locator("#guard-data").input_value()) == complete

            with page.expect_response(lambda reply: reply.url == address + WALLET and reply.request.method == "POST") as pending:
                verify.click()
            assert pending.value.request.post_data_json == {"data": complete, "operationId": "browser-wallet"}
            expect(page.locator("#guard-status")).to_contain_text("steht noch aus")
            expect(page.locator("#guard-http-status")).to_have_text("HTTP 202")
            assert json.loads(result.inner_text()) == {"state": "pending", "operationId": "browser-wallet"}
            expect(deadline).to_be_visible()
            expect(evidence).to_be_hidden()
            page.locator("select[data-language]").select_option("en")
            expect(page.locator("#guard-status")).to_contain_text("wallet presentation is pending")

            fixture.connector.reply = WalletUnavailable()
            verify.click()
            expect(page.locator("#guard-status")).to_have_text("Wallet verification is temporarily unavailable.")
            expect(deadline).to_be_visible()
            expect(evidence).to_be_hidden()

            fixture.connector.reply = WalletRejected()
            verify.click()
            expect(page.locator("#guard-status")).to_contain_text("The wallet presentation was rejected.")
            expect(page.locator("#guard-http-status")).to_have_text("HTTP 403")
            denied = json.loads(result.inner_text())
            assert denied["outcome"] == "deny" and denied["reason"] == "wallet_rejected" and denied["decisionId"]
            expect(deadline).to_be_hidden()
            download_evidence(page, address, evidence, fixture.tokens["admin"], "admin", WALLET,
                              denied, fixture.evidence.export_public_key)

            page.locator("#guard-operation").fill("browser-wallet-approved")
            page.locator("#guard-data").fill('{"action":"start"}')
            verify.click()
            expect(page.locator("#guard-http-status")).to_have_text("HTTP 201")
            fixture.connector.reply = {"status": "active"}
            verify.click()
            expect(page.locator("#guard-status")).to_contain_text("This operation is approved.")
            expect(page.locator("#guard-http-status")).to_have_text("HTTP 200")
            allowed = json.loads(result.inner_text())
            assert allowed["outcome"] == "allow" and allowed["operationId"] == "browser-wallet-approved"

            page.locator("#guard-operation").fill("browser-wallet-expired")
            page.locator("#guard-data").fill('{"action":"start"}')
            verify.click()
            expect(page.locator("#guard-http-status")).to_have_text("HTTP 201")
            expect(deadline).to_be_visible()
            clock += fixture.sessions.lifetime + 1
            verify.click()
            expect(page.locator("#guard-status")).to_have_text("The wallet session expired. Verification is inconclusive.")
            expect(page.locator("#guard-http-status")).to_have_text("HTTP 503")
            expect(deadline).to_be_hidden()
            expired = json.loads(result.inner_text())
            assert expired["outcome"] == "indeterminate" and expired["reason"] == "wallet_expired" and not expired["valid"]
            download_evidence(page, address, evidence, fixture.tokens["admin"], "admin", WALLET,
                              expired, fixture.evidence.export_public_key)
        finally:
            page.close()
    finally:
        fixture.doCleanups()


def verify_verifier_wallet(browser):
    fixture = WalletHTTPTest()
    try:
        fixture.setUp()
        config = fixture.work / "auth.json"
        config.write_text(json.dumps({"version": 1, "principals": [
            account(fixture.tokens["first"], "first", "verifier", ["/verify", WALLET]),
            account(fixture.tokens["admin"], "admin", "admin", [WALLET]),
        ]}), encoding="utf-8")
        fixture.server.access_policy = AccessPolicy.load(config)
        clock = datetime.now(timezone.utc).timestamp()
        fixture.sessions.clock = lambda: clock
        address = f"http://127.0.0.1:{fixture.server.server_port}"
        page = browser.new_page(viewport={"width": 390, "height": 844})
        try:
            page.goto(address + "/apps/guard/")
            sign_in(page, fixture.tokens["first"])

            def control(name):
                return page.locator(f'[data-access="{name}"]')

            endpoint, operation = control("endpoint"), control("operation")
            payload, response = control("input"), control("response")
            verify, http_status, feedback = control("verify"), control("http-status"), control("verify-status")
            deadline, open_wallet, evidence = control("wallet-expiry"), control("wallet-open"), control("evidence")
            endpoint.select_option(WALLET)
            operation.fill("verifier-wallet-order")
            expect(verify).to_have_text("Wallet-Sitzung starten")
            verify.click()
            expect(http_status).to_have_text("HTTP 201")
            session = json.loads(response.inner_text())
            complete = {"action": "complete", "sessionId": session["sessionId"]}
            assert json.loads(payload.input_value()) == complete
            expect(operation).to_have_value("verifier-wallet-order")
            expect(open_wallet).to_have_attribute("href", session["authorizationRequestUri"])
            expect(deadline.locator("time")).to_have_attribute("datetime", session["expiresAt"])
            expect(evidence).to_be_hidden()
            page.locator("select[data-language]").select_option("en")
            expect(verify).to_have_text("Check wallet presentation")
            expect(open_wallet).to_have_text("Open in wallet")
            with page.expect_response(lambda reply: reply.url == address + WALLET
                                      and reply.request.method == "POST") as pending:
                verify.click()
            assert pending.value.request.post_data_json == {"data": complete, "operationId": "verifier-wallet-order"}
            expect(http_status).to_have_text("HTTP 202")
            expect(open_wallet).to_have_attribute("href", session["authorizationRequestUri"])
            expect(deadline).to_be_visible()
            expect(evidence).to_be_hidden()

            fixture.connector.reply = WalletUnavailable()
            verify.click()
            expect(http_status).to_have_text("HTTP 503")
            expect(feedback).to_contain_text("temporarily unavailable")
            expect(open_wallet).to_be_visible()
            fixture.connector.reply = {"status": "active"}
            verify.click()
            expect(http_status).to_have_text("HTTP 200")
            expect(feedback).to_have_text("This operation is approved.")
            expect(verify).to_be_disabled()
            expect(open_wallet).to_be_hidden()
            expect(deadline).to_be_hidden()
            allowed = json.loads(response.inner_text())
            download_evidence(page, address, evidence, fixture.tokens["first"], "first", WALLET,
                              allowed, fixture.evidence.export_public_key)

            operation.fill("verifier-wallet-abandoned")
            expect(verify).to_have_text("Start wallet session")
            expect(evidence).to_be_hidden()
            verify.click()
            expect(http_status).to_have_text("HTTP 201")
            expect(open_wallet).to_be_visible()
            endpoint.select_option("/verify")
            expect(open_wallet).to_be_hidden()
            expect(response).to_be_hidden()
            endpoint.select_option(WALLET)
            expect(operation).to_have_value("")
            expect(payload).to_have_value('{"action":"start"}')
            operation.fill("verifier-wallet-expired")
            verify.click()
            expect(http_status).to_have_text("HTTP 201")
            clock += fixture.sessions.lifetime + 1
            verify.click()
            expect(http_status).to_have_text("HTTP 503")
            expect(feedback).to_contain_text("wallet session expired")
            expect(open_wallet).to_be_hidden()
            expect(verify).to_be_disabled()
            expired = json.loads(response.inner_text())
            assert expired["outcome"] == "indeterminate" and expired["reason"] == "wallet_expired"
            download_evidence(page, address, evidence, fixture.tokens["first"], "first", WALLET,
                              expired, fixture.evidence.export_public_key)

            endpoint.select_option("/verify")
            payload.fill('{"status":"blocked"}')
            verify.click()
            expect(feedback).to_have_text("The verification rule denied the operation.")
            for body, message in (
                ({"valid": False, "outcome": "indeterminate"}, "Verification is inconclusive."),
                ({"valid": True, "outcome": "allow", "delivery": {"state": "unknown"}}, "Delivery is unconfirmed."),
            ):
                page.route(address + "/verify", lambda route: route.fulfill(status=503, json=body))
                verify.click()
                expect(feedback).to_contain_text(message)
                page.unroute(address + "/verify")

            endpoint.select_option(WALLET)
            operation.fill("verifier-wallet-conflict")
            page.route(address + WALLET, lambda route: route.fulfill(status=409, json={"code": "wallet_session_conflict"}))
            verify.click()
            expect(feedback).to_contain_text("look for existing evidence under GET /evidence")
            expect(verify).to_be_disabled()
            page.unroute(address + WALLET)

            operation.fill("verifier-wallet-bad-uri")
            page.route(address + WALLET, lambda route: route.fulfill(status=201, json={
                **session, "operationId": "verifier-wallet-bad-uri", "authorizationRequestUri": "javascript:alert(1)",
            }))
            verify.click()
            expect(http_status).to_have_text("HTTP 201")
            expect(feedback).to_contain_text("could not be completed")
            expect(open_wallet).to_be_hidden()
            expect(open_wallet).not_to_have_attribute("href", "javascript:alert(1)")
            expect(payload).to_have_value('{"action":"start"}')
        finally:
            page.close()
    finally:
        fixture.doCleanups()


def verify_wallet_evidence_recovery(browser):
    fixture = WalletHTTPTest()
    try:
        fixture.setUp()
        fixture.sessions.clock = lambda: datetime.now(timezone.utc).timestamp()
        address = f"http://127.0.0.1:{fixture.server.server_port}"
        for role in ("admin", "first"):
            page = browser.new_page(viewport={"width": 390, "height": 844})
            try:
                page.goto(address + "/apps/guard/?endpoint=" + WALLET)
                sign_in(page, fixture.tokens[role])

                def control(admin_id, verifier_name):
                    return page.locator(f"#guard-{admin_id}" if role == "admin"
                                        else f'[data-access="{verifier_name}"]')

                operation = control("operation", "operation")
                verify = control("verify", "verify")
                status = control("http-status", "http-status")
                feedback = control("status", "verify-status")
                output = control("response", "response")
                evidence = control("evidence", "evidence")
                reference = f"browser-{role}-interrupted"
                operation.fill(reference)
                verify.click()
                expect(status).to_have_text("HTTP 201")
                session = json.loads(output.inner_text())
                complete = {"data": {"action": "complete", "sessionId": session["sessionId"]},
                            "operationId": reference}
                fixture.connector.reply = {"status": "active"}

                def submit():
                    with page.expect_response(lambda reply: reply.url == address + WALLET
                                              and reply.request.method == "POST") as captured:
                        verify.click()
                    response = captured.value
                    assert response.request.post_data_json == complete
                    return response

                with patch.object(fixture.evidence, "record", side_effect=OSError("simulated evidence outage")):
                    response = submit()
                    assert response.status == 503 and response.json()["code"] == "evidence_unavailable"
                expect(feedback).to_contain_text("Frage dieselbe Wallet-Sitzung erneut ab")
                expect(verify).to_be_enabled()
                expect(evidence).to_be_hidden()
                page.locator("select[data-language]").select_option("en")
                expect(feedback).to_contain_text("Retry completion for this same wallet session")
                if role != "admin":
                    expect(verify).to_have_text("Retry completion")

                response = submit()
                decision = response.json()
                assert response.status == 503
                assert (decision["valid"], decision["outcome"], decision["reason"], decision["operationId"]) == (
                    False, "indeterminate", "wallet_evidence_interrupted", reference,
                )
                expect(feedback).to_contain_text("The recorded decision is inconclusive")
                expect(verify).to_be_disabled()
                download_evidence(page, address, evidence, fixture.tokens[role], role, WALLET,
                                  decision, fixture.evidence.export_public_key)
                page.locator("select[data-language]").select_option("de")
                expect(feedback).to_contain_text("Die gespeicherte Entscheidung ist unbestimmt")
                operation.fill(reference + "-new")
                expect(verify).to_be_enabled()
                expect(evidence).to_be_hidden()
                expect(control("data", "input")).to_have_value('{"action":"start"}')
            finally:
                page.close()
        assert fixture.connector.result_calls == 2
    finally:
        fixture.doCleanups()


def main():
    with tempfile.TemporaryDirectory(prefix="proofsieve-guard-browser-") as directory:
        work = Path(directory)
        admin, verifier, scoped, linked_admin, linked_verifier = (secrets.token_urlsafe(32) for _ in range(5))
        config = work / "auth.json"
        config.write_text(json.dumps({"version": 1, "principals": [
            account(admin, "operator", "admin", ["*"]),
            account(verifier, "verifier", "verifier", [ORDER]),
            account(scoped, "scoped", "admin", [DOCUMENT]),
            account(linked_admin, "linked-admin", "admin", [ORDER, DOCUMENT]),
            account(linked_verifier, "linked-verifier", "verifier", [ORDER, DOCUMENT]),
        ]}), encoding="utf-8")
        config.chmod(0o600)
        profile, data = document_profile()
        connector = UncertainConnector()
        registry = CheckRegistry({"browser-check": connector})
        evidence = EvidenceStore(work / "evidence.sqlite")
        guard = Guard(work / "rules.json", {}, registry=registry, evidence=evidence)
        guard.update(DEFAULT_RULE, ORDER)
        document_rule = {**deepcopy(DEFAULT_RULE), "responseMode": "decision", "verification": profile}
        document_rule["policy"]["permission"][0]["constraint"] = [
            {"leftOperand": "field:thresholdMet", "operator": "eq", "rightOperand": True},
        ]
        guard.update(document_rule, DOCUMENT)
        with LoopbackHTTPServer(("127.0.0.1", 0), Handler) as server:
            server.access_policy = AccessPolicy.load(config)
            server.guard = guard
            server.credential_checks = {}
            server.evidence_export = True
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                with sync_playwright() as playwright:
                    with playwright.chromium.launch() as browser:
                        verify_ui(browser, f"http://127.0.0.1:{server.server_port}",
                                  admin, verifier, scoped, connector, profile, data, evidence.export_public_key)
                        verify_endpoint_deep_links(browser, f"http://127.0.0.1:{server.server_port}",
                                                   linked_admin, linked_verifier)
                        verify_admin_wallet(browser)
                        verify_verifier_wallet(browser)
                        verify_wallet_evidence_recovery(browser)
            finally:
                server.shutdown()
                worker.join()
    print("Guard browser acceptance passed: operation evidence, manual document checks, scoped access, bilingual UI and wallet flow.")


if __name__ == "__main__":
    main()
