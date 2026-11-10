"""Exercise the bundled Swagger UI with Playwright Chromium.

Install Playwright and Chromium, then run `python -m tests.api_docs_browser`.
"""

import hashlib
import json
import secrets
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from proofsieve.access import AccessPolicy
from proofsieve.evidence import EvidenceStore, verify_evidence_export
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.server import Handler, LoopbackHTTPServer


ORDER = "/verify/order"


def exercise(browser, address, token):
    with browser.new_context(accept_downloads=True) as context:
        outbound = []

        def route_request(route):
            url = route.request.url
            if url.startswith(address + "/"):
                route.continue_()
            else:
                outbound.append(url)
                route.abort()

        context.route("**/*", route_request)
        page = context.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        foreign_config = page.goto(address + "/apps/api-docs/?configUrl=https%3A%2F%2Fexternal.example%2Fconfig")
        assert foreign_config.status == 400
        page.goto(address + "/apps/api-docs/")
        token_input = page.locator("#api-token")
        expect(token_input).to_be_visible()
        token_input.fill(token)
        page.locator("#api-sign-in").click()
        operation = page.locator(".opblock")
        expect(operation).to_have_count(1)
        expect(operation.locator(".opblock-summary-path")).to_have_text(ORDER)
        expect(token_input).to_have_value("")
        curl_auth = page.locator("#api-curl-auth")
        expect(curl_auth).to_contain_text("Authorization: Bearer $PROOFSIEVE_TOKEN")
        assert token not in curl_auth.inner_text()
        operation.locator(".opblock-summary-control").click()
        operation.get_by_role("button", name="Ausprobieren").click()
        request_text = json.dumps({"data": {"status": "active", "label": "Execute"}, "operationId": "PO-1042"})
        editor = operation.locator("textarea")
        editor.fill(request_text)
        language = page.locator("select[data-language]")
        language.select_option("en")
        expect(operation.get_by_role("button", name="Execute")).to_be_visible()
        expect(editor).to_have_value(request_text)
        language.select_option("de")
        expect(operation.get_by_role("button", name="Abbrechen")).to_be_visible()
        expect(editor).to_have_value(request_text)
        with page.expect_response(lambda response: response.url == address + ORDER
                                  and response.request.method == "POST") as reply:
            operation.get_by_role("button", name="Ausführen").click()
        response = reply.value
        assert response.status == 200, response.status
        assert response.request.post_data == request_text
        assert response.request.all_headers().get("authorization") == f"Bearer {token}"
        decision = response.json()
        assert decision["outcome"] == "allow" and decision["operationId"] == "PO-1042"
        assert decision["decisionId"]
        curl = operation.locator(".curl-command")
        expect(curl).to_contain_text("PO-1042")
        assert token not in curl.inner_text()
        expect(operation.get_by_role("heading", name="Serverantwort")).to_be_visible()
        expect(operation.get_by_role("heading", name="Antworttext")).to_be_visible()

        with page.expect_download() as download:
            page.locator("#api-download").click()
        content = download.value.path().read_text(encoding="utf-8")
        assert token not in content
        spec = json.loads(content)
        assert set(spec["paths"]) == {ORDER}
        assert spec["security"] == [{"bearerAuth": []}]

        language.select_option("en")
        expect(page.get_by_role("heading", name="Explore the verification API")).to_be_visible()
        expect(operation.get_by_role("heading", name="Response body")).to_be_visible()
        expect(operation.locator(".live-responses-table pre").first).to_contain_text(decision["decisionId"])
        page.locator("#api-sign-out").click()
        expect(operation).to_have_count(0)
        expect(token_input).to_be_visible()
        expect(token_input).to_have_value("")
        expect(curl_auth).to_be_hidden()
        storage = page.evaluate("JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])")
        assert token not in storage
        assert not outbound, outbound
        assert not errors, errors


def exercise_evidence(browser, address, token, public_key):
    with browser.new_context(viewport={"width": 320, "height": 844}, accept_downloads=True) as context:
        page = context.new_page()
        page.goto(address + "/apps/api-docs/")
        token_input = page.locator("#api-token")
        token_input.fill(token)
        token_input.press("Enter")
        operation = page.locator(".opblock-get")
        expect(operation.locator(".opblock-summary-path")).to_have_text("/evidence")
        expect(page.locator("#api-download")).to_be_focused()
        operation.locator(".opblock-summary-control").click()
        operation.get_by_role("button", name="Ausprobieren").click()
        expect(page.locator("html")).to_have_attribute("lang", "de")
        expect(page.locator("#api-explorer")).to_have_attribute("lang", "de")
        assert page.evaluate("document.documentElement.scrollWidth") == 320
        operation.get_by_role("button", name="Ausführen").click()
        expect(operation.locator(".validation-errors")).to_contain_text("Behebe die folgenden Eingabefehler")
        expect(operation.locator(".validation-errors")).to_contain_text("Für „endpoint“ fehlt ein Wert.")
        operation.locator('[data-param-name="endpoint"] input').fill(ORDER)
        operation.locator('[data-param-name="operationId"] input').fill("PO-1042")
        with page.expect_response(lambda response: response.url.startswith(address + "/evidence?")
                                  and response.request.method == "GET") as reply:
            operation.get_by_role("button", name="Ausführen").click()
        response = reply.value
        assert response.status == 200
        evidence = response.json()
        assert evidence["scope"]["operationId"] == "PO-1042"
        assert verify_evidence_export(evidence, public_key=public_key)
        with page.expect_download() as export:
            operation.get_by_role("button", name="Herunterladen").click()
        assert json.loads(export.value.path().read_text(encoding="utf-8")) == evidence
        curl = operation.locator(".curl-command")
        expect(curl).to_contain_text("/evidence?")
        assert token not in curl.inner_text()
        page.locator("select[data-language]").select_option("en")
        expect(page.locator("html")).to_have_attribute("lang", "en")
        expect(page.locator("#api-explorer")).to_have_attribute("lang", "en")
        expect(operation.get_by_role("button", name="Download")).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth") == 320


def main():
    with tempfile.TemporaryDirectory(prefix="proofsieve-api-browser-") as directory:
        work = Path(directory)
        admin, verifier = (secrets.token_urlsafe(32) for _ in range(2))
        config = work / "auth.json"
        config.write_text(json.dumps({
            "version": 1,
            "principals": [
                {"id": user, "role": role, "endpoints": endpoints,
                 "tokenSha256": hashlib.sha256(token.encode("ascii")).hexdigest()}
                for user, role, endpoints, token in (
                    ("operator", "admin", ["*"], admin),
                    ("verifier", "verifier", [ORDER], verifier),
                )
            ],
        }), encoding="utf-8")
        config.chmod(0o600)
        guard = Guard(work / "rules.json", {}, evidence=EvidenceStore(work / "evidence.sqlite"))
        guard.update({**DEFAULT_RULE, "responseMode": "decision"}, ORDER)
        with LoopbackHTTPServer(("127.0.0.1", 0), Handler) as server:
            server.access_policy = AccessPolicy.load(config)
            server.guard = guard
            server.credential_checks = {}
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            worker.start()
            try:
                with sync_playwright() as playwright, playwright.chromium.launch() as browser:
                    address = f"http://127.0.0.1:{server.server_port}"
                    exercise(browser, address, verifier)
                    server.evidence_export = True
                    exercise_evidence(browser, address, verifier, guard.evidence.export_public_key)
            finally:
                server.shutdown()
                worker.join()
    print("Swagger UI browser acceptance passed: scoped execution, signed evidence export, token handling, download, logout and language.")


if __name__ == "__main__":
    main()
