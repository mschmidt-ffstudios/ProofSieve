"""Exercise the protected Builder handoff and verifier input profiles in Chromium."""

import json
import secrets
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from proofsieve.evidence import EvidenceStore
from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.paths import ROOT
from proofsieve.server import Handler, LoopbackHTTPServer
from proofsieve.access import AccessPolicy
from tests.guard_browser import account, sign_in


SIGNED = "/verify/demo/eudi-sd-jwt"
MDOC = "/verify/demo/eudi-mdoc"
TURTLE = "/verify/turtle"
DECISION = "/verify/orders"
TURTLE_RULE = """@prefix sh: <http://www.w3.org/ns/shacl#> .
@prefix ex: <https://proofsieve.example/demo/> .
ex:Shape a sh:NodeShape ;
    sh:targetNode ex:request ;
    sh:property [ sh:path ex:status ; sh:hasValue "active" ] ."""


def controls(page, name):
    return page.locator(f'[data-access="{name}"]')


def handoff(page, base, preset, data=None):
    page.goto(base + "/apps/builder/")
    page.locator("#builder-preset").select_option(preset)
    if data is not None:
        page.locator("#builder-input").fill(data)
    text = page.locator("#builder-input").input_value()
    page.locator("#builder-handoff").click()
    return text


def submit(page, base, endpoint, raw_request, expected):
    with page.expect_response(lambda response: response.url == base + endpoint
                              and response.request.method == "POST") as captured:
        controls(page, "verify").click()
    response = captured.value
    assert response.request.post_data == raw_request, response.request.post_data
    assert response.status == 200 and response.json() is expected


def check(browser, base, verifier):
    page = browser.new_page()
    posts = []
    page.on("request", lambda req: posts.append(req.url) if req.method == "POST" else None)

    blocked = handoff(page, base, "status", '  {"status":"blocked", "lexicalValue": 1e0}\n')
    sign_in(page, verifier)
    expect(controls(page, "input")).to_have_value(blocked)
    expect(controls(page, "operation-field")).to_be_hidden()
    expect(controls(page, "format")).to_have_value("JSON-Fakten (ODRL)")
    assert posts == []
    submit(page, base, "/verify", f'{{"data":{blocked}}}', False)

    turtle = handoff(page, base, "turtle")
    sign_in(page, verifier)
    expect(controls(page, "handoff")).to_be_visible()
    expect(controls(page, "input")).to_have_value("")
    expect(controls(page, "verify")).to_be_disabled()
    assert posts == [base + "/verify"]
    controls(page, "endpoint").select_option(TURTLE)
    expect(controls(page, "handoff")).to_be_hidden()
    expect(controls(page, "input")).to_have_value(turtle)
    submit(page, base, TURTLE, '{"data":' + json.dumps(turtle) + '}', True)

    controls(page, "endpoint").select_option(SIGNED)
    expect(controls(page, "format")).to_have_value("Kompaktes SD-JWT VC")
    expect(controls(page, "input")).to_have_value("")
    expect(controls(page, "operation-field")).to_be_hidden()
    controls(page, "endpoint").select_option(MDOC)
    expect(controls(page, "format")).to_have_value("mdoc IssuerSigned (Base64url)")
    controls(page, "endpoint").select_option(DECISION)
    expect(controls(page, "operation")).to_be_visible()
    expect(controls(page, "operation")).to_have_attribute("required", "")
    controls(page, "operation").fill("order-1042")
    controls(page, "endpoint").select_option("/verify")
    expect(controls(page, "operation-field")).to_be_hidden()
    expect(controls(page, "operation")).to_have_value("")

    handoff(page, base, "turtle")
    sign_in(page, verifier)
    expect(controls(page, "handoff")).to_be_visible()
    controls(page, "discard-handoff").click()
    expect(controls(page, "handoff")).to_be_hidden()
    expect(controls(page, "input")).to_have_value("")

    blocked = handoff(page, base, "status", '{"status":"blocked"}')
    page.route("**/openapi.json", lambda route: route.fulfill(status=503))
    sign_in(page, verifier)
    expect(controls(page, "login-status")).to_contain_text("nicht erreichbar")
    expect(controls(page, "verifier")).to_be_hidden()
    page.unroute("**/openapi.json")
    sign_in(page, verifier)
    expect(controls(page, "input")).to_have_value(blocked)
    assert posts == [base + "/verify", base + TURTLE]
    submit(page, base, "/verify", f'{{"data":{blocked}}}', False)
    page.reload()
    sign_in(page, verifier)
    expect(controls(page, "input")).to_have_value("")
    controls(page, "verify").click()
    expect(controls(page, "verify-status")).to_contain_text("Gib Prüfdaten ein")
    assert posts == [base + "/verify", base + TURTLE, base + "/verify"]
    page.close()


def main():
    with tempfile.TemporaryDirectory(prefix="proofsieve-verifier-handoff-") as directory:
        work = Path(directory)
        admin, verifier = (secrets.token_urlsafe(32) for _ in range(2))
        config = work / "access.json"
        config.write_text(json.dumps({"version": 1, "principals": [
            account(admin, "operator", "admin", ["*"]),
            account(verifier, "verifier", "verifier", ["/verify", TURTLE, SIGNED, MDOC, DECISION]),
        ]}), encoding="utf-8")
        config.chmod(0o600)
        demos = json.loads((ROOT / "examples" / "signed" / "guard.json").read_bytes())
        guard = Guard(work / "rules.json", demos, evidence=EvidenceStore(work / "evidence.sqlite"))
        guard.update({"language": "shacl", "policy": TURTLE_RULE, "responseMode": "boolean"}, TURTLE)
        guard.update({**DEFAULT_RULE, "responseMode": "decision"}, DECISION)
        with LoopbackHTTPServer(("127.0.0.1", 0), Handler) as server:
            server.access_policy = AccessPolicy.load(config)
            server.guard = guard
            server.credential_examples = []
            server.credential_checks = {}
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with sync_playwright() as playwright, playwright.chromium.launch() as browser:
                    check(browser, f"http://127.0.0.1:{server.server_port}", verifier)
            finally:
                server.shutdown()
                thread.join()
    print("Verifier browser acceptance passed: exact Builder payload, incompatibility, discard, profiles and metadata retry.")


if __name__ == "__main__":
    main()
