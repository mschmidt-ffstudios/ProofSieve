"""Exercise Builder, Guard and Lab tasks in Chromium on a disposable server.

Run with Playwright and Chromium installed using `python -m tests.workspace_browser`.
"""

import hashlib
import json
import re
import secrets
import tempfile
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

from proofsieve.access import AccessPolicy
from proofsieve.guard import Guard
from proofsieve.paths import ROOT
from proofsieve.server import Handler, LoopbackHTTPServer, load_credential_examples


TURTLE_ENDPOINT = "/verify/review-status"


def verify_handoffs(page, address):
    page.goto(address + "/apps/")
    page.locator('main a[href="/apps/builder/"]').click()
    expect(page.locator("#builder-input")).to_have_value('{\n  "status": "active"\n}')
    page.locator("select[data-language]").select_option("en")
    expect(page.locator("#builder-handoff")).to_have_text("Open input in the Guard")

    imported = b'{"status":"blocked","reviewReference":"case-1042"}'
    file_input = page.locator("#builder-import")
    file_input.set_input_files({"name": "order.json", "mimeType": "application/json", "buffer": imported})
    expect(page.locator("#builder-input")).to_have_value(imported.decode())
    file_input.set_input_files({"name": "broken.json", "mimeType": "application/json", "buffer": b'{"status":'})
    expect(page.locator("#builder-status")).to_have_attribute("data-state", "error")
    expect(page.locator("#builder-input")).to_have_value(imported.decode())
    page.locator("#builder-save").click()
    page.reload()
    expect(page.locator("#builder-input")).to_have_value(imported.decode())
    with page.expect_download() as download:
        page.locator("#builder-export").click()
    assert Path(download.value.path()).read_bytes() == imported

    calls = []
    page.on("request", lambda req: calls.append(req.url) if req.method == "POST" else None)
    page.locator("#builder-handoff").click()
    expect(page.locator("#guard-data")).to_have_value(imported.decode())
    assert not calls, calls
    expect(page.locator("html")).to_have_attribute("lang", "en")
    page.locator("#guard-verify").click()
    expect(page.locator("#guard-response")).to_have_text("false")
    assert calls == [address + "/verify"], calls

    endpoint_picker = page.locator("#guard-endpoint-picker")
    page.once("dialog", lambda dialog: dialog.dismiss())
    endpoint_picker.select_option("__new__")
    expect(endpoint_picker).to_have_value("/verify")
    expect(page.locator("#guard-data")).to_have_value(imported.decode())
    page.once("dialog", lambda dialog: dialog.accept())
    endpoint_picker.select_option("__new__")
    page.locator("#guard-endpoint").fill(TURTLE_ENDPOINT)
    page.locator("#guard-language").select_option("shacl")
    page.locator("#guard-load-template").click()
    page.locator("#guard-save").click()
    expect(page.locator("#guard-status")).to_have_attribute("data-state", "success")

    page.locator('a[href="/apps/builder/"]').click()
    expect(page.locator("#builder-input")).to_have_value(imported.decode())
    page.locator("#builder-preset").select_option("turtle")
    turtle = page.locator("#builder-input").input_value()
    assert '"active"' in turtle
    page.locator("#builder-handoff").click()
    expect(page.locator("#guard-handoff")).to_be_visible()
    assert len(calls) == 1, calls
    page.locator("#guard-endpoint-picker").select_option(TURTLE_ENDPOINT)
    expect(page.locator("#guard-data")).to_have_value(turtle)
    page.locator("#guard-verify").click()
    expect(page.locator("#guard-response")).to_have_text("true")
    page.locator("#guard-data").fill(turtle.replace('"active"', '"blocked"'))
    page.locator("#guard-verify").click()
    expect(page.locator("#guard-response")).to_have_text("false")
    assert calls == [address + "/verify", address + TURTLE_ENDPOINT, address + TURTLE_ENDPOINT], calls



def verify_saved_draft_deletion(page, address):
    page.goto(address + "/apps/builder/")
    raw = page.locator("#builder-input")
    draft = '{"status":"synthetic-draft"}'
    raw.fill(draft)
    page.locator("#builder-save").click()
    page.reload()
    expect(raw).to_have_value(draft)
    note = page.locator("#builder-draft-note")
    language = page.locator("select[data-language]")
    language.select_option("de")
    expect(note).to_contain_text("synthetische Testdaten")
    language.select_option("en")
    expect(note).to_contain_text("same browser profile")
    remove = page.get_by_role("button", name="Delete saved draft")
    remove.click()
    expect(remove).to_be_hidden()
    expect(raw).to_have_value(draft)
    page.reload()
    expect(raw).to_have_value('{\n  "status": "active"\n}')
    expect(remove).to_be_hidden()


def verify_builder_claims(page, address):
    page.goto(address + "/apps/builder/")
    page.locator("#builder-preset").select_option("credential")
    claims = page.locator('#builder-fields textarea[name="claims"]')
    apply = page.locator('#builder-form button[type="submit"]')
    builder_input = page.locator("#builder-input")
    cases = (
        ('{"department":"Demo","active":true}', {"department": "Demo", "active": True}),
        ('{"order":9007199254740993}', {"order": 9007199254740993}),
    )
    for source, expected in cases:
        claims.fill(source)
        apply.click()
        assert json.loads(builder_input.input_value())["claims"] == expected

    # The browser must preserve values and duplicate names for the strict server parser.
    claims.fill('{"order":1e309}')
    apply.click()
    assert '"order":1e309' in builder_input.input_value()

    claims.fill('{"order":1,"order":2}')
    apply.click()
    duplicate = builder_input.input_value()
    assert '"order":1,"order":2' in duplicate
    page.locator("#builder-handoff").click()
    expect(page.locator("#guard-data")).to_have_value(duplicate)
    with page.expect_response(lambda response: response.url == address + "/verify"
                              and response.request.method == "POST") as submitted:
        page.locator("#guard-verify").click()
    response = submitted.value
    assert response.request.post_data == '{"data":' + duplicate + '}'
    assert response.status == 400
    assert "Doppelte JSON-Felder" in response.json()["error"]
    expect(page.locator("#guard-status")).to_have_attribute("data-state", "error")


def verify_pending_template_values(page, address):
    page.goto(address + "/apps/builder/")
    field = page.locator('#builder-fields input[name="status"]')
    raw = page.locator("#builder-input")
    pending = page.locator("#builder-pending")
    handoff = page.locator("#builder-handoff")
    apply = page.locator('#builder-form button[type="submit"]')
    original = raw.input_value()
    field.fill("blocked")
    expect(raw).to_have_value(original)
    expect(pending).to_contain_text("Vorlagenänderungen sind offen")
    for control in (handoff, page.locator("#builder-export"), page.locator("#builder-save")):
        expect(control).to_be_disabled()
    page.locator("select[data-language]").select_option("en")
    expect(pending).to_contain_text("Template changes are pending")
    manual = '{"status":"blocked","reference":"keep this raw edit"}'
    raw.fill(manual)
    expect(handoff).to_be_disabled()
    page.locator("#builder-discard-fields").click()
    expect(raw).to_have_value(manual)
    expect(field).to_have_value("active")
    expect(handoff).to_be_enabled()

    # A saved draft from an older build can contain the very same discrepancy.
    page.evaluate("text => localStorage.setItem('proofsieve:builder-draft:v1', JSON.stringify({"
                  "preset: 'status', values: {status: 'blocked'}, text}))", original)
    page.reload()
    expect(pending).to_be_visible()
    expect(handoff).to_be_disabled()
    apply.click()
    expect(pending).to_be_hidden()
    handoff.click()
    expect(page.locator("#guard-data")).to_have_value('{\n  "status": "blocked"\n}')
    page.locator("#guard-verify").click()
    expect(page.locator("#guard-response")).to_have_text("false")


def verify_builder_file_races(page, address):
    page.goto(address + "/apps/builder/")
    builder_input = page.locator("#builder-input")
    original = builder_input.input_value()
    page.evaluate("""() => {
        const read = File.prototype.arrayBuffer;
        const pending = new Map();
        File.prototype.arrayBuffer = function () {
            return new Promise((resolve, reject) => {
                pending.set(this.name, async () => {
                    try { resolve(await read.call(this)); }
                    catch (error) { reject(error); }
                });
            });
        };
        window.releaseFileRead = async name => {
            await pending.get(name)();
            pending.delete(name);
        };
    }""")
    file_input = page.locator("#builder-import")
    for name, payload in (("first.json", b'{"status":"first"}'), ("last.json", b'{"status":"last"}')):
        file_input.set_input_files({"name": name, "mimeType": "application/json", "buffer": payload})
    page.evaluate("name => window.releaseFileRead(name)", "first.json")
    expect(builder_input).to_have_value(original)
    page.evaluate("name => window.releaseFileRead(name)", "last.json")
    expect(builder_input).to_have_value('{"status":"last"}')

    file_input.set_input_files({"name": "bad.json", "mimeType": "application/json", "buffer": b"\xff"})
    builder_input.fill('{"status":"manual"}')
    status = page.locator("#builder-status")
    expect(status).to_have_attribute("data-state", "info")
    page.evaluate("name => window.releaseFileRead(name)", "bad.json")
    expect(builder_input).to_have_value('{"status":"manual"}')
    expect(status).to_have_attribute("data-state", "info")


def verify_sourced_examples(page, address, examples):
    page.goto(address + "/apps/builder/")
    sample_count = len(examples)
    assert sample_count == 5, sample_count
    for sample in examples:
        page.locator("#builder-preset").select_option(sample["id"])
        expect(page.get_by_role("button", name="Check JSON fields against the example rule")).to_be_visible()
        for button, expected in (("original", "true"), ("negative", "false")):
            page.locator(f"#builder-sample-{button}").click()
            page.locator("#builder-sample-run").click()
            expect(page.locator("#builder-sample-response")).to_have_text(f"HTTP 200 · {expected}")
    return sample_count * 2


def verify_signed_demo_links(page, address, work, server):
    presets = {
        "eudi-pid-sd-jwt": "/verify/demo/eudi-sd-jwt",
        "eudi-pid-mdoc": "/verify/demo/eudi-mdoc",
    }
    picker = page.locator("#builder-preset")
    link = page.locator("#builder-sample-signed-link")
    page.goto(address + "/apps/builder/")
    picker.select_option("eudi-pid-sd-jwt")
    expect(link).to_be_hidden()
    previous_guard = server.guard
    demos = json.loads((ROOT / "examples" / "signed" / "guard.json").read_bytes())
    server.guard = Guard(work / "builder-signed.json", demos)
    handoff = {"language": "odrl", "text": '{"status":"blocked"}'}
    handoff_key = "proofsieve:guard-input:v1"
    page.evaluate("([key, value]) => sessionStorage.setItem(key, JSON.stringify(value))", [handoff_key, handoff])
    page.goto(address + "/apps/builder/")
    posts = []

    def collect_posts(request):
        if request.method == "POST":
            posts.append(request.url)

    def open_demo(expected_path):
        count = len(posts)
        with page.expect_popup() as opened:
            link.click()
        popup = opened.value
        popup.wait_for_url("**/apps/guard/?*")
        assert parse_qs(urlsplit(popup.url).query) == {"endpoint": [expected_path], "case": ["original"]}
        assert popup.evaluate("window.opener === null")
        assert popup.evaluate("key => sessionStorage.getItem(key)", handoff_key) is None
        assert len(posts) == count
        return popup

    page.context.on("request", collect_posts)
    try:
        for language, (preset, path) in zip(("de", "en"), presets.items()):
            picker.select_option(preset)
            page.locator("select[data-language]").select_option(language)
            expect(link).to_have_text("Signiertes Beispiel im Guard öffnen" if language == "de"
                                      else "Open signed example in Guard")
            raw = page.locator("#builder-input")
            draft = '{"changedClaim":"unsaved-' + language + '"}'
            raw.fill(draft)
            popup = open_demo(path)
            expect(popup.locator("#guard-endpoint-picker")).to_have_value(path)
            expect(popup.locator("#guard-data")).to_have_value(demos[path]["credentialExamples"]["valid"])
            popup.locator("#guard-verify").click()
            expect(popup.locator("#guard-response")).to_have_text("true")
            assert posts[-1] == address + path
            popup.locator("#guard-example-tampered").click()
            popup.locator("#guard-verify").click()
            expect(popup.locator("#guard-response")).to_contain_text('"code": "credential_rejected"')
            popup.close()
            expect(raw).to_have_value(draft)
            assert page.evaluate("key => JSON.parse(sessionStorage.getItem(key))", handoff_key) == handoff

        for preset in ("other-w3c-degree", "other-sd-jwt-selective-disclosure", "other-x509-end-entity", "status"):
            picker.select_option(preset)
            expect(link).to_be_hidden()

        admin, verifier = (secrets.token_urlsafe(32) for _ in range(2))
        config = work / "signed-links-access.json"
        config.write_text(json.dumps({"version": 1, "principals": [
            {"id": identity, "role": role, "endpoints": endpoints,
             "tokenSha256": hashlib.sha256(token.encode("ascii")).hexdigest()}
            for identity, role, endpoints, token in (
                ("demo-admin", "admin", ["*"], admin),
                ("demo-verifier", "verifier", ["/verify", presets["eudi-pid-mdoc"]], verifier),
            )
        ]}))
        config.chmod(0o600)
        server.access_policy = AccessPolicy.load(config)
        page.goto(address + "/apps/builder/?example=eudi-pid-mdoc")
        path = presets["eudi-pid-mdoc"]
        popup = open_demo(path)
        token_input = popup.locator('[data-access="token"]')
        token_input.fill(verifier)
        token_input.press("Enter")
        expect(popup.locator('[data-access="endpoint"]')).to_have_value(path)
        expect(popup.locator('[data-access="input"]')).to_have_value(demos[path]["credentialExamples"]["valid"])
        expect(popup.locator('[data-access="verify-status"]')).to_have_text(
            "Signed test credential loaded. Start verification on the server.")
        popup.locator('[data-access="verify"]').click()
        expect(popup.locator('[data-access="response"]')).to_have_text("true")
        expect(popup.locator('[data-access="verify-status"]')).to_have_text("Verification approved the operation.")
        popup.locator('[data-access="input"]').fill(demos[path]["credentialExamples"]["tampered"])
        popup.locator('[data-access="verify"]').click()
        expect(popup.locator('[data-access="verify-status"]')).to_have_text("Credential verification rejected the proof.")

        popup.evaluate("([key, value]) => sessionStorage.setItem(key, JSON.stringify(value))", [handoff_key, handoff])
        popup.reload()
        token_input.fill(verifier)
        token_input.press("Enter")
        expect(popup.locator('[data-access="handoff"]')).to_be_visible()
        expect(popup.locator('[data-access="input"]')).to_have_value("")
        expect(popup.locator('[data-access="verify"]')).to_be_disabled()
        popup.close()

        picker.select_option("eudi-pid-sd-jwt")
        popup = open_demo(presets["eudi-pid-sd-jwt"])
        token_input = popup.locator('[data-access="token"]')
        token_input.fill(verifier)
        token_input.press("Enter")
        expect(popup.locator('[data-access="endpoint-status"]')).to_contain_text("unavailable")
        expect(popup.locator('[data-access="endpoint"]')).to_have_value("")
        expect(popup.locator('[data-access="verify"]')).to_be_disabled()
        popup.close()

        path = presets["eudi-pid-sd-jwt"]
        popup = open_demo(path)
        token_input = popup.locator('[data-access="token"]')
        token_input.fill(admin)
        token_input.press("Enter")
        expect(popup.locator("#guard-endpoint-picker")).to_have_value(path)
        expect(popup.locator("#guard-data")).to_have_value(demos[path]["credentialExamples"]["valid"])
        popup.close()
    finally:
        page.context.remove_listener("request", collect_posts)
        page.evaluate("key => sessionStorage.removeItem(key)", handoff_key)
        server.access_policy = None
        server.guard = previous_guard


def verify_protected_examples(page, address, work, server):
    verifier, admin = (secrets.token_urlsafe(32) for _ in range(2))
    config = work / "access.json"
    config.write_text(json.dumps({"version": 1, "principals": [
        {"id": identity, "role": role, "endpoints": endpoints,
         "tokenSha256": hashlib.sha256(token.encode("ascii")).hexdigest()}
        for identity, role, endpoints, token in (
            ("review-verifier", "verifier", ["/verify"], verifier), ("review-admin", "admin", ["*"], admin),
        )
    ]}))
    config.chmod(0o600)
    server.access_policy = AccessPolicy.load(config)
    page.goto(address + "/apps/builder/?example=eudi-pid-sd-jwt")
    token_input = page.locator("#builder-sample-token")
    expect(token_input).to_be_visible()
    page.locator("#builder-sample-run").click()
    expect(page.locator("#builder-sample-message")).to_contain_text("access token")
    for token, result in ((verifier, "HTTP 403"), (admin, "HTTP 200 · true")):
        token_input.fill(token)
        page.locator("#builder-sample-run").click()
        expect(page.locator("#builder-sample-response")).to_have_text(result)
        expect(token_input).to_have_value("")
    token_input.fill(admin)
    page.locator("#builder-sample-clear-token").click()
    expect(token_input).to_have_value("")
    token_input.fill(admin)
    picker = page.locator("#builder-preset")
    picker.select_option("status")
    expect(token_input).to_be_hidden()
    expect(token_input).to_have_value("")
    picker.select_option("eudi-pid-sd-jwt")
    token_input.fill(admin)
    page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))")
    expect(token_input).to_have_value("")
    storage = page.evaluate("JSON.stringify([Object.entries(localStorage), Object.entries(sessionStorage)])")
    assert verifier not in storage and admin not in storage


def verify_lab(page, address, language):
    fixtures = sorted((ROOT / "examples").glob("[0-9][0-9]-*.json"))
    assert len(fixtures) == 10
    page.goto(address + "/apps/lab/")
    page.locator("select[data-language]").select_option(language)
    expect(page.locator("html")).to_have_attribute("lang", language)
    outgoing_posts = []
    page.on("request", lambda req: outgoing_posts.append(req.url) if req.method == "POST" else None)
    count = 0
    for fixture in fixtures:
        example = json.loads(fixture.read_bytes())
        page.goto(f"{address}/apps/lab/#{example['id']}")
        buttons = page.locator("#cases-panel .case-button")
        expect(buttons).to_have_count(len(example["cases"]))
        for index, case in enumerate(example["cases"]):
            buttons.nth(index).click()
            expect(buttons.nth(index)).to_have_attribute("aria-pressed", "true")
            badge = page.locator("#result-panel .subhead").first.locator(".badge")
            if case["expected"]["valid"]:
                expect(badge).to_have_attribute("data-state", "pass")
            else:
                assert badge.get_attribute("data-state") in {"fail", "skip"}, case["id"]
            preview = page.locator("#result-panel pre").inner_text()
            if "response" in case["expected"]:
                assert json.loads(preview) == case["expected"]["response"], case["id"]
            count += 1
    assert not outgoing_posts, outgoing_posts
    return count


def verify_edited_lab(page, address):
    page.goto(f"{address}/apps/lab/#01-two-of-three")
    page.locator("select[data-language]").select_option("de")
    result = page.locator("#result-panel")
    expect(result).to_contain_text("Die dritte Signatur ist optional.")
    threshold = page.get_by_role("spinbutton", name="Sollwert")
    threshold.fill("3")
    threshold.press("Tab")
    expect(result.locator(".subhead .badge").first).to_have_attribute("data-state", "fail")
    expect(result).to_contain_text("Der aktuelle Entwurf erfüllt 0 von 1 Bedingungen.")
    expect(result).not_to_contain_text("Die dritte Signatur ist optional.")
    expect(result).to_contain_text("Ist 2 · Soll mindestens 3")

    page.locator("select[data-language]").select_option("en")
    expect(result).to_contain_text("The current draft meets 0 of 1 conditions.")
    expect(result).not_to_contain_text("The third signature is optional.")
    export = page.get_by_role("button", name="Export Lab scenario")
    expect(export).to_have_accessible_description("The export contains a Lab scenario. The live Guard uses rules in the Basic Guard profile.")
    with page.expect_download() as download:
        export.click()
    payload = json.loads(Path(download.value.path()).read_bytes())
    assert payload["odrl"]["permission"][0]["constraint"][0]["rightOperand"] == 3
    assert "cases" not in payload

    page.locator("#reset-rule").click()
    expect(result.locator(".subhead .badge").first).to_have_attribute("data-state", "pass")
    expect(result).to_contain_text("The third signature is optional.")


def verify_app_navigation(page, address):
    paths = ("/apps/", "/apps/guard/", "/apps/builder/", "/apps/lab/", "/apps/api-docs/")
    for width in (1280, 390):
        page.set_viewport_size({"width": width, "height": 844})
        for language, landmark, overview, lab in (
            ("de", "Anwendungen", "Übersicht", "Prüflabor"),
            ("en", "Applications", "Overview", "Verification Lab"),
        ):
            page.goto(address + paths[0])
            page.locator("select[data-language]").select_option(language)
            labels = (overview, "Guard", "Credential Builder", lab, "Swagger UI")
            for index, path in enumerate(paths):
                if path == "/apps/lab/":
                    expect(page).to_have_url(re.compile(re.escape(address + path) + r"(?:#01-two-of-three)?$"))
                else:
                    expect(page).to_have_url(address + path)
                expect(page.locator("html")).to_have_attribute("lang", language)
                nav = page.get_by_role("navigation", name=landmark)
                expect(nav.locator('a[href^="/apps/"]')).to_have_text(list(labels))
                expect(nav.locator('[aria-current="page"]')).to_have_attribute("href", path)
                assert page.evaluate("document.documentElement.scrollWidth") == width
                target = nav.get_by_role("link", name=labels[(index + 1) % len(labels)])
                target.press("Enter")
            expect(page).to_have_url(address + paths[0])


def verify_narrow_navigation(page, address):
    page.set_viewport_size({"width": 320, "height": 844})
    page.goto(address + "/apps/")
    for language in ("de", "en"):
        page.locator("select[data-language]").select_option(language)
        assert page.evaluate("document.documentElement.scrollWidth") == 320, language
    page.locator('main a[href="/apps/lab/"]').click()
    expect(page.locator("#export-rule")).to_be_enabled()
    for language in ("de", "en"):
        page.locator("select[data-language]").select_option(language)
        assert page.evaluate("document.documentElement.scrollWidth") == 320, language
        export = page.locator("#export-rule").bounding_box()
        assert export is not None and export["x"] + export["width"] <= 320, language
    example_url = address + "/apps/lab/#03-wallet-presentation"
    page.goto(example_url)
    expect(page.locator("#rule-title")).to_have_text("Fresh wallet presentation")
    skip_link = page.get_by_role("link", name="Skip to verification lab")
    skip_link.focus()
    skip_link.press("Enter")
    expect(page.locator("#workspace")).to_be_focused()
    expect(page).to_have_url(example_url)


def verify_mobile_lab_selection(page, address):
    page.set_viewport_size({"width": 390, "height": 844})
    for language, example_label, title in (
        ("de", "Beispiel auswählen", "Zugelassener DIDComm-Endpunkt"),
        ("en", "Choose an example", "Approved DIDComm endpoint"),
    ):
        page.goto(address + "/apps/lab/")
        page.locator("select[data-language]").select_option(language)
        examples = page.get_by_role("navigation", name=example_label)
        buttons = examples.get_by_role("button")
        expect(buttons).to_have_count(10)
        assert examples.evaluate("element => element.scrollWidth === element.clientWidth")
        for button in buttons.all():
            rect = button.bounding_box()
            assert rect["height"] >= 44
            assert rect["y"] + rect["height"] <= 844
        buttons.nth(8).focus()
        page.keyboard.press("Tab")
        expect(buttons.last).to_be_focused()
        page.keyboard.press("Enter")
        expect(page.locator("#rule-title")).to_have_text(title)
        expect(buttons.last).to_have_attribute("aria-current", "true")
        expect(buttons.last).to_be_focused()

        cases = page.locator("#cases-panel .case-button")
        cases.first.focus()
        page.keyboard.press("Tab")
        expect(cases.nth(1)).to_be_focused()
        page.keyboard.press("Space")
        expect(cases.nth(1)).to_have_attribute("aria-pressed", "true")
        expect(cases.nth(1)).to_be_focused()


def main():
    with tempfile.TemporaryDirectory(prefix="proofsieve-workspace-browser-") as directory:
        work = Path(directory)
        with LoopbackHTTPServer(("127.0.0.1", 0), Handler) as server:
            server.guard = Guard(work / "rules.json", {})
            server.credential_examples, server.credential_checks = load_credential_examples(ROOT / "examples" / "credentials")
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                address = f"http://127.0.0.1:{server.server_port}"
                with sync_playwright() as playwright, playwright.chromium.launch() as browser:
                    page = browser.new_page(viewport={"width": 390, "height": 844})
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    pending_page = browser.new_page(viewport={"width": 390, "height": 844})
                    pending_page.on("pageerror", lambda error: errors.append(str(error)))
                    verify_pending_template_values(pending_page, address)
                    pending_page.close()
                    verify_handoffs(page, address)
                    verify_saved_draft_deletion(page, address)
                    verify_builder_claims(page, address)
                    verify_builder_file_races(page, address)
                    sources = verify_sourced_examples(page, address, server.credential_examples)
                    cases = sum(verify_lab(page, address, language) for language in ("de", "en"))
                    verify_edited_lab(page, address)
                    verify_signed_demo_links(page, address, work, server)
                    verify_protected_examples(page, address, work, server)
                    verify_app_navigation(page, address)
                    verify_narrow_navigation(page, address)
                    verify_mobile_lab_selection(page, address)
                    assert not errors, errors
            finally:
                server.shutdown()
                worker.join()
    print(f"Workspace browser acceptance passed: JSON and Turtle handoff, draft and file round-trip, "
          "pending template resolution, lossless Builder claims, strict server rejection and file import ordering, "
          f"{sources} live sourced-example checks, {cases} synthetic Lab case runs across DE and EN, "
          "signed Guard demo links, edited Lab threshold explanations and export, bilingual application navigation, "
          "and keyboard selection of Lab examples and cases on mobile.")


if __name__ == "__main__":
    main()
