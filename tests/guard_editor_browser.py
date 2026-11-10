"""Run Guard editor conflict and draft-preservation checks in Chromium."""

from playwright.sync_api import expect, sync_playwright

from tests.test_http_security import serve


def verify_editor(browser, address):
    with browser.new_context() as context:
        first, second = context.new_page(), context.new_page()
        for page in (first, second):
            page.goto(address + "/apps/guard/")
            expect(page.locator("#guard-save")).to_be_enabled()
            page.locator("#guard-raw > summary").click()

        policy = first.locator("#guard-policy")
        original = policy.input_value()
        tightened = original.replace('"active"', '"locked"')
        assert original != tightened
        policy.fill(tightened)
        first.locator("#guard-data").fill('{"status":"blocked"}')
        first.once("dialog", lambda dialog: dialog.dismiss())
        first.locator("#guard-load-template").click()
        expect(policy).to_have_value(tightened)
        expect(first.locator("#guard-data")).to_have_value('{"status":"blocked"}')

        policy.fill(original)
        first.once("dialog", lambda dialog: dialog.dismiss())
        first.locator("#guard-load-template").click()
        expect(first.locator("#guard-data")).to_have_value('{"status":"blocked"}')

        policy.fill(tightened)
        first.locator("#guard-save").click()
        expect(first.locator("#guard-status")).to_have_attribute("data-state", "success")

        second.locator("#guard-mode").select_option("guard")
        with second.expect_response(lambda response: response.request.method == "PUT") as response:
            second.locator("#guard-save").click()
        assert response.value.status == 412
        expect(second.locator("#guard-mode")).to_have_value("guard")
        expect(second.locator("#guard-verify")).to_be_disabled()
        expect(second.locator("#guard-reload-rule")).to_be_visible()
        second.once("dialog", lambda dialog: dialog.accept())
        second.locator("#guard-reload-rule").click()
        expect(second.locator("#guard-reload-rule")).to_be_hidden()
        expect(second.locator("#guard-mode")).to_have_value("boolean")
        expect(second.locator("#guard-policy")).to_have_value(tightened)
        second.locator("#guard-verify").click()
        expect(second.locator("#guard-response")).to_have_text("false")

        first.goto(address + "/apps/guard/?example=nested")
        endpoint = first.locator("#guard-endpoint")
        endpoint.fill("/verify/unsaved")
        builder = first.locator('header a[href="/apps/builder/"]')
        dialogs = []
        def dismiss_navigation(dialog):
            dialogs.append(dialog.message)
            dialog.dismiss()
        first.once("dialog", dismiss_navigation)
        builder.click()
        assert len(dialogs) == 1
        expect(endpoint).to_have_value("/verify/unsaved")
        first.once("dialog", lambda dialog: dialog.accept())
        builder.click()
        expect(first).to_have_url(address + "/apps/builder/")


def verify_graph_and_stale_verification(browser, address):
    with browser.new_context() as context:
        page = context.new_page()
        page.goto(address + "/apps/guard/")
        stale = context.new_page()
        stale.goto(address + "/apps/guard/")
        stale_verify = stale.locator("#guard-verify")
        expect(stale_verify).to_be_enabled()
        verify = page.locator("#guard-verify")
        save = page.locator("#guard-save")
        expect(verify).to_be_enabled()
        page.locator('.odrl-node[data-kind="condition"]').click()
        page.get_by_label("Sollwert (JSON)").fill('"locked"')
        expect(verify).to_be_disabled()
        expect(save).to_be_disabled()
        expect(page.locator("#guard-test-rule")).to_be_disabled()

        page.locator("select[data-language]").select_option("en")
        value = page.get_by_label("Expected value (JSON)")
        expect(value).to_have_value('"locked"')
        page.once("dialog", lambda dialog: dialog.dismiss())
        page.locator('.odrl-node[data-kind="permission"]').click()
        expect(value).to_have_value('"locked"')
        page.get_by_role("button", name="Discard changes").click()
        expect(value).to_have_value('"active"')
        expect(verify).to_be_enabled()

        value.fill('"locked"')
        page.get_by_role("button", name="Apply condition").click()
        expect(save).to_be_enabled()
        expect(verify).to_be_disabled()
        save.click()
        expect(verify).to_be_enabled()
        verify.click()
        expect(page.locator("#guard-response")).to_have_text("false")

        stale.locator("#guard-data").fill('{"status":"locked"}')
        with stale.expect_response(lambda response: response.request.method == "POST") as stale_reply:
            stale_verify.click()
        assert stale_reply.value.status == 412
        assert stale_reply.value.json()["code"] == "rule_version_conflict"
        expect(stale_verify).to_be_disabled()
        expect(stale.locator("#guard-reload-rule")).to_be_visible()
        stale.locator("#guard-data").fill('{"status":"active"}')
        expect(stale.locator("#guard-status")).to_have_attribute("data-state", "error")
        stale.once("dialog", lambda dialog: dialog.accept())
        stale.locator("#guard-reload-rule").click()
        expect(stale_verify).to_be_enabled()
        stale.locator("#guard-data").fill('{"status":"locked"}')
        stale_verify.click()
        expect(stale.locator("#guard-response")).to_have_text("true")


def main():
    with sync_playwright() as playwright, playwright.chromium.launch() as browser:
        with serve() as server:
            verify_editor(browser, f"http://127.0.0.1:{server.server_port}")
        with serve() as server:
            verify_graph_and_stale_verification(browser, f"http://127.0.0.1:{server.server_port}")
    print("Guard editor acceptance passed: template confirmation, stale-save conflict, rule reload, "
          "unsaved navigation, unapplied condition handling and stale verification.")


if __name__ == "__main__":
    main()
