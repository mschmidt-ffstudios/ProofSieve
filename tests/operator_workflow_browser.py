"""Exercise the signed supplier rule workflow or prepare it for a human operator."""

import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from cryptography.hazmat.primitives.asymmetric import ec

from examples.company.run import ENDPOINT, ISSUER, configure, issue
from tests.test_http_security import serve


def verify_operator(browser, address, allowed, denied):
    from playwright.sync_api import expect

    with browser.new_context(locale="de-DE") as context:
        page = context.new_page()
        started = time.monotonic()
        page.goto(address + "/apps/guard/")
        page.locator("#guard-endpoint-picker").select_option(ENDPOINT)
        expect(page.locator("#guard-credential")).to_be_visible()
        page.locator("#guard-load-template").click()
        page.locator("#guard-mode").select_option("boolean")
        page.locator("#guard-graph [data-kind='condition']").click()
        fields = page.locator("#guard-graph form.odrl-fields")
        fields.get_by_label("Feld", exact=True).fill("supplier_status")
        fields.get_by_label("Sollwert (JSON)").fill('"active"')
        fields.get_by_role("button", name="Bedingung übernehmen").click()
        with page.expect_response(lambda response: response.request.method == "PUT"
                                  and "/admin/rule?" in response.url) as saved:
            page.locator("#guard-save").click()
        assert saved.value.status == 200
        rule = saved.value.json()["rule"]
        assert rule["credential"]["issuer"] == ISSUER and rule["responseMode"] == "boolean"
        assert rule["policy"]["permission"][0]["constraint"] == [
            {"leftOperand": "field:supplier_status", "operator": "eq", "rightOperand": "active"},
        ]

        for credential, result in ((allowed, "true"), (denied, "false")):
            page.locator("#guard-data").fill(credential)
            with page.expect_response(lambda response: response.request.method == "POST"
                                      and response.url == address + ENDPOINT) as verified:
                page.locator("#guard-verify").click()
            assert verified.value.status == 200 and verified.value.json() is (result == "true")
            expect(page.locator("#guard-response")).to_have_text(result)
        print(f"Signed rule workflow passed in Chromium in {time.monotonic() - started:.1f}s.")


def manual(address, allowed, denied):
    with TemporaryDirectory(prefix="proofsieve-operator-") as directory:
        fixtures = Path(directory)
        (fixtures / "active.sd-jwt").write_text(allowed, encoding="ascii")
        (fixtures / "inactive.sd-jwt").write_text(denied, encoding="ascii")
        print(f"Open {address}/apps/guard/")
        print(f"Prepared endpoint {ENDPOINT} trusts {ISSUER}.")
        print(f"Signed test inputs are in {fixtures}.")
        try:
            input("Press Enter to close the temporary test environment.\n")
        except KeyboardInterrupt:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual", action="store_true", help="Keep the synthetic fixture and local Guard open for an operator")
    args = parser.parse_args()
    key = ec.generate_private_key(ec.SECP256R1())
    with serve() as server:
        address = f"http://127.0.0.1:{server.server_port}"
        configure(server.server_port, key)
        allowed = issue(key, supplier_status="active", expires_in=900)
        denied = issue(key, supplier_status="inactive", expires_in=900)
        if args.manual:
            manual(address, allowed, denied)
        else:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as playwright, playwright.chromium.launch() as browser:
                verify_operator(browser, address, allowed, denied)


if __name__ == "__main__":
    main()
