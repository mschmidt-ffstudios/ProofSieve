import http.client
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stderr
from copy import deepcopy
from pathlib import Path

from proofsieve.guard import DEFAULT_RULE, Guard
from proofsieve.server import MAX_HEADER_BYTES, MAX_REQUEST_TARGET_BYTES, Handler, LoopbackHTTPServer


@contextmanager
def serve(*, timeout=2, max_connections=16, entered=None):
    class TestHandler(Handler):
        def setup(self):
            super().setup()
            if entered is not None:
                entered.set()

    TestHandler.timeout = timeout
    with tempfile.TemporaryDirectory() as directory:
        with LoopbackHTTPServer(("127.0.0.1", 0), TestHandler, max_connections=max_connections) as server:
            server.guard = Guard(Path(directory) / "rule.json", {})
            server.credential_examples = []
            server.credential_checks = {}
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            worker.start()
            try:
                yield server
            finally:
                server.shutdown()
                worker.join()


def connect(server):
    return socket.create_connection(server.server_address, timeout=2)


def read_response(connection):
    with http.client.HTTPResponse(connection) as response:
        response.begin()
        return response.status, dict(response.getheaders()), response.read()


class HTTPSecurityTest(unittest.TestCase):
    def setUp(self):
        server = serve()
        self.server = server.__enter__()
        self.addCleanup(server.__exit__, None, None, None)
        self.host = f"127.0.0.1:{self.server.server_port}"

    def request(self, line, headers=(), body=b"", *, add_host=True):
        if add_host:
            headers = (f"Host: {self.host}", *headers)
        request = "\r\n".join((line, *headers, "", "")).encode("ascii") + body
        with connect(self.server) as connection:
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            return read_response(connection)

    def post(self, endpoint="/verify", headers=()):
        body = b'{"data":{"status":"active"}}'
        return self.request(
            f"POST {endpoint} HTTP/1.1",
            ("Content-Type: application/json", f"Content-Length: {len(body)}", *headers),
            body,
        )

    def test_local_browser_and_cli_requests_keep_working(self):
        status, headers, body = self.request("GET / HTTP/1.1")
        self.assertEqual((status, headers["Location"], headers["Connection"], body), (303, "/apps/", "close", b""))
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.request("GET /apps/guard/?endpoint=/verify/demo/eudi-mdoc HTTP/1.1")[0], 200)
        self.assertEqual(
            self.request("GET /admin/rule?endpoint=%2Fverify HTTP/1.1", (f"Origin: http://{self.host}",))[0], 200,
        )
        status, _, body = self.post(headers=(f"Origin: http://{self.host}", "Sec-Fetch-Site: same-origin"))
        self.assertEqual((status, json.loads(body)), (200, True))

    def test_browser_documents_restrict_plugins_forms_and_openers(self):
        for path in ("/apps/", "/apps/builder/", "/apps/guard/", "/apps/lab/", "/apps/api-docs/"):
            with self.subTest(path=path):
                status, headers, _ = self.request(f"GET {path} HTTP/1.1")
                self.assertEqual(status, 200)
                self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
                directives = headers["Content-Security-Policy"].split("; ")
                self.assertIn("object-src 'none'", directives)
                self.assertIn("form-action 'self'", directives)
                self.assertIn("frame-ancestors 'none'", directives)
                self.assertIn("base-uri 'none'", directives)
                self.assertEqual(headers["Referrer-Policy"], "no-referrer")
                self.assertEqual(headers["Cache-Control"], "no-store")

    def test_ambiguous_or_foreign_host_and_origin_are_rejected(self):
        cases = [
            (f"Host: {self.host}",),
            ("Host: other.example",),
            (f"Origin: http://{self.host}", f"Origin: http://{self.host}"),
            ("Origin: https://other.example",),
            ("Sec-Fetch-Site: same-origin", "Sec-Fetch-Site: cross-site"),
        ]
        for headers in cases:
            with self.subTest(headers=headers):
                self.assertEqual(self.request("GET /admin/rule HTTP/1.1", headers)[0], 403)
                self.assertEqual(self.post(headers=headers)[0], 403)
        self.assertEqual(self.request("GET /apps/ HTTP/1.1", add_host=False)[0], 403)
        self.assertEqual(self.request("GET /apps/ HTTP/1.1", ("Host: other.example",), add_host=False)[0], 403)

    def test_request_target_is_never_normalized_for_dispatch(self):
        for target in (
            "//admin/rule", "/apps//guard/", "/apps/../admin/rule", "/./admin/rule", "/%61dmin/rule",
            "/admin/rule#fragment", "/admin/rule?endpoint=%xy", f"http://{self.host}/admin/rule",
        ):
            with self.subTest(target=target):
                self.assertEqual(self.request(f"GET {target} HTTP/1.1")[0], 400)
        self.assertEqual(self.request("GET  /admin/rule HTTP/1.1")[0], 400)
        self.assertEqual(self.request("GET\t /admin/rule HTTP/1.1")[0], 400)
        self.assertEqual(self.request("GET /admin/rule HTTP/1.1\t")[0], 400)
        self.assertEqual(self.request("GET /admin/rule")[0], 400)

    def test_ambiguous_framing_and_header_folding_are_rejected(self):
        for header in ("Transfer-Encoding: chunked", "Transfer-Encoding:", "Content-Length: 0", "Expect: 100-continue"):
            with self.subTest(header=header):
                self.assertEqual(self.post(headers=(header,))[0], 400)
        self.assertEqual(self.post(headers=("Content-Type: application/json",))[0], 400)
        self.assertEqual(self.post(headers=("X-Example: test\r\n continuation",))[0], 400)
        self.assertEqual(self.post(headers=("X-Example: test\v",))[0], 400)
        self.assertEqual(self.post(headers=("Transfer-Encoding : chunked",))[0], 400)
        self.assertEqual(self.request("GET /apps/ HTTP/1.1", ("Content-Length: 1",), b"x")[0], 400)
        self.assertEqual(self.request("GET /apps/ HTTP/1.1", ("Transfer-Encoding:",))[0], 400)
        self.assertEqual(self.request("POST /verify HTTP/1.1", ("Content-Type: application/json",))[0], 400)
        self.assertEqual(
            self.request("POST /verify HTTP/1.1", ("Content-Type: application/json", "Content-Length: 10"), b"{}")[0],
            400,
        )

    def test_editor_token_must_be_unambiguous(self):
        body = json.dumps({"rule": DEFAULT_RULE, "data": {"status": "active"}}).encode()
        token = f"X-ProofSieve-Token: {self.server.guard.token}"
        headers = ("Content-Type: application/json", f"Content-Length: {len(body)}", token)
        self.assertEqual(self.request("POST /admin/test-rule HTTP/1.1", headers, body)[0], 200)
        self.assertEqual(self.request("POST /admin/test-rule HTTP/1.1", (*headers, token), body)[0], 403)

    def test_rule_preview_rejects_non_object_rules_as_bad_requests(self):
        for rule in (None, True, 1, [], "rule"):
            with self.subTest(rule=rule):
                body = json.dumps({"rule": rule, "data": {"status": "active"}}).encode()
                headers = ("Content-Type: application/json", f"Content-Length: {len(body)}",
                           f"X-ProofSieve-Token: {self.server.guard.token}")
                status, _, response = self.request("POST /admin/test-rule HTTP/1.1", headers, body)
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(response))

    def test_stale_rule_edit_preserves_the_newer_policy(self):
        endpoint = "/admin/rule?endpoint=/verify"
        status, headers, body = self.request(f"GET {endpoint} HTTP/1.1")
        self.assertEqual(status, 200)
        original = json.loads(body)
        etag = headers["ETag"]
        self.assertRegex(etag, r'^"[0-9a-f]{64}"$')

        def save(rule, conditions):
            body = json.dumps(rule).encode()
            return self.request(f"PUT {endpoint} HTTP/1.1", (
                "Content-Type: application/json", f"Content-Length: {len(body)}",
                f"X-ProofSieve-Token: {original['csrfToken']}", *conditions,
            ), body)

        tightened = deepcopy(original["rule"])
        tightened["policy"]["permission"][0]["constraint"][0]["rightOperand"] = "locked"
        status, headers, _ = save(tightened, (f"If-Match: {etag}",))
        self.assertEqual(status, 200)
        new_etag = headers["ETag"]
        self.assertNotEqual(new_etag, etag)

        stale = {**original["rule"], "responseMode": "guard"}
        status, _, body = save(stale, (f"If-Match: {etag}",))
        self.assertEqual((status, json.loads(body)["code"]), (412, "rule_version_conflict"))
        status, _, body = self.post(headers=(f"If-Match: {etag}",))
        self.assertEqual((status, json.loads(body)["code"]), (412, "rule_version_conflict"))
        status, _, body = self.post(headers=(f"If-Match: {new_etag}",))
        self.assertEqual((status, json.loads(body)), (200, False))
        self.assertIs(json.loads(self.post()[2]), False)
        self.assertEqual(self.request(f"GET {endpoint} HTTP/1.1")[1]["ETag"], new_etag)

        for conditions in (
            (f"If-Match: W/{new_etag}",),
            (f"If-Match: {new_etag}", f"If-Match: {new_etag}"),
            (f"If-Match: {new_etag}", "If-None-Match: *"),
        ):
            with self.subTest(conditions=conditions):
                self.assertEqual(save(stale, conditions)[0], 400)
        for conditions in ((f"If-Match: W/{new_etag}",), (f"If-Match: {new_etag}", f"If-Match: {new_etag}")):
            with self.subTest(conditions=conditions):
                self.assertEqual(self.post(headers=conditions)[0], 400)

    def test_malformed_turtle_is_sanitized_at_the_http_boundary(self):
        policy = """@prefix sh: <http://www.w3.org/ns/shacl#> .
<urn:test:shape> sh:targetNode <urn:test:request> ;
    sh:path <urn:test:status> ; sh:hasValue "active" ."""
        self.server.guard.update({"language": "shacl", "policy": policy, "responseMode": "boolean"}, "/verify/turtle")

        def verify(turtle):
            body = json.dumps({"data": turtle}).encode()
            return self.request("POST /verify/turtle HTTP/1.1", (
                "Content-Type: application/json", f"Content-Length: {len(body)}",
            ), body)

        status, _, body = verify('<urn:test:request> <urn:test:status> "active" .')
        self.assertEqual((status, json.loads(body)), (200, True))
        with redirect_stderr(io.StringIO()) as stderr:
            for turtle in ('<a> <b> "SYNTH42', '?a <b> <c> .'):
                with self.subTest(turtle=turtle):
                    status, _, body = verify(turtle)
                    self.assertEqual(status, 400)
                    self.assertEqual(json.loads(body), {"error": "RDF data is invalid or outside the supported Turtle limits"})
        self.assertEqual(stderr.getvalue(), "")

    def test_method_and_aggregate_header_limits(self):
        status, headers, _ = self.request("DELETE /admin/rule HTTP/1.1")
        self.assertEqual(status, 405)
        self.assertEqual(headers["Allow"], "GET, POST, PUT")
        target = "/?" + "x" * MAX_REQUEST_TARGET_BYTES
        self.assertEqual(self.request(f"GET {target} HTTP/1.1")[0], 414)
        padding = "x" * (MAX_HEADER_BYTES // 2)
        self.assertEqual(self.request("GET /apps/ HTTP/1.1", (f"X-One: {padding}", f"X-Two: {padding}"))[0], 431)

    def test_absolute_read_deadline_covers_idle_and_trickle_connections(self):
        with serve(timeout=0.25) as server:
            with connect(server) as idle:
                self.assertEqual(idle.recv(1), b"")
            with connect(server) as trickle:
                trickle.sendall(b"GET /apps/ HTTP/1.1\r\n")
                for _ in range(5):
                    time.sleep(0.06)
                    try:
                        trickle.sendall(b"x")
                    except (BrokenPipeError, ConnectionResetError):
                        break
                try:
                    self.assertEqual(trickle.recv(1), b"")
                except ConnectionResetError:
                    pass

    def test_connections_are_bounded_before_request_processing(self):
        entered = threading.Event()
        with serve(max_connections=1, entered=entered) as server:
            with connect(server) as first:
                self.assertTrue(entered.wait(timeout=1))
                with connect(server) as surplus:
                    self.assertEqual(surplus.recv(1), b"")
                first.sendall(f"GET /apps/ HTTP/1.1\r\nHost: localhost:{server.server_port}\r\n\r\n".encode())
                self.assertEqual(read_response(first)[0], 200)
