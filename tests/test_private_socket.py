import os
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path

from proofsieve.server import Handler, LoopbackHTTPServer
from proofsieve.unix_socket import open_private_socket


@unittest.skipUnless(hasattr(socket, "AF_UNIX") and hasattr(os, "geteuid"), "Requires Unix sockets")
class PrivateSocketTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="ps-socket-", dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.path = self.directory / "guard.sock"

    def request(self, host):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(3)
            client.connect(os.fspath(self.path))
            client.sendall(f"GET /apps/ HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            with client.makefile("rb") as response:
                return response.readline(), response.read()

    def test_http_over_private_socket(self):
        with open_private_socket(LoopbackHTTPServer, self.path, 24180, Handler) as server:
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            worker.start()
            try:
                status, response = self.request("127.0.0.1:24180")
                self.assertIn(b"200", status)
                self.assertIn(b"ProofSieve", response)
                self.assertIn(b"403", self.request("127.0.0.1:4180")[0])
            finally:
                server.shutdown()
                worker.join()
        self.assertFalse(self.path.exists())

    def test_rejects_nonprivate_directory_and_leaves_existing_path(self):
        self.directory.chmod(0o755)
        with self.assertRaises(ValueError), open_private_socket(LoopbackHTTPServer, self.path, 24180, Handler):
            self.fail("A shared socket directory must be rejected")
        self.directory.chmod(0o700)
        self.path.write_text("existing path", encoding="utf-8")
        with self.assertRaises(OSError), open_private_socket(LoopbackHTTPServer, self.path, 24180, Handler):
            self.fail("An existing path must be preserved")
        self.assertEqual(self.path.read_text(encoding="utf-8"), "existing path")

    def test_proxy_group_is_explicit_and_uses_a_traverse_only_directory(self):
        group = self.directory.stat().st_gid
        with self.assertRaises(ValueError), open_private_socket(
            LoopbackHTTPServer, self.path, 24180, Handler, proxy_gid=group,
        ):
            self.fail("An ingress group must use a separate group-traversable directory")
        self.directory.chmod(0o710)
        with open_private_socket(LoopbackHTTPServer, self.path, 24180, Handler, proxy_gid=group):
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o660)
            self.assertEqual(self.path.stat().st_gid, group)
