import hashlib
import json
import os
import secrets
import unittest
from copy import deepcopy
from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from proofsieve.access import MAX_CONFIG_BYTES, MAX_GRANTS, MAX_PRINCIPALS, AccessPolicy


def digest(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def headers(*values):
    message = Message()
    for value in values:
        message.add_header("Authorization", value)
    return message


class AccessPolicyTest(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "access.json"
        self.admin = secrets.token_urlsafe(32)
        self.scoped_admin = secrets.token_urlsafe(32)
        self.verifier = secrets.token_urlsafe(32)
        self.config = {
            "version": 1,
            "principals": [
                {"id": "operator", "role": "admin", "tokenSha256": digest(self.admin), "endpoints": ["*"]},
                {"id": "mdoc-admin", "role": "admin", "tokenSha256": digest(self.scoped_admin),
                 "endpoints": ["/verify/demo/eudi-mdoc"]},
                {"id": "reader", "role": "verifier", "tokenSha256": digest(self.verifier),
                 "endpoints": ["/verify", "/verify/demo/eudi-sd-jwt"]},
            ],
        }

    def write_raw(self, data):
        self.path.write_bytes(data)
        self.path.chmod(0o600)

    def load(self, config=None):
        self.write_raw(json.dumps(self.config if config is None else config).encode())
        return AccessPolicy.load(self.path)

    def test_separate_roles_have_exact_grants(self):
        policy = self.load()
        admin = policy.authenticate(headers(f"Bearer {self.admin}"))
        self.assertEqual((admin.id, admin.role, admin.endpoints), ("operator", "admin", ("*",)))
        self.assertTrue(admin.allows("/verify/a-new-route"))
        self.assertFalse(admin.allows("/admin/rule"))
        scoped = policy.authenticate(headers(f"Bearer {self.scoped_admin}"))
        self.assertEqual(scoped.role, "admin")
        self.assertTrue(scoped.allows("/verify/demo/eudi-mdoc"))
        self.assertFalse(scoped.allows("/verify/demo/eudi-mdoc/subpath"))
        reader = policy.authenticate(headers(f"bearer {self.verifier}"))
        self.assertEqual(reader.role, "verifier")
        self.assertTrue(reader.allows("/verify/demo/eudi-sd-jwt"))
        self.assertTrue(reader.allows("/verify"))
        self.assertFalse(reader.allows("/verify/demo/eudi-mdoc"))

    def test_invalid_bearer_and_duplicate_authorization_fail(self):
        policy = self.load()
        valid = f"Bearer {self.verifier}"
        for values in (
            (), ("",), (f"Basic {self.verifier}",), (f"Bearer {secrets.token_urlsafe(32)}",),
            (valid + "=",), (valid + ", " + valid,), (valid, valid),
            (f"Bearer\t{self.verifier}",), (valid + " ",),
        ):
            with self.subTest(number_of_headers=len(values)):
                self.assertIsNone(policy.authenticate(headers(*values)))

    def test_token_must_be_canonically_encoded(self):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        noncanonical = self.verifier[:-1] + alphabet[alphabet.index(self.verifier[-1]) + 1]
        self.config["principals"][2]["tokenSha256"] = digest(noncanonical)
        self.assertIsNone(self.load().authenticate(headers(f"Bearer {noncanonical}")))

    def test_policy_rejects_duplicate_id_or_digest(self):
        for field in ("id", "tokenSha256"):
            with self.subTest(field=field):
                config = deepcopy(self.config)
                config["principals"][1][field] = config["principals"][0][field]
                with self.assertRaises(ValueError):
                    self.load(config)

    def test_policy_rejects_malformed_grants_and_roles(self):
        for index, key, value in (
            (0, "endpoints", ["*", "/verify"]), (2, "endpoints", ["*"]), (2, "endpoints", []),
            (2, "endpoints", ["/verify", "/verify"]), (2, "endpoints", ["/verify/../admin"]),
            (2, "endpoints", ["/verify?endpoint=private"]),
            (2, "endpoints", [f"/verify/{i}" for i in range(MAX_GRANTS + 1)]),
            (2, "role", "operator"), (2, "tokenSha256", self.verifier),
            (2, "tokenSha256", "A" * 64), (2, "id", "reader\n"),
        ):
            with self.subTest(field=key):
                config = deepcopy(self.config)
                config["principals"][index][key] = value
                with self.assertRaises(ValueError):
                    self.load(config)

    def test_policy_rejects_missing_admin_and_inexact_top_level_schema(self):
        for config in (
            {"version": 1, "principals": self.config["principals"][2:]},
            {**self.config, "version": True}, {**self.config, "other": None},
            {**self.config, "principals": self.config["principals"][:1] * (MAX_PRINCIPALS + 1)},
        ):
            with self.assertRaises(ValueError):
                self.load(config)

    def test_policy_rejects_duplicate_json_keys_and_oversized_file(self):
        for raw in (b'{"version":1,"version":1,"principals":[]}', b" " * (MAX_CONFIG_BYTES + 1)):
            self.write_raw(raw)
            with self.assertRaises(ValueError):
                AccessPolicy.load(self.path)

    @unittest.skipUnless(hasattr(os, "geteuid"), "requires Unix ownership and permissions")
    def test_policy_requires_process_owner_and_private_permissions(self):
        self.load()
        self.path.chmod(0o640)
        with self.assertRaises(ValueError):
            AccessPolicy.load(self.path)
        self.path.chmod(0o600)
        with patch("proofsieve.access.os.geteuid", return_value=os.geteuid() + 1), self.assertRaises(ValueError):
            AccessPolicy.load(self.path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX special files")
    def test_policy_rejects_symlinks_and_nonregular_files(self):
        self.load()
        link = self.path.with_name("link.json")
        link.symlink_to(self.path)
        fifo = self.path.with_name("fifo.json")
        os.mkfifo(fifo, 0o600)
        for invalid in (link, fifo, self.path.parent):
            with self.assertRaises(ValueError):
                AccessPolicy.load(invalid)
