import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from proofsieve.guard import Guard
from proofsieve.odrl import (
    MAX_CONSTRAINT_DEPTH,
    MAX_CONSTRAINT_NODES,
    PROFILE,
    compile_policy,
)


def field(name, expected, operator="eq"):
    return {"leftOperand": f"field:{name}", "operator": operator, "rightOperand": expected}


def permission(*constraints):
    return {
        "@context": ["http://www.w3.org/ns/odrl.jsonld", {"field": "https://proofsieve.example/facts/"}],
        "@type": "Set",
        "uid": "urn:proofsieve:test:odrl-graph",
        "profile": PROFILE,
        "permission": [{"target": "urn:service:test", "action": "use", "constraint": list(constraints)}],
    }


class OdrlGraphTest(unittest.TestCase):
    def test_legacy_constraints_remain_implicit_and(self):
        check = compile_policy(permission(field("status", "active"), field("age", 18, "gteq")))
        self.assertTrue(check({"status": "active", "age": 18}))
        self.assertFalse(check({"status": "active", "age": "18"}))
        self.assertFalse(check({"status": "active"}))
        self.assertFalse(check([{"status": "active", "age": 20}]))

    def test_nested_groups_keep_their_logical_boundaries(self):
        check = compile_policy(permission(
            field("status", "active"),
            {"or": [
                {"and": [field("country", "DE"), field("age", 18, "gteq")]},
                {"xone": [field("reviewed", True), field("waived", True)]},
            ]},
        ))
        self.assertTrue(check({"status": "active", "country": "DE", "age": 19}))
        self.assertTrue(check({"status": "active", "reviewed": True}))
        self.assertTrue(check({"status": "active", "waived": True}))
        self.assertFalse(check({"status": "inactive", "reviewed": True}))
        self.assertFalse(check({"status": "active", "country": "DE", "age": 17}))
        self.assertFalse(check({"status": "active", "reviewed": True, "waived": True}))
        self.assertFalse(check({"status": "active", "reviewed": 1}))
        self.assertFalse(check({"status": "active"}))

    def test_missing_or_mistyped_value_does_not_satisfy_inequality(self):
        check = compile_policy(permission({"or": [field("name", "Sam", "neq"), field("override", True)]}))
        self.assertFalse(check({}))
        self.assertFalse(check({"name": 17}))
        self.assertFalse(check({"name": "Sam"}))
        self.assertTrue(check({"name": "Kim"}))
        self.assertTrue(check({"override": True}))

    def test_malformed_groups_and_unsupported_operands_are_rejected(self):
        operand = field("status", "active")
        invalid = [
            {"and": []},
            {"or": [operand]},
            {"xone": {"@list": [operand, operand]}},
            {"and": [operand, operand], "or": [operand, operand]},
            {"and": [operand, operand], "uid": "urn:unsupported:group"},
            {"andSequence": [operand, operand]},
            {"and": [operand, {"@id": "urn:unsupported:reference"}]},
            {"or": [operand, field("status", True, "gteq")]},
            {"or": [operand, field("status", float("inf"))]},
        ]
        for constraint in invalid:
            with self.subTest(constraint=constraint), self.assertRaises(ValueError):
                compile_policy(permission(constraint))

    def test_depth_limit_counts_top_level_nodes_as_depth_zero(self):
        node = field("status", "active")
        for _ in range(MAX_CONSTRAINT_DEPTH):
            node = {"and": [node, field("status", "active")]}
        self.assertTrue(compile_policy(permission(node))({"status": "active"}))
        with self.assertRaisesRegex(ValueError, "maximum constraint depth"):
            compile_policy(permission({"and": [node, field("status", "active")]}))

    def test_node_limit_counts_groups_and_leaves(self):
        leaves = [field("status", "active") for _ in range(MAX_CONSTRAINT_NODES - 1)]
        self.assertTrue(compile_policy(permission({"and": leaves}))({"status": "active"}))
        with self.assertRaisesRegex(ValueError, "at most 128 constraint nodes"):
            compile_policy(permission({"and": [*leaves, field("status", "active")]}))

    def test_saved_jsonld_preserves_integers_outside_browser_range(self):
        exact = 9007199254740993
        rule = {"language": "odrl", "responseMode": "boolean", "policy": permission(field("amount", exact))}
        with TemporaryDirectory() as directory:
            state = Path(directory) / "rules.json"
            saved = Guard(state, {}).update(rule)
            reopened = Guard(state, {}).describe("/verify")
            self.assertIn(str(exact), reopened["policyText"])
            self.assertEqual(json.loads(reopened["policyText"]), rule["policy"])
            self.assertEqual(saved["policyText"], reopened["policyText"])
