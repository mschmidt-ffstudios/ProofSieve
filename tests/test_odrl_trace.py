import unittest

from proofsieve.guard import DEFAULT_RULE, preview_rule
from proofsieve.odrl import MAX_TRACE_VALUE_LENGTH, PROFILE, compile_policy


def condition(field, expected):
    return {"leftOperand": f"field:{field}", "operator": "eq", "rightOperand": expected}


def compile_constraints(*constraints):
    return compile_policy({
        "@context": ["http://www.w3.org/ns/odrl.jsonld", {"field": "https://proofsieve.example/facts/"}],
        "@type": "Set",
        "uid": "urn:proofsieve:test:trace",
        "profile": PROFILE,
        "permission": [{"target": "urn:demo:service", "action": "use", "constraint": list(constraints)}],
    })


class OdrlTraceTest(unittest.TestCase):
    def test_nested_trace_records_matches_and_reasons(self):
        check = compile_constraints(
            condition("status", "active"),
            {"xone": [condition("role", "admin"), {"and": [condition("mfa", True), condition("role", "reviewer")]}]},
        )
        data = {"status": "active", "role": "reviewer", "mfa": True}
        trace = []
        self.assertTrue(check(data, trace=trace))
        self.assertTrue(check(data))
        self.assertEqual(trace, [{
            "kind": "group", "operator": "and", "matched": True, "children": [
                {"kind": "condition", "field": "status", "operator": "eq", "matched": True,
                 "reason": "match", "expected": "active", "expectedText": '"active"', "actualText": '"active"'},
                {"kind": "group", "operator": "xone", "matched": True, "children": [
                    {"kind": "condition", "field": "role", "operator": "eq", "matched": False,
                     "reason": "comparison", "expected": "admin", "expectedText": '"admin"', "actualText": '"reviewer"'},
                    {"kind": "group", "operator": "and", "matched": True, "children": [
                        {"kind": "condition", "field": "mfa", "operator": "eq", "matched": True,
                         "reason": "match", "expected": True, "expectedText": "true", "actualText": "true"},
                        {"kind": "condition", "field": "role", "operator": "eq", "matched": True,
                         "reason": "match", "expected": "reviewer", "expectedText": '"reviewer"', "actualText": '"reviewer"'},
                    ]},
                ]},
            ],
        }])

    def test_short_circuit_does_not_hide_branches_in_trace(self):
        check = compile_constraints(condition("status", "active"), {"or": [
            condition("role", "admin"), condition("mfa", True),
        ]})
        trace = []
        data = {"mfa": {"sensitive": "nested value"}}
        self.assertFalse(check(data))
        self.assertFalse(check(data, trace=trace))
        status, alternatives = trace[0]["children"]
        self.assertEqual(status["reason"], "missing")
        self.assertEqual([node["reason"] for node in alternatives["children"]], ["missing", "type"])
        self.assertNotIn("actualText", alternatives["children"][1])
        self.assertNotIn("sensitive", repr(trace))

    def test_exactly_one_denies_multiple_true_children(self):
        check = compile_constraints({"xone": [condition("primary", True), condition("fallback", True)]})
        trace = []
        self.assertFalse(check({"primary": True, "fallback": True}, trace=trace))
        group = trace[0]["children"][0]
        self.assertFalse(group["matched"])
        self.assertEqual([node["matched"] for node in group["children"]], [True, True])

    def test_trace_bounds_scalar_text_and_omits_unreferenced_values(self):
        check = compile_constraints(condition("status", "active"))
        trace = []
        data = {"status": '"' * 2000, "secret": "not evaluated"}
        self.assertFalse(check(data, trace=trace))
        self.assertEqual(len(trace[0]["children"][0]["actualText"]), MAX_TRACE_VALUE_LENGTH)
        self.assertTrue(trace[0]["children"][0]["actualText"].endswith("…"))
        self.assertNotIn("secret", repr(trace))

    def test_preview_calculates_configured_return_and_fail_urls(self):
        rule = {**DEFAULT_RULE, "responseMode": "url", "returnUrl": "https://example.invalid/ok",
                "failUrl": "https://example.invalid/deny"}
        for status, valid, target in (("active", True, "ok"), ("blocked", False, "deny")):
            with self.subTest(status=status):
                result = preview_rule(rule, {"status": status})
                self.assertEqual(result["decisionStatus"], 200)
                self.assertEqual(result["decision"], {"valid": valid, "redirectUrl": f"https://example.invalid/{target}"})
                self.assertEqual(result["trace"]["matched"], valid)
