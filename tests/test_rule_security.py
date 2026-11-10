import os
import unittest
import warnings
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from proofsieve.guard import DEFAULT_RULE, Guard, load_json
from proofsieve.shacl import _parse_turtle, compile_shapes


FALSE_POLICY = """
@prefix sh: <http://www.w3.org/ns/shacl#> .
<urn:shape> sh:targetNode <urn:request> ;
  sh:path <urn:active> ;
  sh:hasValue false .
"""


class RuleSecurityTest(unittest.TestCase):
    def test_json_numbers_preserve_integral_values_and_reject_rounding(self):
        self.assertEqual(load_json(b"9007199254740993.0"), 9007199254740993)
        self.assertEqual(load_json(b"1e25"), 10**25)
        self.assertEqual(load_json(b"0.10000"), 0.1)
        for token in (b"1e-999", b"17.999999999999999999999", b"1" * 513, b"1e999"):
            with self.subTest(token=token[:30]), self.assertRaises(ValueError):
                load_json(token)

    def test_duplicate_key_error_omits_input(self):
        with self.assertRaises(ValueError) as error:
            load_json(b'{"private-input": 1, "private-input": 2}')
        self.assertNotIn("private-input", str(error.exception))

    def test_json_rejects_excessive_depth_and_lone_surrogates(self):
        with self.assertRaises(ValueError):
            load_json(b"[" * 65 + b"null" + b"]" * 65)
        for payload in (br'"\ud800"', br'{"\udfff": true}'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                load_json(payload)
        self.assertEqual(load_json(br'"\ud83d\ude00"'), "😀")

    def test_shacl_does_not_normalize_an_invalid_boolean_into_a_match(self):
        check = compile_shapes(FALSE_POLICY)
        self.assertTrue(check("<urn:request> <urn:active> false ."))
        with warnings.catch_warnings(record=True) as emitted, self.assertRaises(ValueError):
            check('<urn:request> <urn:active> "private-malformed-value"^^'
                  '<http://www.w3.org/2001/XMLSchema#boolean> .')
        self.assertEqual(emitted, [])

    def test_shacl_rejects_invalid_literals_before_normalizing(self):
        for datatype, text in (("decimal", "1e10000"), ("double", "1_2"), ("base64Binary", "Zg==AAAA")):
            with self.subTest(datatype=datatype), self.assertRaises(ValueError):
                _parse_turtle(f'<urn:s> <urn:p> "{text}"^^<http://www.w3.org/2001/XMLSchema#{datatype}> .',
                              "RDF data", 32)

    def test_shacl_has_value_compares_lexical_rdf_terms(self):
        prefix = '@prefix xsd: <http://www.w3.org/2001/XMLSchema#> . '
        for expected, same_term, different_term in (
            ('1', '"1"^^xsd:integer', '+01'),
            ('1', '1', '"01"^^xsd:integer'),
            ('0e0', '"0e0"^^xsd:double', '1e-999'),
            ('false', '"false"^^xsd:boolean', '"0"^^xsd:boolean'),
            ('"active"^^xsd:string', '"active"', '"active"@en'),
        ):
            with self.subTest(expected=expected, different_term=different_term):
                check = compile_shapes(prefix + FALSE_POLICY.replace('sh:hasValue false', f'sh:hasValue {expected}'))
                self.assertTrue(check(prefix + f'<urn:request> <urn:active> {same_term} .'))
                self.assertFalse(check(prefix + f'<urn:request> <urn:active> {different_term} .'))

    def test_shacl_numeric_limits_apply_to_turtle_shorthand(self):
        with self.assertRaises(ValueError):
            _parse_turtle(f'<urn:s> <urn:p> {"1" * 513} .', 'RDF data', 32)

    def test_shacl_does_not_log_malformed_rdf_values(self):
        with self.assertNoLogs("rdflib.term"), self.assertRaises(ValueError):
            _parse_turtle('<urn:s> <urn:p> "private-lexical-form"^^'
                          '<http://www.w3.org/2001/XMLSchema#date> .', "RDF data", 32)

    def test_shacl_caps_unique_triples_and_does_not_load_imports(self):
        self.assertEqual(len(_parse_turtle("<urn:s> <urn:p> 1, 1 .", "RDF data", 1)), 1)
        with self.assertRaises(ValueError):
            _parse_turtle("<urn:s> <urn:p> 1, 2 .", "RDF data", 1)

        with patch("socket.create_connection", side_effect=AssertionError("Unexpected network access")):
            self.assertTrue(compile_shapes(FALSE_POLICY)(
                '@prefix owl: <http://www.w3.org/2002/07/owl#> . '
                '<urn:request> <urn:active> false ; owl:imports <https://test.invalid/> .'
            ))

    def test_rule_state_and_api_results_use_independent_snapshots(self):
        with TemporaryDirectory() as directory:
            state = Path(directory) / "rules.json"
            guard = Guard(state, {})
            rule = deepcopy(DEFAULT_RULE)
            rule.update(responseMode="url", returnUrl="https://safe.invalid/return", failUrl="")
            response = guard.update(rule)
            rule["returnUrl"] = "https://unsafe.invalid/"
            response["rule"]["returnUrl"] = "https://also-unsafe.invalid/"

            for instance in (guard, Guard(state, {})):
                self.assertEqual(instance.verify({"status": "active"}), (
                    200, {"valid": True, "redirectUrl": "https://safe.invalid/return"}
                ))

    def test_failed_state_replace_leaves_disk_and_live_policy_unchanged(self):
        with TemporaryDirectory() as directory:
            state = Path(directory) / "rules.json"
            guard = Guard(state, {})
            guard.update(DEFAULT_RULE)
            original = state.read_bytes()
            new_rule = deepcopy(DEFAULT_RULE)
            new_rule["policy"]["permission"][0]["constraint"][0]["rightOperand"] = "blocked"
            with patch("proofsieve.guard.os.replace", side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):
                    guard.update(new_rule)
            self.assertEqual(state.read_bytes(), original)
            self.assertEqual(guard.verify({"status": "active"}), (200, True))
            self.assertEqual(list(state.parent.iterdir()), [state])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs POSIX special files")
    def test_state_rejects_symlink_and_nonregular_file(self):
        with TemporaryDirectory() as directory:
            parent = Path(directory)
            target = parent / "regular.json"
            target.write_text("{}")
            link = parent / "link.json"
            link.symlink_to(target)
            fifo = parent / "fifo.json"
            os.mkfifo(fifo)
            for state in (link, fifo):
                with self.subTest(state=state.name), self.assertRaises(ValueError):
                    Guard(state, {})
