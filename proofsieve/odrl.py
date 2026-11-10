"""Compile the local ProofSieve Basic Guard profile without external lookups.

A supported policy has the fixed ODRL and field contexts, identifies the Basic
Guard profile, and contains one Permission for one fixed target IRI and the
action use. Its nonempty constraint list is a conjunction. A node can be a
field comparison or an inline and, or, or xone group with nested operands.
A field operand reads exactly one top-level JSON property.

Equality and inequality compare strings, booleans, and finite numbers of the
same JSON type. Ordering compares finite numbers only. Missing properties,
incompatible types, and invalid input make the comparison false. The caller
verifies any credentials, binds the configured target to the
protected service and controls the provenance of the JSON values.
"""

import json
import math
import operator
import re
from typing import Callable
from urllib.parse import urlsplit


PROFILE = "https://proofsieve.example/profiles/basic/v1"
_CONTEXT = [
    "http://www.w3.org/ns/odrl.jsonld",
    {"field": "https://proofsieve.example/facts/"},
]
_FIELD = re.compile(r"field:([A-Za-z_][A-Za-z0-9_-]*)")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
_INVALID_IRI_CHAR = re.compile(r'[\s\x00-\x1f\x7f<>"{}|\\^`]|%(?![A-Fa-f0-9]{2})')
_COMPARISONS = {
    "eq": operator.eq,
    "neq": operator.ne,
    "gt": operator.gt,
    "gteq": operator.ge,
    "lt": operator.lt,
    "lteq": operator.le,
}
_ORDERING = {"gt", "gteq", "lt", "lteq"}
_MISSING = object()
MAX_CONSTRAINT_DEPTH = 8
MAX_CONSTRAINT_NODES = 128
MAX_TRACE_VALUE_LENGTH = 160


def _require_fields(value, fields, location):
    if type(value) is not dict or value.keys() != fields:
        expected = ", ".join(sorted(fields))
        raise ValueError(f"{location} must contain exactly these fields: {expected}")


def _require_absolute_iri(value, location):
    if type(value) is str and not _INVALID_IRI_CHAR.search(value):
        scheme, separator, resource = value.partition(":")
        if separator and _SCHEME.fullmatch(scheme) and resource and not resource.startswith("#"):
            try:
                parts = urlsplit(value)
                if parts.scheme not in {"http", "https"} or parts.hostname:
                    return
            except ValueError:
                pass
    raise ValueError(f"{location} must be an absolute IRI")


def _kind(value):
    if type(value) is bool:
        return "boolean"
    if type(value) is str:
        return "string"
    if type(value) is int or (type(value) is float and math.isfinite(value)):
        return "number"
    return None


def _trace_text(value):
    limit = MAX_TRACE_VALUE_LENGTH
    if type(value) is int and value.bit_length() > 4 * limit:
        return "…"
    clipped = type(value) is str and len(value) > limit
    text = json.dumps(value[:limit] if clipped else value)
    return text[:limit - 1] + "…" if clipped or len(text) > limit else text


def _compile_comparison(constraint, location):
    _require_fields(constraint, {"leftOperand", "operator", "rightOperand"}, location)
    operand = constraint["leftOperand"]
    field = _FIELD.fullmatch(operand) if type(operand) is str else None
    if field is None:
        raise ValueError(f"{location} leftOperand must be a top-level field:<name>")

    comparison = constraint["operator"]
    if type(comparison) is not str or comparison not in _COMPARISONS:
        raise ValueError(f"{location} uses an unsupported operator")
    expected = constraint["rightOperand"]
    kind = _kind(expected)
    if kind is None:
        raise ValueError(f"{location} rightOperand must be a string, boolean, or finite number")
    if comparison in _ORDERING and kind != "number":
        raise ValueError(f"{location} ordering requires a number")
    name = field.group(1)
    compare = _COMPARISONS[comparison]

    def check(data, trace=None):
        value = data.get(name, _MISSING)
        actual_kind = _kind(value)
        matched = actual_kind == kind and compare(value, expected)
        if trace is not None:
            if value is _MISSING:
                reason = "missing"
            elif actual_kind != kind:
                reason = "type"
            else:
                reason = "match" if matched else "comparison"
            result = {
                "kind": "condition",
                "field": name,
                "operator": comparison,
                "matched": matched,
                "reason": reason,
                "expected": expected,
                "expectedText": _trace_text(expected),
            }
            if actual_kind is not None:
                result["actualText"] = _trace_text(value)
            trace.append(result)
        return matched

    return check


def _exactly_one(results):
    return sum(results) == 1


_LOGICAL = {"and": all, "or": any, "xone": _exactly_one}


def _compile_group(operation, children):
    combine = _LOGICAL[operation]

    def check(data, trace=None):
        if trace is None:
            return combine(child(data) for child in children)
        branches = []
        for child in children:
            child(data, branches)
        matched = combine(branch["matched"] for branch in branches)
        trace.append({"kind": "group", "operator": operation, "matched": matched, "children": branches})
        return matched

    return check


def compile_policy(policy) -> Callable[..., bool]:
    """Compile a Basic Guard rule. The check can append its result tree to a trace list."""
    _require_fields(policy, {"@context", "@type", "uid", "profile", "permission"}, "Policy")
    if policy["@context"] != _CONTEXT:
        raise ValueError("Unsupported policy context")
    if policy["@type"] != "Set":
        raise ValueError("Policy type must be Set")
    if policy["profile"] != PROFILE:
        raise ValueError("Unsupported policy profile")
    _require_absolute_iri(policy["uid"], "Policy uid")

    permissions = policy["permission"]
    if type(permissions) is not list or len(permissions) != 1:
        raise ValueError("Policy must contain exactly one permission")
    permission = permissions[0]
    _require_fields(permission, {"target", "action", "constraint"}, "Permission")
    _require_absolute_iri(permission["target"], "Permission target")
    if permission["action"] not in ("use", "odrl:use"):
        raise ValueError("Permission action must be use or odrl:use")

    constraints = permission["constraint"]
    if type(constraints) is not list or not constraints:
        raise ValueError("Permission must contain at least one constraint")

    node_count = 0

    def compile_constraint(constraint, location, depth):
        nonlocal node_count
        node_count += 1
        if node_count > MAX_CONSTRAINT_NODES:
            raise ValueError(f"Policy allows at most {MAX_CONSTRAINT_NODES} constraint nodes")
        if depth > MAX_CONSTRAINT_DEPTH:
            raise ValueError(f"{location} exceeds maximum constraint depth {MAX_CONSTRAINT_DEPTH}")

        if type(constraint) is dict and len(constraint) == 1:
            operation = next(iter(constraint))
            if operation in _LOGICAL:
                operands = constraint[operation]
                if type(operands) is not list or len(operands) < 2:
                    raise ValueError(f"{location} {operation} requires at least two operands")
                children = tuple(
                    compile_constraint(operand, f"{location}.{operation}[{index}]", depth + 1)
                    for index, operand in enumerate(operands, start=1)
                )
                return _compile_group(operation, children)
        return _compile_comparison(constraint, location)

    compiled = tuple(
        compile_constraint(constraint, f"Constraint {index}", 0)
        for index, constraint in enumerate(constraints, start=1)
    )

    evaluate = _compile_group("and", compiled)

    def check(data, trace=None) -> bool:
        return type(data) is dict and evaluate(data, trace)

    return check
