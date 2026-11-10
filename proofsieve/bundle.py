"""Verify and join bounded sets of proofs before exposing facts to a rule."""

import math
import re
from dataclasses import dataclass


_LABEL = re.compile(r"[a-z][a-z0-9]{0,23}")
_FIELD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_OPERATION = "$operationId"


@dataclass(frozen=True)
class BundleResult:
    outcome: str
    facts: dict
    evidence: tuple


@dataclass(frozen=True)
class _Item:
    label: str
    kind: str
    fields: tuple
    verify: object
    expected_type: str | None


def _scalar(value):
    return (type(value) in (bool, int) or type(value) is float and math.isfinite(value)
            or type(value) is str and len(value) <= 4096)


def compile_bundle(config, compile_credential, registry):
    if (type(config) is not dict or config.keys() != {"items", "bindings"}
            or type(config["items"]) is not dict or not 2 <= len(config["items"]) <= 4
            or type(config["bindings"]) is not list or not 1 <= len(config["bindings"]) <= 16):
        raise ValueError("A proof bundle needs two to four items and one to sixteen bindings.")
    items = []
    owners = {_OPERATION: _OPERATION}
    document_count = 0
    for label, item in config["items"].items():
        if (type(label) is not str or not _LABEL.fullmatch(label) or type(item) is not dict
                or item.keys() not in (
                    {"credential", "fields"}, {"credential", "fields", "credentialType"}, {"verification", "fields"},
                )
                or type(item["fields"]) is not list or not 1 <= len(item["fields"]) <= 16
                or any(type(name) is not str or not _FIELD.fullmatch(name) for name in item["fields"])
                or len(set(item["fields"])) != len(item["fields"])):
            raise ValueError("A proof item needs a unique label, verifier and selected fields.")
        expected_type = item.get("credentialType")
        if "credential" in item:
            verifier = compile_credential(item["credential"])
            kind = item["credential"]["format"]
            if kind in ("sd-jwt", "mdoc"):
                if not isinstance(expected_type, str) or not 1 <= len(expected_type) <= 512:
                    raise ValueError("Each SD-JWT or mdoc proof needs an explicit credentialType.")
            elif "credentialType" in item:
                raise ValueError("Set the expected type inside the W3C credential profile.")
        else:
            document_count += 1
            if registry is None or document_count > 1:
                raise ValueError("A bundle permits one document profile with a configured check registry.")
            verifier, kind = registry.compile(item["verification"]), "document"
        fields = tuple(item["fields"])
        items.append(_Item(label, kind, fields, verifier, expected_type))
        owners.update({f"{label}_{name}": label for name in fields})
    edges = {owner: set() for owner in owners.values()}
    bindings = []
    for pair in config["bindings"]:
        if (type(pair) is not list or len(pair) != 2
                or any(type(name) is not str or name not in owners for name in pair)
                or owners[pair[0]] == owners[pair[1]]):
            raise ValueError("A binding must compare fields from different proofs or the operation reference.")
        left, right = pair
        edges[owners[left]].add(owners[right])
        edges[owners[right]].add(owners[left])
        bindings.append((left, right))
    reachable = {_OPERATION}
    while neighbors := set().union(*(edges[node] for node in reachable)) - reachable:
        reachable.update(neighbors)
    if reachable != edges.keys():
        raise ValueError("Every proof must be linked to the operation reference through explicit bindings.")
    return _Bundle(tuple(items), tuple(bindings))


@dataclass(frozen=True)
class _Bundle:
    items: tuple
    bindings: tuple

    def __call__(self, data, operation_id):
        if type(data) is not dict or data.keys() != {item.label for item in self.items}:
            raise ValueError("Provide exactly the proof items configured for this endpoint.")
        if not operation_id:
            raise ValueError("A proof bundle requires an operation reference.")
        facts = {_OPERATION: operation_id}
        evidence = []
        for item in self.items:
            record = {"kind": "bundle_item", "item": item.label, "format": item.kind}
            if item.kind == "document":
                result = item.verify(data[item.label])
                evidence.extend({**check, "item": item.label} for check in result.evidence)
                if result.outcome != "passed":
                    evidence.append({**record, "outcome": result.outcome, "reason": "document_check"})
                    return BundleResult(result.outcome, {}, tuple(evidence))
                values = result.facts
            else:
                try:
                    proof = data[item.label]
                    if type(proof) is not (dict if item.kind == "vc-data-integrity" else str):
                        raise ValueError("Unexpected proof input type.")
                    values = item.verify(proof)
                except ValueError:
                    evidence.append({**record, "outcome": "failed", "reason": "credential_rejected"})
                    return BundleResult("failed", {}, tuple(evidence))
                if item.expected_type is not None:
                    type_field = "vct" if item.kind == "sd-jwt" else "docType"
                    if values.get(type_field) != item.expected_type:
                        evidence.append({**record, "outcome": "failed", "reason": "credential_type_mismatch"})
                        return BundleResult("failed", {}, tuple(evidence))
            if any(name not in values or not _scalar(values[name]) for name in item.fields):
                evidence.append({**record, "outcome": "failed", "reason": "required_fact_missing_or_invalid"})
                return BundleResult("failed", {}, tuple(evidence))
            facts.update({f"{item.label}_{name}": values[name] for name in item.fields})
            evidence.append({**record, "outcome": "passed"})
        for left, right in self.bindings:
            a, b = facts[left], facts[right]
            if type(a) is not type(b) or a != b:
                evidence.append({"kind": "bundle_binding", "outcome": "failed", "reason": "binding_mismatch",
                                 "fields": [left, right]})
                return BundleResult("failed", {}, tuple(evidence))
        evidence.append({"kind": "bundle_binding", "outcome": "passed"})
        del facts[_OPERATION]
        return BundleResult("passed", facts, tuple(evidence))
