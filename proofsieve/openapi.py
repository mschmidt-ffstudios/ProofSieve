"""Describe each configured verification operation without exposing its rule."""

from copy import deepcopy


_JSON = "application/json"
_OUTPUTS = {
    "boolean": ("JSON true for approval or false for refusal.", {"type": "boolean"}),
    "guard": ("JSON true for approval. A policy refusal uses HTTP 403.", {"const": True}),
    "url": ("Decision with an optional configured HTTPS destination.", {"$ref": "#/components/schemas/UrlDecision"}),
    "decision": ("Recorded approval or refusal for the supplied operation reference.", {"$ref": "#/components/schemas/Decision"}),
}
_INPUTS = {
    "odrl": ("JSON facts for the configured ODRL rule.", {"type": "object"}, {"status": "active"}),
    "shacl": ("RDF Turtle for the configured SHACL shapes.", {"type": "string"},
              "@prefix ex: <https://proofsieve.example/demo/> . ex:request ex:status \"active\" ."),
    "sd-jwt": ("Compact issuer SD-JWT VC with disclosures.", {"type": "string"}, "<compact issuer SD-JWT VC>"),
    "mdoc": ("Base64url mdoc IssuerSigned CBOR.", {"type": "string"}, "<base64url IssuerSigned>"),
    "jwt-vc": ("Compact ES256 JWS carrying a W3C VCDM 2.0 credential.",
               {"type": "string"}, "<compact JWT-VC>"),
    "vc-data-integrity": ("W3C VCDM 2.0 credential with an eddsa-jcs-2022 Data Integrity proof.",
                          {"type": "object"}, {"@context": ["https://www.w3.org/ns/credentials/v2"]}),
    "bundle": ("Named proofs bound to the same operation.", {"type": "object"}, {}),
    "document": ("Base64 document and signature proofs for the configured signer profile.",
                 {"$ref": "#/components/schemas/DocumentProofs"}, {"document": "ZXhhbXBsZQ==", "proofs": []}),
    "wallet": ("Start a wallet session or complete the same operation after presenting the credential.",
               {"$ref": "#/components/schemas/WalletAction"}, {"action": "start"}),
}


def verification_document(template, profiles, *, protected, demos=None, forwarding=(), bundles=None, evidence_export=False):
    generic = template["paths"]["/verify"]["post"]
    paths = {}
    for path, (kind, mode) in profiles.items():
        operation = deepcopy(generic)
        if path != "/verify":
            operation.pop("operationId", None)
        description, schema, value = _INPUTS[kind]
        response_description, response_schema = _OUTPUTS[mode]
        operation["description"] = f"{description} {response_description}"
        operation["x-proofsieve-input"] = kind
        request = operation["requestBody"]["content"][_JSON]
        fields = request["schema"]
        fields["properties"]["data"] = {"description": description, **schema}
        if kind == "bundle":
            items = bundles[path]
            fields["properties"]["data"].update({
                "properties": {name: _INPUTS[profile][1] for name, profile in items.items()},
                "required": list(items), "additionalProperties": False,
            })
            value = {name: _INPUTS[profile][2] for name, profile in items.items()}
        example = {"data": value}
        if mode == "decision":
            fields["required"].append("operationId")
            example["operationId"] = "PO-1042"
        else:
            fields["properties"].pop("operationId")
        demo = (demos or {}).get(path, {})
        samples = demo.get("credentialExamples")
        if samples and kind in {"sd-jwt", "mdoc"}:
            expiry = demo.get("credentialExampleExpiresAt")
            description = f"The signed original expires at {expiry}. Verification uses the server clock." if expiry else ""
            request["examples"] = {
                "original": {"summary": "Synthetic signed original", "description": description,
                             "value": {**example, "data": samples["valid"]}},
                "tampered": {"summary": "Synthetic tampered sample · credential rejection",
                             "value": {**example, "data": samples["tampered"]}},
            }
        else:
            summary = "Request template · replace the example credential" if kind in {"sd-jwt", "mdoc"} else "Example request shape"
            request["examples"] = {"example": {"summary": summary, "value": example}}
        responses = operation["responses"]
        example_names = {
            "boolean": ("booleanApproval", "booleanRefusal"), "guard": ("booleanApproval",),
            "url": ("urlApproval", "urlRefusal", "urlBranchWithoutDestination"),
            "decision": ("recordedApproval", "recordedRefusal"),
        }[mode]
        examples = responses["200"]["content"][_JSON]["examples"]
        responses["200"] = {"description": response_description, "content": {
            _JSON: {"schema": response_schema, "examples": {name: examples[name] for name in example_names}},
        }}
        if mode != "decision":
            responses.pop("503")
        if not protected:
            responses.pop("401")
        forbidden = responses["403"]
        alternatives = [{"$ref": "#/components/schemas/AccessError"}]
        notes = ["The request failed access checks."]
        if mode == "guard":
            alternatives.append({"const": False})
            notes.append("A policy refusal returns JSON false.")
        if mode != "decision" and kind in {"sd-jwt", "mdoc", "jwt-vc", "vc-data-integrity"}:
            alternatives.append({"$ref": "#/components/schemas/CredentialRejection"})
            notes.append("A rejected signed credential returns code=credential_rejected.")
        forbidden["description"] = " ".join(notes)
        forbidden["content"][_JSON]["schema"] = {"oneOf": alternatives} if len(alternatives) > 1 else alternatives[0]
        if path in forwarding:
            describe_forwarding(operation)
        if kind == "wallet":
            describe_wallet(operation, example)
        paths[path] = {"post": operation}
    if evidence_export:
        paths["/evidence"] = {"get": describe_evidence_export()}
    template["paths"] = paths
    if protected:
        template["security"] = [{"bearerAuth": []}]
    return template


def describe_evidence_export():
    return {
        "operationId": "exportEvidence",
        "summary": "Export this caller's recorded operation evidence",
        "parameters": [
            {"name": name, "in": "query", "required": required, "schema": {"type": "string"}}
            for name, required in (("endpoint", True), ("operationId", True), ("decisionId", False))
        ],
        "responses": {
            "200": {"description": "Ed25519-signed decision evidence.",
                    "content": {_JSON: {"schema": {"type": "object", "required": [
                        "version", "scope", "decisions", "truncated", "integrity",
                    ]}}}},
            "400": {"description": "Invalid query parameters."},
            "401": {"description": "Authentication required."},
            "403": {"description": "The caller lacks the endpoint grant."},
            "404": {"description": "No matching evidence within retention."},
            "503": {"description": "Evidence is unavailable."},
        },
    }


def describe_wallet(operation, example):
    operation.pop("parameters")
    request = operation["requestBody"]["content"][_JSON]
    request["examples"] = {
        "start": {"summary": "Start a wallet session", "value": example},
        "complete": {"summary": "Complete using the same operation ID and the returned session ID", "value": {
            **example, "data": {"action": "complete", "sessionId": "A" * 43},
        }},
    }
    responses = operation["responses"]
    responses.pop("412")
    responses["200"]["description"] = "Verified presentation accepted by the saved policy."
    decision_examples = responses["200"]["content"][_JSON]["examples"]
    decision_examples.pop("recordedRefusal")
    interrupted_example = {
        **decision_examples["recordedApproval"]["value"],
        "outcome": "indeterminate",
        "valid": False,
        "reason": "wallet_evidence_interrupted",
    }
    responses["201"] = {"description": "Wallet session created. Open the authorization request in the wallet.",
                        "content": {_JSON: {"schema": {"$ref": "#/components/schemas/WalletSession"}}}}
    pending = {"type": "object", "required": ["state", "operationId"],
               "properties": {"state": {"const": "pending"}, "operationId": {"type": "string"}}}
    responses["202"] = {"description": "No wallet presentation has arrived yet. Poll the same session.",
                        "content": {_JSON: {"schema": pending}}}
    responses["403"]["description"] += " A recorded wallet or policy refusal can also return HTTP 403."
    responses["403"]["content"][_JSON]["schema"] = {"oneOf": [
        {"$ref": "#/components/schemas/AccessError"}, {"$ref": "#/components/schemas/Decision"},
    ]}
    responses["404"] = {"description": "Endpoint or matching wallet session is unavailable."}
    responses["409"] = {"description": (
        "Operation already reserved, session consumed or configuration changed. A completion whose decision was "
        "already recorded can return this conflict. Use the evidence export for the matching operation when available."
    )}
    retry_seconds = {"type": "integer", "minimum": 1, "maximum": 2_592_000}
    responses["429"] = {
        "description": "This caller reached its wallet start quota across all wallet endpoints.",
        "headers": {"Retry-After": {"description": "Seconds until the caller quota may allow a new start.",
                                    "schema": retry_seconds}},
        "content": {_JSON: {"schema": {
            "type": "object", "required": ["code", "error", "retryAfterSeconds"], "properties": {
                "code": {"const": "wallet_rate_limited"}, "error": {"type": "string"},
                "retryAfterSeconds": retry_seconds,
            },
        }}},
    }
    responses["503"] = {
        "description": (
            "Wallet verification, the journal or evidence is unavailable, or the session has a recorded "
            "indeterminate decision. On evidence_unavailable retry the exact completion for the same caller, "
            "endpoint, operation and session. A recorded wallet_evidence_interrupted decision keeps the operation "
            "blocked and can be exported by its decision ID. A local deadline has reason=wallet_expired."
        ),
        "content": {_JSON: {"schema": {"oneOf": [
            {"allOf": [{"$ref": "#/components/schemas/Decision"}, {"properties": {
                "outcome": {"const": "indeterminate"}, "valid": {"const": False},
                "reason": {"enum": ["wallet_expired", "wallet_evidence_interrupted"]},
            }}]},
            {"type": "object", "required": ["error", "code"], "properties": {
                "error": {"type": "string"}, "code": {"enum": ["wallet_unavailable", "evidence_unavailable"]},
            }},
        ]}, "examples": {
            "evidenceUnavailable": {"summary": "Retry the exact completion", "value": {
                "code": "evidence_unavailable", "error": "Der Nachweisspeicher ist nicht verfügbar.",
            }},
            "interruptedCompletion": {"summary": "Recovered indeterminate decision",
                                      "value": interrupted_example},
        }}},
    }


def describe_forwarding(operation):
    operation["x-proofsieve-forwarding"] = True
    operation["description"] += (
        " An approval forwards the original JSON body to the configured service. "
        "Use a unique operation reference and check the delivery state."
    )
    responses = operation["responses"]
    schema = {"$ref": "#/components/schemas/ForwardingDecision"}
    success = responses["200"]["content"][_JSON]
    original = success["examples"]["recordedApproval"]["value"]
    success["schema"] = schema
    success["examples"] = {"forwarded": {"value": {
        **original, "delivery": {
            "state": "delivered", "id": "6beae769-16fd-4818-9642-1d87312177ca", "upstreamStatus": 204,
        },
    }}}
    responses["200"]["description"] = "The approved operation reached the configured service."
    responses["403"]["description"] += " A refused decision does not send an upstream request."
    responses["403"]["content"][_JSON]["schema"] = {"oneOf": [
        {"$ref": "#/components/schemas/AccessError"}, schema,
    ]}
    responses["409"] = {
        "description": "This operation reference is bound to a different input or its delivery approval expired.",
        "content": {_JSON: {"schema": {
            "type": "object", "required": ["error", "code"],
            "properties": {"error": {"type": "string"}, "code": {
                "enum": ["operation_conflict", "operation_evidence_expired"],
            }},
        }}},
    }
    responses["502"] = {"description": "The destination responded outside the success range.",
                        "content": {_JSON: {"schema": schema}}}
    responses["503"]["description"] = "Verification, evidence or forwarding was indeterminate. Check delivery state."
    responses["503"]["content"][_JSON]["schema"]["oneOf"][0] = schema
