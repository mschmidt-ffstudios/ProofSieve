# Proof bundles and evidence export

A proof bundle joins two to four independently verified inputs before a saved ODRL rule evaluates them. The rule owner selects which facts can enter the policy. Explicit equality bindings link each input to the operation reference, either directly or through a chain of bindings between proofs. The caller supplies the named proofs and `operationId`. ProofSieve derives the facts from the verified inputs.

## Configure the join

Use an ODRL rule in `decision` mode with a `bundle` object. Each item declares one configured issuer credential profile or a document verification profile. Set the expected `credentialType` on each SD-JWT or mdoc item. W3C credential profiles carry their type within the profile. A bundle can contain one document item. Item labels use lowercase letters and digits and begin with a letter. Select up to 16 scalar facts per item.

```json
{
  "items": {
    "org": {
      "credential": {
        "format": "sd-jwt",
        "issuer": "https://issuer.example.test",
        "publicKeyPem": "<organization issuer public key>"
      },
      "credentialType": "urn:example:organization",
      "fields": ["organization", "status"]
    },
    "mandate": {
      "credential": {
        "format": "jwt-vc",
        "issuer": "https://mandates.example.test",
        "publicKeyPem": "<mandate issuer public key>",
        "credentialType": "PurchaseMandate",
        "contexts": ["https://www.w3.org/ns/credentials/v2"],
        "claims": {
          "organization": {"path": ["organization"], "type": "string"},
          "operation": {"path": ["operation"], "type": "string"},
          "amount": {"path": ["amount"], "type": "integer"}
        }
      },
      "fields": ["organization", "operation", "amount"]
    }
  },
  "bindings": [
    ["org_organization", "mandate_organization"],
    ["mandate_operation", "$operationId"]
  ]
}
```

In this example, the mandate carries the operation reference. The organization credential joins the mandate through the shared organization value. The saved rule can compare `field:org_status` with `"active"` and `field:mandate_amount` with `10000`. A mandate can be validly signed and exceed that policy limit. A different organization or operation fails the binding first. Select document facts such as `documentSha256` to bind a credential's signed digest to the exact submitted document. A global admin owns the trust configuration.

Send `POST /verify/<path>` with `{"operationId":"order-1042","data":{"org":"<SD-JWT>","mandate":"<JWT-VC>"}}`. Swagger describes each input by its configured label. Use the saved endpoint with an operation reference for bundle tests. Keep the relevant policy identifiers, resource digests and transaction terms inside the signed proof when the relying service needs to enforce them.

## Export a decision

Start with `--evidence-export`, `--auth-config` and `--evidence`. On the private operator listener, use the token of the caller that made the verification.

```sh
curl --get http://127.0.0.1:4180/evidence \
  -H "Authorization: Bearer $PROOFSIEVE_VERIFIER_TOKEN" \
  --data-urlencode endpoint=/verify/business-order \
  --data-urlencode operationId=order-1042
```

Add `decisionId` for a single decision. Exports include a caller and operation scope, rule version, outcome, provenance, input fingerprint and any matching delivery record. Results are bounded by the retention policy and a maximum of 32 decisions. A truncated result signals that additional decisions exist within retention. Raw input and claims stay out of the export. When a check records an upstream report ID, the export can include its operation-bound `reportFingerprint` instead of the raw ID.

The Ed25519 export key is distinct from the HMAC key used for input fingerprints. Obtain `EvidenceStore(path).export_public_key` through the operator's trusted local setup and pin that key at the recipient. Treat the public key embedded in the export as informational. Verify the file with `proofsieve.evidence.verify_evidence_export(bundle, public_key=pinned_key)`. The signature covers the canonical JSON under the ProofSieve evidence export v1 domain. Keep the evidence database and its key private and preserve the key across normal backup and restore.

## Trust service integration boundary

Export signing proves integrity under the operator's evidence key. Qualified timestamps, archiving and registered delivery each need a separately configured provider and validation policy. A timestamp integration would send the evidence digest and retain the returned RFC 3161 token alongside the export. Archiving or delivery would submit the authorized export and verify the provider receipt against its digest, service identity and operation. A status of qualified requires evidence of the provider and service qualification in the applicable trust scheme.

[RFC 3161](https://www.rfc-editor.org/info/rfc3161/) · [eIDAS trust services](https://eur-lex.europa.eu/eli/reg/2014/910/2024-10-18/eng)
