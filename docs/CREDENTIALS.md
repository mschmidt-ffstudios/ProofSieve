# Native W3C credential verification

ProofSieve can verify two issuer-signed W3C Verifiable Credentials Data Model 2.0 profiles before evaluating ODRL. Each endpoint pins its issuer and public key. ODRL receives only the scalar facts mapped from the verified credential subject. The submitted credential cannot choose its own verification key or authorize remote retrieval.

| Profile | JSON request field `data` | Signature |
| --- | --- | --- |
| `jwt-vc` | Compact JWS string with the VCDM 2.0 credential as the payload | ES256 with a pinned P-256 key and protected `typ: vc+jwt` |
| `vc-data-integrity` | VCDM 2.0 credential JSON object | One `eddsa-jcs-2022` Ed25519 proof for `assertionMethod` and the configured verification method |

[W3C JOSE securing profile](https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/#securing-json-ld-verifiable-credentials-with-jose) · [W3C EdDSA JCS cryptosuite](https://www.w3.org/TR/2025/REC-vc-di-eddsa-20250515/#eddsa-jcs-2022)

## Pin the profile

An operator with trust-management access saves the `credential` object alongside the ODRL policy. Replace the example key placeholder with the issuer's public key in PEM SubjectPublicKeyInfo format. For `jwt-vc`, use a P-256 key and omit `verificationMethod`.

```json
{
  "format": "vc-data-integrity",
  "issuer": "https://issuer.example.test",
  "publicKeyPem": "<issuer Ed25519 public key in PEM>",
  "verificationMethod": "https://issuer.example.test#vc-key",
  "credentialType": "MembershipCredential",
  "contexts": [
    "https://www.w3.org/ns/credentials/v2",
    "https://vocab.example.test/membership/v1"
  ],
  "claims": {
    "active": {
      "path": ["membership", "active"],
      "type": "boolean"
    }
  }
}
```

The credential must contain the ordered configured context identifiers, exactly the base `VerifiableCredential` type plus the configured type, one `credentialSubject` object and a signed `validFrom`. A signed `validUntil` bounds acceptance when supplied. Claim paths address literal JSON properties and bounded array indexes relative to that subject. Context identifiers are matched without JSON-LD expansion. Nested JSON-LD keywords and typed-claim mismatches are refused.

Data Integrity uses RFC 8785 canonicalization for both the unsigned document and proof options. If the proof repeats the context, it must repeat the complete credential context. The profile supports a standalone issuer assertion with optional proof creation and expiration timestamps. [VCDM 2.0](https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/) · [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html)

## Bind an offline resource version

Both profiles can require the issuer to sign an exact `relatedResource` reference. Set optional `resourcePins` in the `credential` configuration. The following pin approves the exact UTF-8 bytes of `{"type":"object"}`, with no trailing newline.

```json
{
  "resourcePins": [
    {
      "id": "https://vocab.example.test/membership/schema-v1.json",
      "digestSRI": "sha384-s9VOcj+ofSZxpi2cZe6yFQ4G5OouK/bxFfPFTEsZoSyWY47iG7YhUX3nlg+JrXwD",
      "mediaType": "application/schema+json",
      "contentBase64": "eyJ0eXBlIjoib2JqZWN0In0="
    }
  ]
}
```

The credential includes the corresponding `relatedResource` entry with `id`, `digestSRI` and `mediaType`. The operator supplies the approved local bytes as `contentBase64` when configuring the rule. Use files suitable for storage in the rule configuration. ProofSieve checks the bytes against the pin at rule compilation and checks that every signed reference matches the approved set before returning claims. Each profile can pin four resources up to 12 KiB each. SHA-384 and SHA-256 use single SRI digests. The operator and issuer select a new version explicitly by changing its identifier or digest.

This check establishes the identity and integrity of the referenced bytes. JSON Schema validation, `credentialSchema`, XML/XSD semantics for ELMO, LOTAR payload semantics and arbitrary `$ref` resolution require separate adapters. Legacy VCDM 1.1 JWT wrapping, RDF-canonicalized proof suites, credential revocation and holder presentation binding are also outside these two issuer-verification profiles. [W3C related resource integrity](https://www.w3.org/TR/2025/REC-vc-data-model-2.0-20250515/#integrity-of-related-resources)
