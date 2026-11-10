# Document signature checks

A document verification endpoint checks who signed the submitted bytes before applying its ODRL rule. The configuration pins a certificate to each allowed signer, chooses how to check each signature, and sets a minimum number of distinct signers. The decision records the outcome and its evidence under the caller's operation ID. A portal uses an `allow` outcome only for the matching operation and submitted document.

## Select a check for each signer

| Kind | What ProofSieve checks | Input proof |
| --- | --- | --- |
| `local` | Detached signature over the exact document bytes, using the configured end-entity certificate. The certificate must be within its validity period. | `signer` and Base64 `signature` |
| `ocsp` | The same local signature plus a fresh, signed OCSP response matching the certificate and request nonce. The configured issuer signs the response directly. | `signer` and Base64 `signature` |
| `dss` | A configured HTTPS bridge validates the format selected in the verification profile. ProofSieve matches the response to the request, document, certificate and detached proof when present. | See the format table below |
| `remote` | An HTTPS verifier implements the same request and response contract for a configured format. The remote profile also permits `raw` for a detached byte-level signature. | The same proof shape as the matching format |

Local and OCSP checks use SHA-256 with RSA PKCS#1 v1.5 (2,048 to 4,096 bits) or DER-encoded ECDSA with P-256, P-384 or P-521. OCSP uses a SHA-256 CertID, a matching nonce and a current `nextUpdate`. Configure the certificate's direct issuer and the responder route explicitly. This is a direct-issuer profile with a maximum response age of one day.

The same certificate or public key can represent one signer per endpoint. A self-signed end-entity certificate is suitable for the local test profile when explicitly pinned. The acceptance suite issues its electronic-seal certificate from a disposable test CA and tests it with a distinct organisation signing key. Trust for that certificate applies only to the test environment.

## DSS format profiles

The bundled test bridge uses DSS 6.5.1 and a private trust anchor. Its profiles select the corresponding validator and check the coverage shown below. [European Commission DSS documentation](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html) · [DSS release notes](https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109114/DSS%2Breleases)

| `format` | Base64 `document` | Proof and checked scope |
| --- | --- | --- |
| `pades` | PDF with embedded PAdES | `signer` only. The signed byte range covers the PDF up to its last byte, excluding the signature contents. |
| `cades-detached` | Original document | `signer` and Base64 detached CMS signature. |
| `xades-detached` | Original document | `signer` and Base64 detached XAdES Baseline signature. The XML has one local basename reference that covers the complete original without a data transform. |
| `jades-detached` | Original document | `signer` and Base64 compact detached JAdES Baseline signature. The signature covers the direct detached payload. |
| `cbades-detached` | Original document | `signer` and Base64 detached CB-AdES Baseline `COSE_Sign1`. The signature covers the direct detached payload. |
| `asic-s`, `asic-e` | ASiC container with CAdES Baseline signature | `signer` only. Every submitted payload entry must be covered by the selected signature. The bridge checks both ZIP directory views and permits bounded flat payloads with ASiC signature metadata. |
| `rfc3161` | Original timestamped document | `signer` and Base64 CMS TimeStampToken. The bridge checks the imprint against the complete document, the signature against the pinned TSA certificate, and the DSS timestamp verdict. |

The timestamp profile accepts one timestamp authority with a critical extended key usage restricted to timestamp signing. Its ODRL facts are `timestampVerified` and `documentSha256`. The signature threshold profiles continue to produce `validSignerCount`, `requiredSignerCount`, `thresholdMet` and `documentSha256`. [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161)

Run the extended format suite against the actual local TLS bridge and disposable trust material with:

```sh
.venv/bin/python examples/acceptance/dss/extended.py --java-home /absolute/path/to/jdk
```

The suite generates six valid originals and twelve negative cases. It checks each Guard decision and the corresponding DSS reference in SQLite. The test certificate policies and trust anchors belong to the acceptance environment. The production operator selects its trust material and qualification policy.

## Configure connectors as an operator

Store the registry in an owner-only JSON file such as `/etc/proofsieve/private/checks.json`. Pass it as `--checks-config`, alongside an access configuration and a private `--evidence` database. Use an empty connector map for a local-only installation. A connector becomes available through the operator's registry and executes only when a saved verification profile references it.

```json
{
  "version": 1,
  "connectors": {
    "dss-test": {
      "kind": "dss",
      "url": "https://127.0.0.1:8443/validate",
      "allowedNetworks": ["127.0.0.1/32"],
      "caFile": "/absolute/path/to/test-ca.pem",
      "bearerEnv": "PROOFSIEVE_DSS_TOKEN",
      "profileVersion": "test-seal-v1",
      "timeoutSeconds": 3
    },
    "status-test": {
      "kind": "ocsp",
      "url": "https://127.0.0.1:8444/ocsp",
      "allowedNetworks": ["127.0.0.1/32"],
      "caFile": "/absolute/path/to/test-ca.pem",
      "profileVersion": "test-direct-issuer-v1"
    }
  }
}
```

DSS and remote verifiers require a bearer credential read from the named environment variable. Set `caFile` to an absolute trust bundle path when using a private TLS CA. The operator chooses the target URL, allowed destination CIDRs and connector version. ProofSieve validates the resolved IPs at startup and uses a fixed verified address with TLS hostname verification. Use narrowly scoped networks, a validation-only route and an outbound firewall. The HTTP client accepts a bounded response with one content length and the expected media type, and rejects redirects. Each configured network request has a timeout, with a twelve-second budget for the document's external checks.

The [acceptance bridge](../examples/acceptance/dss/src/main/java/org/proofsieve/acceptance/Bridge.java) is a loopback-only fixture that validates with actual DSS, a temporary trust anchor and a local CRL. A shared installation needs its own privately hosted validation bridge, a pinned DSS version and validation policy, and explicit trust and network configuration. An existing DSS installation can sit behind a bridge that implements the typed contract below. [European Commission DSS documentation](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html)

## Configure a two-of-three endpoint

Use an admin with all-endpoint access to save a rule with `language: "odrl"`, `responseMode: "decision"`, the ODRL policy and a `verification` profile. The example uses a local signer, a signer whose CAdES signature is checked by DSS, and a local signer with an OCSP status check. Replace each placeholder with exactly one PEM certificate. Use the profile as the value of the rule's `verification` field.

```json
{
  "threshold": 2,
  "signers": [
    {
      "id": "finance",
      "kind": "local",
      "certificatePem": "<finance signing certificate>"
    },
    {
      "id": "company-seal",
      "kind": "dss",
      "format": "cades-detached",
      "connector": "dss-test",
      "certificatePem": "<organisation seal certificate>"
    },
    {
      "id": "audit",
      "kind": "ocsp",
      "connector": "status-test",
      "certificatePem": "<audit signing certificate>",
      "issuerCertificatePem": "<direct issuer certificate>"
    }
  ]
}
```

Each proof signs the same exact document. Sign the bytes as transmitted, including whitespace and line endings. Send standard, padded Base64 for the document and detached signatures. The raw document limit is 64 KiB, the detached signature limit is 32 KiB per proof, and the complete HTTP request limit is 96 KiB. Supply each signer at most once.

```http
POST /verify/supplier-orders HTTP/1.1
Authorization: Bearer <granted service access token>
Content-Type: application/json

{
  "operationId": "order-1042",
  "data": {
    "document": "<base64 of the exact order bytes>",
    "proofs": [
      {"signer": "finance", "signature": "<base64 detached signature>"},
      {"signer": "company-seal", "signature": "<base64 detached CAdES>"}
    ]
  }
}
```

An embedded PAdES seal uses a profile with `format: "pades"`. Send the signed PDF as `document` and a proof such as `{"signer":"company-seal"}`. An ASiC profile uses the same embedded proof shape with the full container as `document`.

When the threshold passes, ODRL receives the facts below. A policy can check `thresholdMet`, set a higher minimum via `validSignerCount`, or pin the exact document via `documentSha256`. The latter represents a SHA-256 hex digest of the bytes supplied in `document`.

```json
{
  "validSignerCount": 2,
  "requiredSignerCount": 2,
  "thresholdMet": true,
  "documentSha256": "<sha256 of the exact order bytes>"
}
```

| Case | Decision behaviour |
| --- | --- |
| Two distinct configured signers pass for the same order | Evaluate ODRL. A matching policy returns `200 allow`. |
| One signer passes and the second signed different order bytes | With the third proof absent, return `200 deny` with reason `check_failed`. |
| Two signers pass and the third returns unknown status | Evaluate ODRL with the two confirmed signers. |
| One signer passes and a second configured verifier times out | Return `503 indeterminate` when that verification could satisfy the threshold. |
| Duplicate signer proof, unknown signer or malformed encoding | Return `400` before contacting a verifier. |
| Token invalid or exact path grant absent | Return `401` or `403` before performing document checks. |

Decision-mode responses carry `outcome`, `valid`, `reason`, `decisionId`, `operationId` and `ruleVersion` for completed evaluations. The private decision store records per-signer reason codes, the configured connector profile and a validated report identifier when available. Signed exports use a keyed `reportFingerprint` for that identifier. [Evidence export](PROOF-BUNDLES.md#export-a-decision) The application retains responsibility for applying the response only to the submitted operation.

## DSS and remote bridge contract

Send JSON by HTTPS POST. The request includes `version: 1`, a fresh `nonce`, `format`, Base64 `document`, `documentSha256` and the configured signer's `certificateSha256` over its DER certificate. Detached formats also send Base64 `signature` and `signatureSha256`. The bridge validates the actual artifact digests, establishes that the signature covers the submitted bytes, applies its configured trust policy and matches the certificate to the signature it evaluated.

The response is a fixed JSON object. It echoes `version`, `nonce`, `documentSha256`, `certificateSha256` and `signatureSha256` for detached signatures. It also includes `verdict` and a short, opaque `reportId`. The DSS bridge maps the selected signature's `TOTAL-PASSED`, `TOTAL-FAILED` and `INDETERMINATE` indications to `passed`, `failed` and `indeterminate`. Transport failures, malformed responses and mismatched bindings are indeterminate. An unconfirmed signer cannot satisfy the threshold.

Run the [adapter tests](../tests/test_external_checks.py) for real local cryptographic proofs, signed OCSP fixtures and HTTPS connector boundary checks. The [acceptance suite](../examples/acceptance/) exercises real DSS and Keycloak with disposable certificates and documents.
