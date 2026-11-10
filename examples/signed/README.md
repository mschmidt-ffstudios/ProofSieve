# Signed EUDI inputs in the Guard

Choose **Verify on server** to run the selected case. The Guard reports issuer verification, verified claim extraction and the ODRL decision. The built-in rules are read-only. Use **Load signed original** or **Load tampered case** to compare them without changing a saved rule.

Swagger UI exposes the same original and tampered requests on the permitted demo paths. It shows the signed expiry of each original. Test requests use the running server's clock.

| Format | Original | Tampered | Verified fields in the rule |
| --- | --- | --- | --- |
| SD-JWT VC | [HTTP 200 · true](http://127.0.0.1:4180/apps/guard/?endpoint=/verify/demo/eudi-sd-jwt) | [HTTP 403 · disclosure digest mismatch](http://127.0.0.1:4180/apps/guard/?endpoint=/verify/demo/eudi-sd-jwt&case=tampered) | `vct` equals `urn:eudi:pid:de:1` and `family_name` equals `Mustermann` |
| mdoc IssuerSigned | [HTTP 200 · true](http://127.0.0.1:4180/apps/guard/?endpoint=/verify/demo/eudi-mdoc) | [HTTP 403 · issuerAuth signature mismatch](http://127.0.0.1:4180/apps/guard/?endpoint=/verify/demo/eudi-mdoc&case=tampered) | `docType` equals `eu.europa.ec.eudi.pid.1` and `issuing_country` equals `GR` |

The SD-JWT case uses the original RFC 9901 Appendix A.3 issuer JWS and four of its published disclosures. The holder proof is omitted for this issuer-only check. The original public test key is from Appendix A.5. The altered input substitutes the disclosed family name without updating the signed digest. [RFC 9901 A.3](https://www.rfc-editor.org/rfc/rfc9901.html#appendix-A.3)

The live mdoc example is signed by a synthetic P-256 document signer. Its Mobile Security Object uses the EUDI PID document type and is valid until **2031-01-01 at 00:00:00 UTC**. The altered case flips one bit in the COSE signature. The bundled public key is for the example. The original [upstream vector](mdoc-upstream.json) stays available for historical regression with its original validity and signer. [EUDI source fixture](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt/blob/8897d4324a8e34cc5de90b4eadffc656517a4924/src/test/resources/example/mso_mdoc_pid-issuersigned.txt) · [Upstream Apache license](LICENSE-EUDI-OPENID4VP.txt)

## Configure a signed endpoint

A trusted local operator can create a rule via `PUT /admin/rule?endpoint=/verify/<name>` using the editor token from `GET /admin/rule`. Add a `credential` object to the normal ODRL rule. Set `format` to `sd-jwt` or `mdoc`, set `publicKeyPem` to the expected issuer's public P-256 key in PEM SubjectPublicKeyInfo format, and for `sd-jwt` set `issuer` to the expected signed `iss` value. Derive trust from your own configuration source. The request credential cannot select its verification key. The Guard editor preserves this configuration when editing an existing rule. [Complete demo rules](guard.json)

Send `POST` to the configured endpoint with a JSON body of the form `{"data":"<signed credential>"}`. SD-JWT VC input is compact issuer serialization ending in `~`. mdoc input is base64url of IssuerSigned CBOR. The policy receives only verified claims from the adapter. If the adapter rejects the credential in boolean, guard or URL mode, the response is HTTP 403 with `stage: "credential"` and `code: "credential_rejected"`. If the credential passes verification but a required claim is missing, the policy refuses it using the configured response mode.

For a recorded decision, include an opaque `operationId` alongside `data` and authenticate with a token granted that endpoint. Credential rejection produces a recorded `deny` with reason `credential_rejected`. The HTTP status follows the [decision and delivery contract](../../README.md#response-modes).

## Verification scope

- The SD-JWT profile accepts `dc+sd-jwt` with ES256, an exact issuer match, a signed type and expiry, and SHA-256 disclosure digests. It enforces the signed `nbf` and `iat` when present. It checks each supplied disclosure against the digest that anchors it to the signed claims.
- The mdoc profile checks COSE_Sign1 ES256, the signed Mobile Security Object validity, and SHA-256 over the original CBOR bytes of every supplied issuer-signed item. ODRL can compare `docType` and native scalar values from that document type's namespace.
- Each pinned key expresses the operator's trust for that endpoint. This local scope covers issuer authenticity and claim integrity. Full EUDI Wallet presentations need holder or device authentication and verifier binding. Production issuer trust and status require certificate chain or trust-list validation and revocation handling.

Run `.venv/bin/python -m unittest discover -s tests -v` from the repository root. The historical regression uses its fixture date. The installed Guard, Swagger examples and Builder handoff acceptance use the real clock.

## RFC fixture notice

The RFC 9901 test data carries the [IETF Trust notice](LICENSE-RFC9901.txt).
