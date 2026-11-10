# Supplier portal eligibility

A company lets eligible supplier accounts continue to its order portal. The supplier issuer signs the credential. The portal calls ProofSieve to verify the configured issuer and decide whether the credential's claims meet its eligibility rule. The portal applies the result to its authenticated session.

[The ODRL rule](policy.json) requires the configured supplier credential type and an active supplier. A procurement user meets the role requirement directly. A reviewer also needs an issuer-attested `mfa_enrolled` boolean set to `true`. This field expresses enrollment recorded by the issuer. The portal performs its own MFA challenge when its session policy requires a fresh factor.

## Run the reference case

Install the project using the [repository instructions](../../README.md). From the checkout, run `python examples/company/run.py` with the installed environment activated. The script starts a disposable loopback instance, configures `/verify/supplier-orders`, and exercises the public HTTP contract. It creates a fresh signing key in memory, passes only its public key to the verifier, and discards the temporary rule state at exit. Every credential and decision uses fictional data. This exercise uses URL response mode on an unprotected local listener. The protected Keycloak and recorded-decision flow is exercised by the [acceptance suite](../acceptance/README.md).

| Expected decision | Cases | Response |
| --- | --- | --- |
| Allow | Procurement account, reviewer with MFA enrollment | HTTP 200 with `valid: true` and the configured order-portal URL |
| Policy refusal | Reviewer without MFA enrollment, enrollment recorded as text, inactive supplier, wrong credential type | HTTP 200 with `valid: false` and the configured refusal URL |
| Credential rejection | Wrong issuer, untrusted signing key, altered role disclosure, expiry, unsigned claims | HTTP 403 with `stage: "credential"` and `code: "credential_rejected"` |

The script prints one JSON result per case and exits with an error if the observed decision differs. Its tampering case replaces a signed reviewer's disclosed role with `procurement`. The digest check rejects the escalation before ODRL evaluation.

## Use the same contract in an integration

Configure the ODRL rule and the issuer identifier and P-256 public key in the trusted local administration channel. The relying service posts `{"data":"<compact issuer SD-JWT VC>"}` to its configured `/verify` route. For this example the caller interprets the decision and may use the configured return or fail URL. The rule's `target` identifies the portal operation, and the URL is a value returned to the caller. The portal remains responsible for access control, the authenticated user session and request binding. [Signed endpoint configuration](../signed/README.md#configure-a-signed-endpoint)

This exercise covers issuer signature, claim integrity and eligibility. A deployment that accepts wallet presentations also needs holder and request binding, replay controls, issuer key lifecycle and status checks appropriate to its trust model. [Current implementation scope](../../docs/STATUS.md)

## Record a decision for an order

Set the endpoint's `responseMode` to `decision` and start the service with `--auth-config` and `--evidence`. The portal obtains its Keycloak service-account access token and sends `{"operationId":"order-1042","data":"<compact issuer SD-JWT VC>"}` to the configured endpoint. Its pending order determines the exact input and operation reference. Apply an approval once, to that pending order, after checking both `outcome: "allow"` and the returned operation reference. Bind the response to the request made by the portal. The operation reference itself is supplied by the portal.

A recorded response carries `decisionId`, `ruleVersion`, `operationId`, `outcome`, `valid` and a stable `reason`. Policy refusal and credential rejection give distinct reasons. An unconfirmed required check produces a recorded `indeterminate` outcome with HTTP 503. An evidence write failure returns HTTP 503 with `code: "evidence_unavailable"` and no decision ID. Keep the order blocked in either case. Use the decision ID to locate the server-side record. The database records an HMAC fingerprint of the request and the configured check results. [Keycloak configuration](../../docs/ACCESS.md#keycloak-service-accounts) · [Full acceptance suite](../acceptance/README.md)
