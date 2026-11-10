# Supported profiles and limitations

This page describes the current verification profiles and their limits. See the [architecture](CONCEPT.md) for the request flow and the [release notes](RELEASE-NOTES-0.5.0.md) for changes.

## Available locally

| Area | What works |
| --- | --- |
| [Workspace](../apps/index.html) | Three separately organized apps on the same local server. The home page links to Guard, Credential Builder, Verification Lab and Swagger UI. |
| [Guard](../apps/guard/index.html) | Create and select verification endpoints, save an ODRL or SHACL rule per endpoint, and make a real server request. The endpoint can return a boolean, HTTP 403 on policy refusal in guard mode, a configured approval or refusal URL in JSON, or a recorded decision. See the [response modes](../README.md#response-modes). The editor synchronizes a connected ODRL rule tree and its JSON-LD draft. |
| Guard rule preview | A live two-pane dialog takes pasted input or a local file, evaluates the current draft with the server verifier, and shows the ODRL result tree and API outcome. Signed inputs must pass issuer verification before the policy can be traced. |
| [Credential Builder](../apps/builder/index.html) | Create unsigned JSON status data, illustrative credential data or RDF Turtle. Edit the fields or raw text, preview the API request, import and export a local file, and save a draft in the browser. |
| [Sourced credential examples](../examples/credentials/README.md) | Five Builder examples with the source, editable input and a real server-side ODRL comparison. Each has a counterexample. Sample checks are read-only and run independently of saved Guard endpoints. |
| [Signed EUDI demos](../examples/signed/README.md) | Two Guard endpoints verify issuer SD-JWT VC or mdoc IssuerSigned with a configured P-256 key, authenticate disclosed values, enforce validity and apply ODRL. The Guard shows whether the credential was rejected before policy evaluation. |
| [Verification Lab](../apps/lab/index.html) | Ten examples, including 2-of-3, with editable example settings, a linked rule graph, simulated evidence and API response previews. |
| Builder to Guard | The Builder hands input to the Guard in the same tab, including after verifier sign-in. A compatible endpoint loads the exact input. An incompatible pending handoff blocks verification until the user selects a matching endpoint or discards it. The user starts verification explicitly. |
| Languages | The workspace, Guard, Credential Builder, Verification Lab and Swagger UI controls support German and English. A shared browser preference applies when navigating between them. Rules and test data retain their configured values. |
| [Integration API](../openapi.json) | The live OpenAPI document describes the actual request and response mode of each permitted `POST /verify…` endpoint. Saved endpoint rules persist across restart. |
| [Swagger UI](../apps/api-docs/index.html) | The operator-side console loads the token-scoped specification, downloads it as JSON and runs explicit test calls against the same ProofSieve instance. The ProofSieve shell uses the shared language preference. |
| [Company reference case](../examples/company/README.md) | A fictional supplier portal runs 11 HTTP cases against a disposable Guard with a per-run issuer key. The cases cover eligibility, return and fail URLs, and credential rejection before policy evaluation. |
| [Distribution and deployment boundary](DEPLOYMENT.md) | Python wheel and source distribution with a command-line entry point and bundled UI. Keep site-specific settings and writable state in a private deployment directory. |
| [Security controls](SECURITY-REVIEW.md) | A private Unix socket supports operator-authenticated SSH forwarding. HTTP, JSON, policy and credential boundaries have adversarial regression coverage. |
| [Endpoint access](ACCESS.md) | Separate admin and verifier bearer identities with exact path grants. Protected discovery lists only granted routes. Admin writes and preview also require a principal-specific editor token. |
| [Keycloak service accounts](ACCESS.md#keycloak-service-accounts) | Version 2 access files support short-lived, audience-bound Keycloak service-account tokens. Signed client roles map to exact verifier grants. Opaque admin credentials remain a separate access path. |
| [Recorded decisions](../examples/company/README.md#record-a-decision-for-an-order) | Recorded-decision mode binds a decision ID to the caller, operation, rule version and input fingerprint. Local SQLite evidence records the decision and check provenance. |
| [Server-side forwarding](FORWARDING.md) | Exact endpoints can send approved original requests to an operator-configured HTTPS receiver. The SQLite delivery journal prevents repeated attempts and distinguishes decision from delivery. |
| [Wallet presentations](WALLET.md) | Configured endpoints create single-use HAIP sessions through a configured EUDI Reference Verifier or Credo bridge, project typed facts into ODRL and optionally validate signed status snapshots. |
| [W3C credential inputs](CREDENTIALS.md) | Pinned issuer verification for ES256 JWT-VC and Ed25519 Data Integrity credentials. Signed resource references can be matched against versioned local bytes. |
| [Proof bundles and evidence export](PROOF-BUNDLES.md) | Join two to four checked proofs to an operation, evaluate ODRL on the projected facts and export caller-scoped, Ed25519-signed decision evidence. |
| [Document verification](DOCUMENT-CHECKS.md) | Pinned signer certificates, distinct-signer thresholds, local detached signatures, a direct-issuer OCSP profile and optional DSS or compatible HTTPS bridges. The Guard exposes the configured signer paths and explicit document preview. |
| [Shared service deployment](DEPLOYMENT.md#shared-service-deployment) | Separate Unix sockets for operator access and the HTTPS-facing verification API. The API socket enforces its host and route boundary before applying caller grants. |

Run the server with the [README instructions](../README.md) and open [the local workspace](http://127.0.0.1:4180/apps/).

## Scope and limitations

| Area | Current boundary |
| --- | --- |
| Input routing | The verification path selects the rule and input profile. Format and issuer hints from submitted data do not select a policy. |
| Rules and trust | The runtime supports the documented [ODRL and SHACL subsets](ODRL-PROFILE.md#basic-guard-profile). Operators configure trusted issuers, keys and status sources for each deployment. |
| Document verification | The configured signer and timestamp profiles validate the submitted bytes. Establishing qualified status under eIDAS requires separate trust evidence. [Document checks](DOCUMENT-CHECKS.md) |
| Evidence | Signed exports preserve the integrity of recorded decisions under the configured signing key. Qualified timestamps for exports, archival services and registered delivery require separate integrations. [Evidence scope](PROOF-BUNDLES.md#trust-service-integration-boundary) |

## Wallet interoperability

The wallet adapters verify cross-device OpenID4VP presentations of SD-JWT VC and ISO mdoc through the configured EUDI Reference Verifier or Credo bridge. They use DCQL, encrypted `direct_post.jwt` responses and one-time sessions bound to the operation. The verifier checks holder or device binding before the Guard evaluates the mapped claims. Endpoint profiles can require signed JWT or CWT status snapshots. [Wallet profiles](WALLET.md) · [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) · [HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)

ISO/IEC 18013-5 proximity reading, ISO/IEC 18013-7 Annex C browser flows, full EU trust-list integration and wallet conformance testing are outside the current integration scope. [EUDI presentation protocols](https://docs.eudi.dev/latest/use-cases/mobile-driving-license/mdl-overview/standards-and-protocols/)

## Reproduce verification tests

The [verification test suite](../examples/acceptance/README.md) covers browser workflows, endpoint grants, signature and document checks, and signed evidence. The [wallet adapter comparison](../examples/acceptance/WALLET-COMPARISON.md) exercises the live adapters with synthetic presentations and disposable keys. See the [installation guide](../deploy/README.md) for the packaged service and HTTPS checks.
