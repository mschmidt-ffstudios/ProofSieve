# ProofSieve security review

This review covers the single-operator reference deployment and the current policy and credential profiles. The operator reaches the service through authenticated SSH forwarding to an owner-only Unix socket. [Deployment boundary](DEPLOYMENT.md)

| Area | Findings and changes | Regression coverage |
| --- | --- | --- |
| HTTP and editor boundary | Limit concurrent connections, request target and header sizes, and the total time for reading a request. Dispatch only validated origin-form targets. Reject ambiguous framing and duplicate trust-related headers. Check local Host and Origin and protect editor writes with the editor token. | Raw socket tests cover malformed, duplicate, slow and concurrent requests. |
| JSON and rule state | Reject numeric literals whose fractional value would change on conversion. Preserve exact supported integers. Validate the bounded request structure. Copy saved rule data across the state boundary and check the state file type before reading. Retain atomic replacement on save. | Numeric threshold, duplicate and malformed input, state snapshots, rollback and file type tests. |
| ODRL graph | Detect rounding in JSON-LD drafts before a graph edit can replace the original value. The raw editor preserves the source text. | Browser check with a high-precision threshold and the existing graph and signed-rule tests. |
| SHACL | Reject malformed lexical values before RDF parsing can normalize them. Limit graph construction and omit raw literal contents from parse diagnostics. | Malformed Boolean and other literal tests, graph bounds and existing Turtle handoff checks. |
| SD-JWT and mdoc | Verify against the configured key. Reject ambiguous SD-JWT numbers and malformed Unicode. Validate the mdoc digest table and signed validity bounds. Only authenticated scalar fields from the document's namespace reach flat ODRL comparisons. | Wrong key, tampered disclosure, malformed digest table, expiry, cross-namespace and typed-claim tests. |
| Remote demo | The runtime socket is mode `0600` inside an owner-only directory. SSH authenticates the operator. The application listens on the socket and the forwarding endpoint listens on workstation loopback. | Socket mode, unsafe directory, Host mismatch and real tunneled requests. |

The issuer credential adapters verify signatures and disclosed data under a pinned key. Wallet or device binding, credential revocation and PKI trust-chain evaluation are separate work for that issuer profile. [Signed profile limits](../examples/signed/README.md#verification-scope) · [Security policy](../SECURITY.md)

## Integration trust boundaries

| Boundary | Control and acceptance |
| --- | --- |
| Calling service | Keycloak tokens are checked against a fixed realm and API audience, a bound service-account client and subject, and an exact endpoint grant. The signature-key lookup has size and time bounds. Service accounts receive verifier rights. |
| Operator access | The HTTPS API socket checks the exact host and its API-only routes. A separate owner-only socket serves the local operator UI and admin endpoints. Connector profiles require a global operator grant and previews use the saved profile. |
| Document and network | The profile pins signer certificates and checks proofs against the submitted bytes. Connectors use configured HTTPS destinations, TLS authentication, address pinning, limits and fixed response binding. The OCSP profile verifies the direct issuer signature, certificate ID, freshness and nonce. |
| Decision integrity | Policy applies to authenticated inputs and verified facts. The portal consumes only an approval for its matching pending request. The decision is returned after durable SQLite recording. Indeterminate required checks and evidence write failures block the operation. |
| Evidence data | The store keeps the operation reference, rule fingerprint, input HMAC and bounded provenance. Limit operation IDs to opaque references. SQLite access and backups require operator-side file protection. Independent tamper-proof archival is a separate storage integration. |
| Test trust | All acceptance credentials, private keys and seals are generated for an isolated run. DSS uses the synthetic trust anchor and CRL. A production installation supplies reviewed trust sources and a policy for its documents. |

The acceptance dependencies are separate from the Python distribution. The DSS fixture uses Jackson 2.22.3 after the runtime dependency audit. Keycloak 26.8.2 is used in the disposable loopback acceptance environment. Its shipped Guava, OpenTelemetry and MariaDB JDBC dependencies still have upstream advisories. A shared pilot must review its actual Identity Provider bundle, configuration and exposure before activation. The fixture uses an in-memory database, has tracing disabled and handles synthetic data. [Reproduce the acceptance run](../examples/acceptance/README.md) · [Guava advisory](https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94) · [OpenTelemetry advisory](https://github.com/open-telemetry/opentelemetry-java/security/advisories/GHSA-ccrj-gw8r-854m) · [MariaDB JDBC advisory](https://github.com/mariadb-corporation/mariadb-connector-j/security/advisories/GHSA-fhx5-2xqw-2cgm)

## 0.5.0 security verification

This review covers the reference Guard, bundled browser apps, wallet bridge and release checks. It uses selected requirements from OWASP ASVS 5.0.0, the OWASP API Security Top 10, NIST SP 800-53 Rev. 5 and the NIST Secure Software Development Framework. [OWASP ASVS](https://asvs.owasp.org/) · [OWASP API Security](https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption/) · [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) · [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final)

| Review area | Relevant controls | Implementation and evidence |
| --- | --- | --- |
| Access boundaries | ASVS V8 and V10, NIST AC-3 and AC-6 | Existing HTTP and browser tests cover exact grants, admin isolation, cross-caller evidence access, bearer validation and Keycloak issuer, audience and role binding. |
| Browser and data protection | ASVS V3.4 and V14.3, NIST SC-18 | HTML responses set opener isolation and restrict objects and form destinations. The Builder clears its admin token when submitting, switching templates or leaving the page. Users can remove the saved local draft while keeping the open text. Chromium exercises these flows, the signed demo links and scoped Swagger export. |
| Security events | ASVS V16.2–V16.4, NIST AU-2, AU-3 and AU-12 | The protected runtime logs access outcomes, rule revisions and evidence export events as JSON. Tests verify actor attribution and exclusion of tokens, submitted claims and raw URLs. Log retention and independent storage belong to the deployment. |
| Wallet resource and input bounds | OWASP API4, NIST SC-5 and SI-10 | The journal enforces per-caller quotas inside the reservation transaction. HTTP tests cover 429 and Retry-After, independent callers and replay protection. Credo rejects malformed encrypted response envelopes before they reach its stateful verifier. The real wallet comparison covers malformed callback, valid retry and replay for both formats. |
| Interrupted wallet evidence | ASVS V16.4, NIST AU-5 and SI-7 | Completion receipts reconcile an evidence write interruption without retaining plaintext claims. Recovery either finds the committed decision or records an indeterminate outcome for the exact session, available as a signed export. Reconcile pending receipts before reverting to an older runtime. [Wallet recovery](WALLET.md#recover-interrupted-evidence) |
| Release integrity and runtime dependencies | SSDF PS.2, PW.4 and RV.1, NIST SI-2 and SI-7 | The release procedure tests the installed wheel, audits runtime dependencies and records the candidate identity and artifact hashes. The kit builder checks those hashes before creating the service archive. The known Credo legacy decoder advisory is scoped to the exact reviewed lockfile. [Release acceptance](DEPLOYMENT.md#release-acceptance) · [Credo dependency review](../integrations/credo/README.md#dependency-audit) |

### Remaining boundaries

- The shared ingress needs aggregate connection and request limits. Wallet quotas bound each caller within the local session journal. Upstream adapter capacity is shared.
- A wallet callback with an acceptable envelope still goes through the verifier. Protect the authorization URL as a short-lived session reference. The envelope checks cover the supported encryption profile and structural errors.
- A shared deployment needs managed token rotation, protected external logs, and an encrypted off-host backup with a restore exercise. Verify the release builder and artifact host separately from the Guard before relying on their provenance. [Deployment boundary](DEPLOYMENT.md)
