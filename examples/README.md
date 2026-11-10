# Worked examples

Each file contains format selection, check configuration, an ODRL policy, an output mode and synthetic decision cases. The example inputs stand for verified facts. The cases can be used to check policy evaluation without test certificates, live services or issuer credentials.

| Example | Grants approval when | Counterexample | Output |
|---|---|---|---|
| [01 · Two of three signers](01-two-of-three.json) | At least two distinct allowed signers prove a signature on the same payment order. | Two signatures from one signer or a second signature over different content. | Continuation link |
| [02 · SD-JWT VC membership](02-member-credential.json) | The active credential comes from an authorized issuer and belongs to the authenticated member. | Valid signature from an issuer outside the membership trust configuration. | Boolean |
| [03 · Wallet presentation](03-wallet-presentation.json) | The verified mdoc presentation is bound to a fresh, unused verifier session. | Wrong verifier, expired session window or replay. | Boolean |
| [04 · JSON-LD context](04-jsonld-context.json) | The approved contexts and content pins match, the type expands as expected and the proof verifies. | Extra context or a mismatch in a pinned context document. | Boolean |
| [05 · Qualified seal](05-qualified-seal.json) | The PDF seal validates and its qualification can be established. | A valid seal without the required qualification. | Boolean |
| [06 · Fresh MFA](06-fresh-mfa.json) | A trusted OIDC session establishes the required MFA assurance within five minutes. | A stale session or missing authentication time. | Server-side forwarding |
| [07 · External revocation status](07-external-status.json) | An approved status source provides fresh, verified evidence of non-revocation. | Revoked credential, untrusted status list or timeout without usable evidence. | Boolean |
| [08 · Identification assurance](08-assurance-level.json) | The trusted eIDAS assertion establishes substantial or higher assurance within that scheme. | A low level or an unrecognized scheme identifier. | Boolean |
| [09 · Detached timestamp](09-detached-timestamp.json) | A trusted timestamp token covers the exact submitted artifact. | A valid token attached to different content. | Boolean |
| [10 · DIDComm destination](10-did-service.json) | A DID document advertises a well-formed DIDComm service within the approved destination origins. | A structurally valid service points outside the allowlist. | Boolean |

The set uses reserved example domains and synthetic identifiers. The checks describe what an implementation must verify. The `cases` arrays capture expected decisions and the reasons to record in evidence. See the [policy and example conventions](../docs/ODRL-PROFILE.md).
