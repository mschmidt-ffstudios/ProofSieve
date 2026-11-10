# Wallet presentation verification

Wallet endpoints use an operator-configured verifier to verify a presentation before running ODRL. Each endpoint selects either the EUDI Reference Verifier or the optional Credo bridge. Both accept one SD-JWT VC or one ISO mdoc per cross-device OpenID4VP session. ProofSieve generates a fresh nonce and retrieves the result over authenticated private HTTPS. Callers submit a session reference. The EUDI adapter targets reference revision [fd46c1fdba40](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint/tree/fd46c1fdba404f44607591ac3574af9a6da222d8).

## Configure the EUDI adapter and wallet endpoint

Start the reference verifier with a registered intended use, a suitable access certificate and its `x509_hash` client identifier. Classify each requested `vct` or `docType` using the verifier's `verifier.attestation-classifications` setting. Route wallet traffic to its HTTPS wallet-facing origin. Keep its `/ui/` and `/utilities/` API behind a separate private HTTPS listener that enforces the dedicated service bearer token. Restrict network egress and certificate resolution at the verifier as well as at ProofSieve. The reference verifier can retain presentation events. Configure its data access and lifecycle separately. [Reference verifier setup](https://docs.eudi.dev/latest/build/build-your-remote-verifier/)

Prepare an ODRL rule in decision mode for the selected endpoint using the projected claim names. With the service stopped, put the rule in the private state file under `rules["/verify/wallet-pid"]` in the version 1 state envelope. Keep the existing `/verify` rule. Add `"wallet": true` to the wallet rule beside `language`, `policy` and `responseMode`. Start the service with the matching operator profile below. It requires both files to agree on the wallet endpoint at startup.

```json
{
  "version": 1,
  "sessionLimits": {"recentPerCaller": 16, "retainedPerCaller": 500},
  "connectors": {
    "reference": {
      "url": "https://verifier-private.example.test",
      "allowedNetworks": ["10.40.1.20/32"],
      "bearerEnv": "PROOFSIEVE_WALLET_TOKEN",
      "publicOrigin": "https://wallet-verifier.example.test",
      "clientId": "x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
  },
  "endpoints": {
    "/verify/wallet-pid": {
      "connector": "reference",
      "profile": {
        "format": "dc+sd-jwt",
        "credentialType": "urn:eudi:pid:1",
        "issuer": "https://issuer.example.test",
        "issuerChainPem": "<operator-approved PEM X.509 certificates>",
        "intendedUseId": "1",
        "claims": {
          "surname": {"path": ["family_name"], "type": "string"}
        },
        "status": {"mode": "not-required"}
      }
    }
  }
}
```

Keep the configuration owner-only. Supply the private bearer through the named environment variable. Use optional `caFile` for a private TLS CA. Start ProofSieve with `--wallet-config`, `--wallet-sessions`, `--auth-config`, `--state` and `--evidence`. The session and evidence databases are separate private files. Give callers exact grants to their wallet endpoints.

`sessionLimits` is optional. Each caller can start 16 sessions within a rolling five-minute window and hold 500 journal entries within retention across all wallet endpoints. The limits count completed and failed starts because the verifier may still hold those sessions until its deadline. Configure `recentPerCaller` from 1 to 64 and `retainedPerCaller` from 1 to 2500. If the retained cap is lower than the recent cap, it also limits starts in the five-minute window. The journal has 10,000 shared entries, and Credo has 128 shared upstream sessions until their own expiration. Size the per-caller limits for your upstream capacity and enforce aggregate traffic limits at ingress.

For a downgrade to a runtime that predates `sessionLimits`, restore a compatible wallet configuration. The quotas use the existing session journal schema.

For mdoc, choose `mso_mdoc` and the document type, omit `issuer`, and map each claim using `["namespace","element"]`. The same claim names can be projected from both formats into separate endpoints with equivalent rules. Use `not-required` only for an explicitly approved status policy such as a disposable synthetic test. Where status is required, use `jwt-file` for SD-JWT VC or `cwt-file` for mdoc with `uri`, absolute `file`, pinned `publicKeyPem` and `maxAgeSeconds`. The operator supplies and refreshes signed snapshots at the configured path. ProofSieve checks the status URI, signature, validity and referenced bit or identifier independently of the verifier. Stale or untrusted snapshots block approval.

## Configure the optional Credo adapter

Run the Credo bridge as a separate Node.js service. Its wallet listener serves the OpenID4VP request and response routes. The private loopback HTTPS listener accepts calls from ProofSieve using a dedicated bearer. Provide a TLS certificate for the listeners and a verifier signing certificate and key for the OpenID4VP request. The configured `clientId` is `x509_hash:` followed by the base64url-encoded SHA-256 digest of the verifier leaf certificate in DER form.

Add a connector with `"kind": "credo"` to the same `connectors` object. Set `url` to the private listener, `publicOrigin` to the wallet-facing HTTPS origin, and configure `allowedNetworks`, `bearerEnv`, `clientId` and `caFile` for that service. Point the applicable `endpoints` entries at the new connector. The formats, issuer trust, claim mapping, status settings and Guard API use the same configuration as above. Existing connector entries without a kind keep the EUDI adapter.

Credo verifies the presentation and holder binding before the bridge releases the result. The bridge binds the nonce in Credo's signed request to ProofSieve's separate transaction nonce. ProofSieve projects typed claims and checks the configured status policy. The signed evidence records the configured connector ID and presentation format. Restrict the private listener to the operator network and configure issuer trust for each profile. [Credo OpenID4VC](https://credo.js.org/guides/protocols/openid4vc) · [Credo service](../integrations/credo/README.md)

## Call the Guard

In Swagger UI or the Guard, use a fresh operation reference for each business operation. Send these two requests to the same endpoint with the same authenticated caller.

```json
{"operationId":"order-1042","data":{"action":"start"}}
```

The HTTP 201 response supplies `sessionId`, `authorizationRequestUri` and `expiresAt`. Pass the authorization request URI to a compatible wallet. Then submit the completion request.

```json
{"operationId":"order-1042","data":{"action":"complete","sessionId":"<sessionId returned by start>"}}
```

| Response | Meaning |
| --- | --- |
| 202 | Presentation is still pending. Check again using the same session. |
| 200 | Presentation and policy passed. The response includes a decision ID. |
| 403 | Access, presentation or policy was refused. Recorded decisions include a reason. |
| 404 | No available session matches this caller, endpoint and operation. |
| 409 | The operation is already reserved, the session was consumed or the configuration changed. A completion whose decision was already recorded or whose evidence has been retired can also return this conflict. |
| 429 | The caller's wallet start quota is full. `Retry-After` and `retryAfterSeconds` give the wait in seconds before another start may fit. Existing sessions can still be completed. |
| 503 | The verifier, status snapshot, journal or evidence is unavailable, or the session has a recorded indeterminate decision. Keep the operation blocked. |

The default session lifetime is five minutes. The journal retains replay records for 24 hours after expiration. During that retention period, completing a matching session that expired without a confirmed result records an indeterminate decision with reason `wallet_expired` and a decision ID. This records the local deadline. The caller can retry the same completion to retrieve the same decision, then use its decision ID for the signed evidence export. A timed-out presentation does not establish how the external wallet or verifier handled it. A decision uses a single session and the saved rule and profile versions. Evidence records the decision, a fingerprint of evaluated data and verifier provenance. The local operation reference correlates the presentation with an API operation. A wallet-signed confirmation of business terms requires a separate transaction-data profile. Keep the same journal across restarts and invalidate pending sessions after restoring an older snapshot.

## Recover interrupted evidence

If completion returns HTTP 503 with `code: evidence_unavailable`, keep the operation blocked and repeat the exact completion. Use the same authenticated caller, endpoint, operation reference and session ID. The server reconciles the completion receipt with the evidence database. When the original decision was absent, a successful recovery returns HTTP 503 with `valid: false`, `outcome: indeterminate`, `reason: wallet_evidence_interrupted` and a decision ID. The Guard presents that terminal decision and offers its signed export when export is enabled.

A recorded decision can yield HTTP 409 on a retry, including after recovery was acknowledged. To locate existing evidence, use the permitted export for that endpoint and operation reference. When you have the decision ID, pass it to retrieve only that decision. A conflict response leaves the operation blocked. Review the separately recorded outcome through the signed export.

The existing version 1 stores gain additive completion metadata. The completion receipt binds recovery to the session and stores no plaintext claims or raw presentation. A receipt can be recovered for up to 24 hours from session creation. A compact commit marker prevents a retry from issuing a replacement decision after the original evidence has expired. The marker contains only the opaque decision ID and commit time. An expired recovery leaves the operation blocked.

Keep the journal and evidence database together across restart or restore. Before switching to an older runtime, run the following command as the service user against the matched wallet journal.

```sh
proofsieve --wallet-receipts --wallet-sessions /path/to/wallet.sqlite3
```

The command exits with status 1 when any receipt remains pending. Use the displayed caller, endpoint and operation to coordinate the exact authorized retry before taking a stopped snapshot. Each caller keeps its original session ID. An expired receipt can leave the ordinary replay reservation in place until its separate retention deadline. The `wallet_expired` path continues to record the local deadline as before.

## Interoperability boundary

The selected verifier is responsible for the presentation protocol and wallet key binding. ProofSieve trusts its authenticated private result and projects only configured typed claims. The integration exercises the cross-device signed-request and encrypted-response profile with X.509 trust and one requested credential. The supported flows and the boundaries for ISO proximity, browser-mediated flows and trust lists are listed under [wallet interoperability](STATUS.md#wallet-interoperability). The EU PID `x5u` and certificate thumbprint profile and wallet sandbox conformance require separate validation. Wallet endpoints cannot use server-side forwarding. If an application acts on an approved wallet decision, bind it to that pending operation and its expected payload. [EU PID and presentation profiles](https://eur-lex.europa.eu/eli/reg_impl/2026/1731/oj/eng)
