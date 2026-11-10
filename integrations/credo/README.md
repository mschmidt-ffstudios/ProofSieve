# Optional Credo wallet verifier

The bridge uses Credo TS 0.7.4 for cross-device OpenID4VP 1.0. Each request asks for one SD-JWT VC or one ISO mdoc through DCQL. It signs the Request Object with an X.509 verifier key, requires holder or device binding, and receives an encrypted response. ProofSieve uses the verified result for its own operation, typed claim projection, ODRL evaluation and signed evidence.

Use Node.js 22 or 24. Install the locked npm dependencies in this directory with lifecycle scripts disabled. The Askar Node binding requires the native library from the [Askar v0.5.0 release](https://github.com/openwallet-foundation/askar/releases/tag/v0.5.0). Verify the release archive SHA-256 before extracting it into a private directory. Set `LIB_ASKAR_PATH` to that directory.

| Platform | Archive | SHA-256 |
| --- | --- | --- |
| Linux x64 | `library-linux-x86_64.tar.gz` | `dc243dbfce814905810532885b21945fd62ed5ae3fb006f38c3ecd7c698a2adb` |
| macOS | `library-darwin-universal.tar.gz` | `249f70967fe529433efa135689fedd9d4413a672a2ccca11be6b7ca8161d846d` |

Start the service with an owner-only JSON configuration.

```sh
npm ci --omit=dev --ignore-scripts
LIB_ASKAR_PATH=/absolute/path/askar-native node server.mjs /absolute/path/credo.json
```

```json
{
  "publicOrigin": "https://wallet.example.test",
  "publicHost": "127.0.0.1",
  "publicPort": 24443,
  "privatePort": 24444,
  "tlsCertFile": "/run/proofsieve/tls-chain.pem",
  "tlsKeyFile": "/run/proofsieve/tls-key.pem",
  "verifierCertFile": "/run/proofsieve/verifier.pem",
  "verifierKeyFile": "/run/proofsieve/verifier-key.pem",
  "intendedUseId": "my-wallet-profile",
  "bearerEnv": "PROOFSIEVE_CREDO_BEARER"
}
```

Set the dedicated bearer in the service environment and the ProofSieve environment. Supply a matching P-256 verifier key and a currently valid leaf certificate. The optional `verifierChainFile` supplies the remaining request-signing certificates. Use a valid TLS certificate for both listeners and configure the ProofSieve HTTPS trust accordingly.

Send wallet traffic to the wallet listener under `/oid4vp/proofsieve/`. The private listener binds to loopback and requires the bearer. Point the ProofSieve `kind: "credo"` connector at this private listener. Configure the same intended use in the endpoint's wallet profile. Supply the trusted issuer chain and exact claim mapping through that profile. The existing EUDI reference adapter can be configured for other endpoints in the same Guard process. [ProofSieve wallet setup](../../docs/WALLET.md)

The public callback checks the compact encrypted response and its protected header against the advertised encryption profile before invoking Credo. Malformed envelopes receive HTTP 400 and leave the session available for the wallet's valid response. Credo still verifies the encrypted response and proof. A completed callback cannot be used twice. Keep the authorization URL within the intended wallet flow.

The bridge keeps short-lived Credo records in an encrypted Askar SQLite file in an owner-only temporary directory. The store has a random per-process key kept in memory. Its file survives Askar pool connection retirement and is removed when the process exits normally. Set `TMPDIR` to a private runtime directory on tmpfs when operating the bridge with systemd. The bridge blocks outbound SDK resource resolution. Active sessions expire on service restart. The synthetic test credentials omit network status references. When a presentation requires a blocked upstream status lookup, the Guard keeps the operation blocked. Registered relying-party identity, live trust lists and real-wallet conformance require separate validation.

## Dependency audit

The Askar storage configuration removes Drizzle ORM and its esbuild tooling from the locked dependency tree. The bridge uses a process-local encrypted store and ephemeral keys.

The audit still reports the legacy standalone `@sd-jwt/decode` packages pulled in by Credo's Presentation Exchange dependencies. That decoder has no patched standalone release. This bridge creates only OpenID4VP 1.0 DCQL requests. The active `dc+sd-jwt` validation uses `@sd-jwt/core` 0.21.1, which includes the upstream fix. ProofSieve independently validates the issuer signature and all presented disclosures before using the claims. [SD-JWT security advisory](https://github.com/advisories/GHSA-f9j6-8p6x-r9j6)

The ProofSieve maintainers own the release exception for this advisory. It expires on 2027-02-09. It applies to `@sd-jwt/decode` 0.7.2 and 0.9.2 in the optional Credo bridge and to the reviewed `package-lock.json` with SHA-256 `d7301659103bd4aba96a18e01e711ceda8dee1fb7b342cb8b0e67dac886e35d9`. Install the lockfile as written with `npm ci`. Package flattening, overrides and forced downgrades fall outside this exception. Review the exception before changing the lockfile and resolve or renew it before expiry.

The [release comparison](../../examples/acceptance/WALLET-COMPARISON.md#credo-advisory-regressions) sends a legacy Presentation Exchange response to a live DCQL request and separately adds a disclosure whose digest the issuer did not sign. The latter test signs a fresh holder proof over the altered presentation. Both cases must produce a denial and a single verifiable evidence export, with the callback and completion replays refused.
