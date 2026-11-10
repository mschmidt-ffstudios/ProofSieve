# Endpoint access

The protected API authenticates callers with bearer tokens. The access file maps opaque token digests to identities and exact verification paths. It can also map signed [Keycloak service-account tokens](#keycloak-service-accounts) to verifier grants. Keep the raw token with its caller and the digest file in the service's private deployment directory. Use authenticated SSH forwarding for remote operator access. [Deployment boundary](DEPLOYMENT.md)

| Request | Admin | Verifier |
| --- | --- | --- |
| `GET /auth/me`, `GET /openapi.json` | Lists the caller's existing, granted endpoints | Lists the caller's existing, granted endpoints |
| `GET /admin/rule?endpoint=…` | Reads the rule for a granted path | `403` |
| `PUT /admin/rule?endpoint=…` | Changes a granted writable rule with its editor token | `403` |
| `POST /admin/test-rule?endpoint=…` | Previews a draft for a granted path with its editor token | `403` |
| `POST /verify…` | Evaluates a granted path | Evaluates a granted path |
| `GET /evidence` on the operator listener when export is enabled | Exports this caller's decisions for a granted path | Exports this caller's decisions for a granted path |

Without a valid bearer token, the protected API returns `401`. A valid token without the requested grant receives `403` and `code: forbidden`. An allowed request can still receive a credential or policy refusal. Those results retain the verification response contract. Evidence export also requires the identity that made the verification request. An administrator's role does not expand that caller scope. [Evidence export](PROOF-BUNDLES.md#export-a-decision)

Built-in demo rules are read-only. The bundled synthetic Builder check routes require a global admin in protected mode. The app shell and packaged synthetic examples can be loaded before sign-in.

## Provision access

Generate a separate `secrets.token_urlsafe(32)` value for each identity. Compute SHA-256 over its ASCII text. Store only the lowercase hex digest in the following configuration. Set file ownership to the runtime account and mode `0600`.

```json
{
  "version": 1,
  "principals": [
    {
      "id": "orders-admin",
      "role": "admin",
      "tokenSha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "endpoints": ["/verify/supplier-orders"]
    },
    {
      "id": "orders-verifier",
      "role": "verifier",
      "tokenSha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "endpoints": ["/verify/supplier-orders"]
    }
  ]
}
```

The digests above are placeholders. `endpoints: ["*"]` explicitly grants an admin every verification path and access to the synthetic Builder checks. Verifier grants always list exact paths. An admin grant can also name an endpoint the admin is allowed to create. A Unix-socket deployment requires `--auth-config`. Local development on TCP loopback can start with this option omitted.

Send `Authorization: Bearer <token>` with API requests. An administrator obtains their separate `csrfToken` from `GET /auth/me` or a permitted `GET /admin/rule` and sends it as `X-ProofSieve-Token` on writes and draft tests. The Guard sign-in UI keeps the bearer token in page memory. Signing out clears the UI session. Replace or remove a digest and restart the service to revoke the corresponding API token. [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

`GET /admin/rule` and successful `PUT /admin/rule` responses include the saved rule's `ETag`. Send that exact value as `If-Match` when saving an edit. If another editor saved a change first, the server returns `412` with `rule_version_conflict`. Read the current rule and reconcile the changes before retrying. The Guard editor always sends this condition for existing rules. Use `If-None-Match: *` when creating a rule. Integrations that intentionally replace rules can still omit the condition.

An ordinary `POST /verify…` can also send the rule's `ETag` as `If-Match`. A mismatch returns `412` with `rule_version_conflict` before evaluation, evidence recording or delivery. Wallet completion uses the rule revision bound to its session.

## Keycloak service accounts

For a service-to-service integration, use version 2 of the same owner-only configuration file. Keep the existing `principals` list with at least one opaque administrator. Add this `oauth` object alongside it and replace the example values.

```json
{
  "issuer": "https://login.example.test/realms/partner-demo",
  "audience": "proofsieve-api",
  "serviceAccounts": [
    {
      "id": "supplier-portal",
      "clientId": "supplier-portal",
      "subject": "replace-with-keycloak-service-account-subject",
      "grants": {
        "verify-supplier-orders": "/verify/supplier-orders"
      }
    }
  ]
}
```

In Keycloak, create the API client and the confidential caller client with service accounts enabled. Assign the service-account user the API client's `verify-supplier-orders` role and configure the audience mapper so the token's `aud` includes `proofsieve-api`. Copy the service-account user's ID into `subject`. Set a short access-token lifetime. A token needs the configured issuer, audience, client and subject, plus the exact client role in `resource_access.proofsieve-api.roles`. Keycloak service accounts receive verifier rights only. A global opaque admin can change issuer trust, document and bundle profiles, or change a rule out of recorded-decision mode. A scoped admin can edit the policy for a granted endpoint and use its saved profile in the preview.

The API validates RS256 with the configured realm's JWKS and checks the Keycloak bearer-token type and time claims. Unknown keys trigger one bounded JWKS refresh while fresh cached keys remain available. Retain the old public key during a planned rotation until its tokens expire. Removing a service account from the ProofSieve configuration and restarting revokes its local grants immediately. Keycloak changes alone apply to newly minted tokens. Any previously issued token can remain usable within its signed lifetime and the local verification constraints. Use TLS for the realm and the ProofSieve API. `allowLoopbackHttp` exists for explicitly configured isolated development realms on a numeric loopback address. [Keycloak service accounts](https://www.keycloak.org/docs/latest/server_admin/index.html#_service_accounts)

## Builder example checks

In a protected workspace, the Builder offers a password field for the global admin token when a sourced example is selected. Enter the token for each submitted example check. The field is cleared on submission, when switching examples or when leaving the page. The server requires an admin with access to all endpoints for example checks. A verifier can pass JSON or Turtle input to the Guard for a compatible permitted endpoint.
