# Server-side forwarding

A deployment operator can attach a fixed HTTPS receiver to an exact verification path. ProofSieve authenticates the verifier, checks the input against the saved rule and records the decision before sending. A denied or indeterminate verification sends nothing. The rule preview has no delivery side effect.

## Configure a receiver

1. Set the saved rule's response mode to `decision`. Use a JSON request envelope containing `operationId` and `data`. Use a stable operation ID for retries of the same business operation.
2. Provide `--forwarding-config` with an owner-only JSON file alongside the protected `--auth-config` and `--evidence` options. Keep private files and tokens in the deployment environment.
3. Give the service its own bearer token through the named environment variable. Restrict the receiver's network access and set its allowed destination CIDRs. ProofSieve pins the resolved address at startup and verifies the receiver's TLS certificate and hostname. Restart to apply target or DNS changes.

```json
{
  "version": 1,
  "endpoints": {
    "/verify/orders": {
      "url": "https://orders.example.test/api/approved-orders",
      "allowedNetworks": ["10.40.1.20/32"],
      "bearerEnv": "ORDERS_SERVICE_TOKEN",
      "timeoutSeconds": 3
    }
  }
}
```

Use optional `caFile` to supply an absolute path to a private CA bundle. The receiver gets one `POST` with the original JSON bytes, a dedicated bearer token and a stable `Idempotency-Key`. Choose a receiver trusted to handle the entire submitted payload, including any signed credentials or documents in `data`. Use a shared payload schema, with strings for identifiers and precise decimals when the verifier and receiver parse JSON numbers differently. The caller's token stays at ProofSieve. The receiver's status is reported without relaying its response body or following redirects.

## Interpret the result

| HTTP response from ProofSieve | Decision | Delivery state |
| --- | --- | --- |
| 200 | Allowed | `delivered`, receiver returned 2xx |
| 403 | Denied | `not_forwarded` |
| 503 | Indeterminate | `not_forwarded` |
| 409 | An approved request reused the operation ID with different input | No new delivery |
| 409 | The operation is reserved and its original approval has expired from evidence retention | No new delivery |
| 502 | Allowed | `rejected`, receiver returned a non-2xx status |
| 503 | Allowed | `pending` or `unknown`, delivery has no confirmed outcome |

The decision describes the policy check. The delivery state describes the downstream handoff. Only `delivered` confirms that the receiver acknowledged the request, and the business meaning of that acknowledgment follows the receiver's API contract.

The evidence database records the approval and reserves one delivery attempt in the same transaction for each combination of verifier identity, exact path and operation ID. When the current policy still approves a retry with the same input, the response returns the original decision ID and rule version with the recorded delivery state. The signed evidence for that decision contains the corresponding delivery record. The journal retains reservations independently of decision retention. After the original approval expires, the retry returns `operation_evidence_expired`. The journal rejects new reservations when its capacity is exhausted.

Investigate rejected, pending or unknown attempts with the receiver before authorizing a new operation. A backup taken before a reservation can produce a new delivery ID for that operation. Reconcile older backups with the receiver before reopening traffic and deduplicate by business operation on the receiver if it must tolerate that recovery scenario.
