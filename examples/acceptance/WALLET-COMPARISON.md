# Compare Credo and the EUDI Reference Verifier

The browser test signs disposable SD-JWT VC and mdoc inputs, opens Guard and Swagger as a scoped verifier, submits real OpenID4VP presentations, and downloads the evidence from Swagger. Both adapters receive the same issuer-signed credential and holder or device key for each case. The runner signs a fresh holder binding for each verifier challenge and verifies that all 12 challenges are distinct.

## Prepare a test instance

Use an isolated ProofSieve deployment and the [wallet setup instructions](../../docs/WALLET.md) to configure both adapters. Run the Guard through an HTTP loopback listener or tunnel. Keep each wallet listener on HTTPS. Use only synthetic credentials and test trust anchors.

Generate private fixtures in a new directory. The host must match the wallet HTTPS listener used for this run.

```sh
.venv/bin/python examples/acceptance/wallet_cases.py ./wallet-fixtures --host 127.0.0.1
```

Configure both wallet profiles with the generated `issuer-ca.pem` and an explicitly registered test intended use. Use the fixture reader certificate and key or equivalent per-adapter request-signing certificates. The command below pins each request signer separately.

| Format | Credential type | Projected claim path |
| --- | --- | --- |
| `dc+sd-jwt` | `urn:eudi:pid:1` with issuer `https://issuer.example.test` | `surname` from `["family_name"]` |
| `mso_mdoc` | `eu.europa.ec.eudi.pid.1` | `surname` from `["eu.europa.ec.eudi.pid.1", "family_name"]` |

Use connector IDs `credo` and `eudi-reference`. Configure the matching profiles on `/verify/compare/credo-sd-jwt`, `/verify/compare/eudi-sd-jwt`, `/verify/compare/credo-mdoc` and `/verify/compare/eudi-mdoc`. Each endpoint uses the same ODRL decision rule with `wallet: true` and a constraint of `field:surname eq "Mustermann"`. Use `status.mode: not-required` for these disposable credentials. Grant a verifier exactly the four test endpoints. Save its token to an owner-only file and export the service's public evidence signing key to a separate file from the operator side.

## Run the cases

Install ProofSieve and Playwright in a Python virtual environment. Install the Chromium version expected by Playwright.

```sh
.venv/bin/python -m pip install . playwright==1.60.0
.venv/bin/python -m playwright install chromium

.venv/bin/python examples/acceptance/run_wallet_comparison.py \
  --guard http://127.0.0.1:4180 \
  --credentials ./wallet-fixtures \
  --credo https://127.0.0.1:4140 ./wallet-fixtures/tls-ca.pem ./wallet-fixtures/verifier.pem \
  --eudi https://127.0.0.1:4141 ./wallet-fixtures/tls-ca.pem ./wallet-fixtures/verifier.pem \
  --token-file ./verifier-token \
  --evidence-key-file ./evidence-public-key \
  --output ./wallet-acceptance-results
```

Provide the actual TLS CA and request signer for each wallet listener. The output directory must be new. The report records operation and decision IDs, HTTP statuses, sanitized browser screenshots and downloaded evidence filenames. It verifies the Ed25519 signature against the pinned public key and checks that changing a decision invalidates the signature.

| Case | Credo | EUDI Reference Verifier |
| --- | --- | --- |
| Signed `Mustermann` with the current challenge | Guard allows and Swagger exports the decision | Guard allows and Swagger exports the decision |
| Signed `Anders` with the current challenge | Wallet checks pass, ODRL denies, Swagger exports the decision | Wallet checks pass, ODRL denies, Swagger exports the decision |
| Signed `Mustermann` with a wrong challenge | Wallet rejects, Guard records a denial, Swagger exports the decision | Wallet rejects, Guard remains pending and Swagger returns 404 for that operation |

The last row captures the behavior of the pinned reference verifier in this setup. Its public wallet endpoint rejects the presentation while its private API continues to report that a presentation has yet to be submitted. A pending session stays blocked and has no decision to export.

## Credo advisory regressions

Add `--check-credo-envelope` to the browser comparison command to run the optional Credo hardening checks. The disposable release environment enables this flag. Alongside the existing 12 comparison cases, the report lists two Credo SD-JWT cases in `credoAdvisoryCases`. Both use fresh challenges, a matching signed credential, and a correctly encrypted response.

| Case | Wallet response under test |
| --- | --- |
| `pex-downgrade` | Submit a legacy Presentation Exchange response to a DCQL request. |
| `unbound-disclosure` | Append a disclosure absent from the issuer's signed digest list, then sign the holder binding over the altered presentation with the current challenge. |

Both wallet callbacks must return HTTP 400. Guard must return HTTP 403 with `wallet_rejected`. The wallet callback and exact Guard completion replays must return HTTP 409. Swagger must export exactly one signed denial for each operation. See the [Credo dependency audit](../../integrations/credo/README.md#dependency-audit) for the scope and expiry of the release exception.

## Run with a disposable release environment

The release harness starts both wallet verifiers and the exact checkout's Guard in a disposable environment. Run it from a clean checkout with the documented toolchain and a new output directory.

```sh
.venv/bin/python examples/acceptance/run_wallet_release.py \
  --revision "$(git rev-parse HEAD)" \
  --eudi-jar "$PROOFSIEVE_EUDI_JAR" \
  --java "$JAVA_HOME/bin/java" \
  --askar-library-dir "$LIB_ASKAR_PATH" \
  --output ./wallet-release-results
```

The EUDI JAR is checked against the digest in `eudi_runtime.py`. The harness installs the locked Credo dependencies with lifecycle scripts disabled. It writes the outcome, public key and validated outputs separately from the disposable credentials and service state. See the [release acceptance guide](../../docs/DEPLOYMENT.md#release-acceptance) for the installed package checks.

For the installed recovery check, also pass `--previous-binary` and `--candidate-binary` with CLI paths from separate installations of the previous release and the proposed upgrade. The runner reuses its disposable Credo service and creates an independent rules, evidence and wallet state set. See `upgrade-rollback.json` in the output for the results.
