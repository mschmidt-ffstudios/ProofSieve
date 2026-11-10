# Verification acceptance suite

The suite runs the supplier portal flow with real Keycloak service-account tokens, ProofSieve, a self-hosted Java DSS validation bridge, and a signed OCSP responder. It creates fresh keys, certificates, rules, and evidence for each run. The default topology sends portal requests over HTTPS to an API-only Unix socket and keeps the administrator on a separate operator socket.

## Reproduce a run

Use Python 3.10 or newer, Maven, and a JDK 25 installation. The tested Keycloak distribution is 26.8.2. The Maven project pins DSS 6.5.1 and uses its CAdES, PAdES, and signature-validation modules. Run from the ProofSieve checkout or extracted source distribution.

Download and verify the official Keycloak server archive from Maven Central in a working directory of your choice.

```sh
curl --fail --location --output keycloak-26.8.2.tar.gz \
  https://repo.maven.apache.org/maven2/org/keycloak/keycloak-quarkus-dist/26.8.2/keycloak-quarkus-dist-26.8.2.tar.gz
printf '%s  %s\n' \
  07e0704b5084b2d5c0d065951878334f62f09f7d88d193e945063698fad199a2a8b77d947404f5f99f7878ff97588c6de1be64470afe6145f44a8eb9e7dd245e \
  keycloak-26.8.2.tar.gz | shasum -a 512 -c
tar -xzf keycloak-26.8.2.tar.gz
```

On Apple silicon, the tested JDK was Temurin 25.0.5+8. The vendor provides separate archives and SHA-256 checksums for other systems. Set `JAVA_HOME` to the extracted Java home, such as `jdk-25.0.5+8/Contents/Home` on macOS. [Official Temurin release](https://github.com/adoptium/temurin25-binaries/releases/tag/jdk-25.0.5%2B8)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python examples/acceptance/run.py \
  --keycloak-home /absolute/path/keycloak-26.8.2 \
  --keycloak-java-home "$JAVA_HOME" \
  --report ./acceptance-report.json
```

The report path must be new. It contains version numbers, transport, case names, HTTP statuses, decision reasons and IDs, and the evidence record count. The command exits unsuccessfully at the first mismatched assertion. Services bind to disposable loopback ports. A private temporary directory holds test certificates, keys, tokens, the copied Keycloak distribution, the SQLite evidence store, and service logs until teardown. The optional `--transport loopback` exercises the reference listener while Keycloak, DSS, and OCSP still use HTTPS.

## Inputs and expected decisions

| Case | Input and configured trust | Expected result |
| --- | --- | --- |
| Supplier approval | Real Keycloak token with audience `proofsieve-api` and a client role mapped to `/verify/supplier-orders`. An ES256 issuer signs the supplier SD-JWT VC. | ProofSieve returns `allow`, a rule version, and a decision ID for the specific operation. |
| Access isolation | Missing, expired, or tampered token, wrong audience, valid token with no role, valid role sent to a different route, and admin access via the verification API. | The bearer checks return 401 for invalid authentication and 403 for missing privileges. The API-only proxy and socket reject admin access. |
| Claims and business policy | A reviewer lacks the enrollment claim required by the rule. The same reviewer discloses a modified role in a separate request. | The first case reaches ODRL and returns `policy_denied`. The altered disclosure returns `credential_rejected`. |
| Portal enforcement | The portal records the pending order and exact submitted input. It tries to reuse the approval for another order, a different input, and a repeated submission. | The approval releases the pending order once. The operation ID correlates the response. The portal checks the order, submitted input, and single-use business state. |
| Two of three signers | A signs the order bytes locally. B supplies a detached DSS-generated CAdES signature. C signs locally and passes a fresh, issuer-signed OCSP check. | A+B, A+C, and A+B+C pass. A alone, signatures over another order, a tampered CAdES signature, and an unlisted certificate fail. A repeated signer is rejected as malformed. |
| Rule runs on checked facts | The signature adapter accepts two signers while the test ODRL policy separately requires three. | The check succeeds and ODRL returns `policy_denied`. |
| OCSP status | The same signed order and pinned certificate receive good, revoked, unknown, stale, wrong-nonce, and unauthorized-signer responses. | A fresh authenticated good status counts. Revocation denies. Untrustworthy or inconclusive status produces `indeterminate` when the threshold depends on it. |
| Organization seal | DSS generates a PAdES baseline B signature over a test PDF using the fictional organization's certificate. The harness changes the signed page text, appends unsigned bytes, and tries a different signer pin. | The original passes. Each variation fails. |
| Self-signed and expired certificates | One test signer is directly self-signed and pinned. A different identity signs the same order as a negative case. Another fixture uses an expired leaf. | The matching self-signed certificate passes. The wrong key and expired certificate fail. |
| DSS revocation report | The test signing CA publishes a signed CRL that revokes the test certificate. DSS evaluates the detached signature and its validation evidence. | The DSS `INDETERMINATE` result stays indeterminate and the order remains blocked. |
| DSS configuration and outage | A rule names an unconfigured connector. Then the live DSS service is stopped during otherwise identical 2-of-3 checks. | The unconfigured rule is rejected. An outage returns 503 if the result depends on DSS. Two independently confirmed signatures still satisfy the threshold. |
| Evidence | SQLite records each live decision with the caller, endpoint, operation, policy version, input fingerprint, outcome and check provenance. | The recorded decisions match their responses. DSS report references and the connector profile are present. The original input stays out of the database. |

The test trust anchors are self-generated and private to the run. The PAdES example demonstrates an organization seal under that test trust model. Qualification under a regulated trust scheme requires separately configured trust sources and criteria. The loopback DSS bridge exposes validation only, uses the test trust root and signed CRL, and runs inside the acceptance suite. [DSS documentation](https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/doc/dss-documentation.html)

## Workflow test set

Run from the checkout with the [browser test dependencies](../../CONTRIBUTING.md) installed. With both toolchain paths, the runner executes the Python unit and HTTP tests, company cases, six Chromium suites, the Keycloak and DSS HTTPS flow above, and the additional DSS document cases. A failure in any layer makes the runner exit unsuccessfully. Without the two toolchain paths it reports both Java-dependent layers as skipped.

```sh
.venv/bin/python examples/acceptance/run_testset.py \
  --keycloak-home /absolute/path/keycloak-26.8.2 \
  --java-home "$JAVA_HOME" \
  --supplier-report /absolute/path/new-supplier-report.json
```

| Implemented path | Acceptance coverage |
| --- | --- |
| Builder, Guard editor and Lab | JSON and Turtle handoff, file import and exact input preservation, allowed and blocked cases, invalid payloads, nested ODRL graph and rule trace, concurrent save conflict, and DE/EN screens. The Lab runs synthetic cases separately from live checks. |
| Guard, rules and credentials | Per-endpoint rules and response modes, ODRL and SHACL, valid and forged SD-JWT, ISO mdoc, JWT VC and W3C Data Integrity inputs. Check disclosure binding, expiry, type, issuer, algorithm and unsupported inputs. |
| Scoped access and operation routing | Admin and verifier scopes, issuer and audience checks, Keycloak service-account tokens, private sockets and browser token handling. Check exact-payload forwarding on approval, denied forwarding, retries and replay, upstream failure and transport restrictions. |
| Documents and trust | A local signature, external DSS and combined checks, 2-of-3, self-signed and expired certificates, OCSP, CRL, CAdES, PAdES, XAdES, JAdES, CB-AdES, ASiC-S, ASiC-E and RFC 3161. Check altered documents and containers, failed trust and unavailable services. |
| Bundles and evidence | Multiple proofs, cross-claim matching and operation binding, evidence scope, export integrity and tamper rejection. Check signed downloads in Swagger and that stored evidence excludes submitted payloads. |
| Deployed wallet adapters | The separate browser comparison below covers real SD-JWT VC and mdoc presentations, rule allow and deny, nonce rejection, adapter provenance, and signed Swagger downloads. Core wallet tests additionally exercise replay, caller binding, signed JWT and CWT status snapshots, and connector restrictions. |

See the [supported profiles and limitations](../../docs/STATUS.md#scope-and-limitations) for the scope of the implementation. Tests with locally generated seals and certificates establish behavior under the configured test trust model.

The separate [wallet adapter comparison](WALLET-COMPARISON.md) documents its service setup, cases, and signed browser evidence. See the [release acceptance guide](../../docs/DEPLOYMENT.md#release-acceptance) for the packaging and installed checks.
