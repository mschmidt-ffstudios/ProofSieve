# Deployment boundary

Use the source checkout to develop and run the local reference application. Install a versioned service on Linux with the [service kit](../deploy/README.md). Keep each organization's deployment configuration separate from the source. A company can consume a pinned release while its operators control the trusted issuers, rule state and service access for each environment.

## Configuration and state

Keep site-specific configuration, secrets, writable state and backups outside the source tree. For a local checkout, Git ignores the `instance/` state directory. The repository contains portable examples with placeholder values and public test verification material.

## Run a private local instance

Use `proofsieve --version` to identify the installed API release before starting or switching a service. The command exits before opening application state or starting a listener.

From a checkout with dependencies installed, choose an explicit state file. Keep one ProofSieve process per state file. Start separate processes on distinct ports for independent local environments.

```sh
umask 077
mkdir -p instance
.venv/bin/python -m proofsieve --port 4180 --state instance/rules.json
```

Open the [local workspace](http://127.0.0.1:4180/apps/). When you save a rule, ProofSieve writes it to the selected state file. Protect this file as deployment configuration, back it up before upgrading and restore it with the corresponding runtime version if you need to roll back. The file can contain issuer keys, policy decisions and destination URLs. Its verifier keys are public keys and express the trust selected by the operator.

## Operator access over SSH

For remote operator access, start the service on a Unix socket in an operator-owned directory with mode `0700`. The service sets the socket itself to `0600`. With `--socket`, `--port` specifies the browser-facing forwarding port. Store the service definition and state in your private deployment directory.

```sh
install -d -m 0700 "$XDG_RUNTIME_DIR/proofsieve-demo"
proofsieve --port 24180 --socket "$XDG_RUNTIME_DIR/proofsieve-demo/guard.sock" \
  --auth-config /absolute/private/access.json \
  --state "${XDG_STATE_HOME:-$HOME/.local/state}/proofsieve-demo/rules.json"
```

On the operator's workstation, forward the same port with the server's absolute socket path. Use a verified SSH host key and bind the local tunnel to loopback.

```sh
ssh -N -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:24180:/absolute/private/guard.sock operator@demo-host
```

Open [the forwarded workspace](http://127.0.0.1:24180/apps/). SSH authenticates the connection and encrypts the path to the host. The socket permissions limit access on the host to the service account and privileged local users. The application checks a separate bearer token and endpoint grant on protected requests. Use synthetic credentials and keep the tunnel within the workstation's trust boundary. [Endpoint access](ACCESS.md) · [OpenSSH local forwarding](https://man.openbsd.org/ssh#L)

## Service exposure

The default local development listener binds to `127.0.0.1`. Host and Origin validation and the editor token protect the browser workflow. A client that can reach the local admin endpoint can obtain that token. The reference HTTP server is intended for this local operator workflow. [Python HTTP server guidance](https://docs.python.org/3/library/http.server.html)

For a shared deployment, use the [Nginx and systemd reference configuration](../deploy/README.md) with separate operator and API sockets. Manage caller identities and secret rotation at the deployment level. Keep the demo routes and editor on the operator side. Terminate TLS at the service boundary, apply request limits and define an evidence retention policy before processing real credentials. Use a dedicated service identity and a restricted state directory. Assign ownership for issuer trust and key rotation in the private deployment runbook.

### Shared service deployment

Use an HTTPS reverse proxy as the network listener. ProofSieve can expose two distinct Unix sockets in the same process. The operator socket serves the local UI and administration through authenticated SSH forwarding. The API-only socket permits verification and protected OpenAPI discovery for one exact configured HTTPS origin. Configure the proxy to set that fixed `Host` value and pass the bearer authorization header. The ingress socket independently filters paths and methods. Use a dedicated ingress group when the proxy and Guard run as distinct identities.

```sh
proofsieve --port 24180 \
  --socket /run/proofsieve-admin/guard.sock \
  --proxy-socket /run/proofsieve-ingress/api.sock \
  --proxy-origin https://proofsieve-api.example.test \
  --proxy-gid 12345 \
  --auth-config /etc/proofsieve/private/access.json \
  --state /var/lib/proofsieve/rules.json \
  --evidence /var/lib/proofsieve/evidence.sqlite3
```

Replace the hostname and group ID. The service account must own both socket directories before startup. Add `--checks-config` for document verification connectors and `--evidence-export` to enable signed exports on the operator listener. The admin socket directory has mode `0700`. The ingress directory has mode `0710`, belongs to the service account and has the configured ingress group. Its socket has mode `0660`. Keep the evidence directory owner-only. The reference HTTP handler remains behind the proxy. The proxy should set TLS, body and rate limits, timeout bounds and network access rules. Use the private environment overlay for the actual service definitions, credentials, connector endpoints and TLS paths.

The protected CLI writes JSON security events to standard error. These events record access denials, editor-token failures, saved rule fingerprints, evidence export and wallet throttling. The event includes UTC time, result, and the configured actor and role when known. Headers, tokens, raw URLs, operation references and credentials stay out of these records. When using systemd, collect the service journal with restricted access and a defined retention policy. Forward the events to a protected log sink for a shared installation and monitor repeated denials and service failures.

Before activating a shared instance, test the proxy route and operator separation with real tokens, pin the installed artifact and trust profiles, and rehearse release recovery in a disposable instance.

Stop the Guard before taking a matched backup of its rules, evidence database and wallet session database. Use the SQLite backup API for each database, or copy the database and any existing journal or WAL files from the stopped service as one snapshot. Keep the matching runtime configuration, artifact version and trust files so the snapshot can be reopened. The evidence database includes the input fingerprint key and evidence signing key. Protect backups with the same permissions and retention controls as the live state.

Keep the current state for a version rollback when the previous release can open and use it. A restore from an older snapshot reverts its recorded decisions and replay protections to that point. Before reopening restored endpoints, reconcile deliveries and wallet operations accepted after the snapshot with the authoritative downstream records and prevent those operations from being submitted again.

Open `/apps/api-docs/` through the operator listener for interactive Swagger UI. The API ingress serves protected `/openapi.json` for machine clients. The browser console uses bundled assets and a fixed same-origin specification. Its German and English controls share the workspace language preference. Its token stays in memory and the generated request example omits the injected authorization header. [Vendor version and security review](../apps/api-docs/vendor/README.md)

## Prepare public release artifacts

Build the source archive and Python distributions from a reviewed commit in a clean checkout or CI. Verify that no private directories are tracked before release:

```sh
git ls-files -- internal instance
git archive --format=tar HEAD | tar -tf -
```

The first command must produce no paths. Review the archive listing alongside the wheel and source distribution contents. Keep private deployments, state, credentials and organization-specific endpoints outside those artifacts. Ignore and archive settings protect routine packaging. Publishing a Git repository also publishes its reachable history, so check that history separately before changing repository visibility.

## Release acceptance

Use a clean checkout of the candidate. Run the [verification test set](../examples/acceptance/README.md#workflow-test-set) and the [wallet adapter comparison](../examples/acceptance/WALLET-COMPARISON.md) with fresh test keys and scoped accounts. For the installed recovery check, supply the verified previous and candidate CLI installations to `examples/acceptance/run_wallet_release.py`. The suite checks saved rules, signed exports and replay protection through upgrade, rollback and restoration of a disposable state set.

Build the wheel and source distribution with `python -m build`. On Ubuntu 24.04 amd64 with Python 3.12, install the wheel into a fresh environment. Generate the dependency lock with `examples/acceptance/lock_runtime.py <pinned-dependencies.txt> <runtime-wheel-directory>`. Supply the exact resolved runtime dependencies as `name==version` lines and a directory with one matching wheel per dependency. Exclude the ProofSieve wheel and build or test tools from both inputs. Redirect the output to `requirements-linux-x86_64-py312.txt`. Reinstall using the resulting hashes, run `pip check`, audit the installed dependencies and produce the dependency inventory. Run `tests/smoke_installed.py` against the distributions and the [HTTPS ingress and reboot checks](../deploy/README.md#verify-the-installed-service) against the installed service.

After testing the exact files, record the checked-out commit and ref in `candidate.json` under `commit` and `ref`. Add a `sha256` object that maps the wheel, source archive and `requirements-linux-x86_64-py312.txt` basenames to their lowercase SHA-256 digests. The kit builder checks the staged files against these digests. Record the tested runtime versions in `runtime.json`. Place the two JSON files and the dependency lock in the same metadata directory. Keep the public metadata limited to source and build provenance. Run the kit builder from the Git checkout of the tested commit on Linux with Bash, Git, jq, Python 3 and GNU coreutils.

```sh
bash deploy/build-service-kit.sh dist /path/to/release-metadata \
  dist/proofsieve-0.5.0-linux-x86_64-py312-service.tar.gz
```

The kit contains the exact wheel and source distribution, the installation guide and operator documentation, the hash-locked dependencies and a checksum manifest. Verify the manifest after extraction and compare `candidate.json` with the intended source ref. Keep raw logs, internal screenshots and detailed test evidence with the operator's release record. Publish the reviewed distributions, checksums, dependency inventory and release notes.
