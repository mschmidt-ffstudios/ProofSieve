# Install ProofSieve as a Linux service

This reference installation uses Ubuntu 24.04 amd64, Python 3.12, systemd and Nginx. It gives applications an HTTPS verification API and gives authorized operators a separate Unix socket for the workspace, rule management and signed evidence export. [Access model](../docs/ACCESS.md) · [Deployment boundaries and recovery](../docs/DEPLOYMENT.md)

| Listener | Access |
| --- | --- |
| Nginx HTTPS to `/run/proofsieve-ingress/api.sock` | `GET /openapi.json` and `POST /verify` or an exact granted `/verify/…` path. Verification demo routes stay on the operator side. |
| `/run/proofsieve-admin/guard.sock` | Guard, Builder, Lab, Swagger UI, scoped API and rule administration, and signed evidence export. The service owner can open this socket. Application privileges are checked separately. |

## Install the release wheel

Use the service bundle attached to the intended release, if available, or follow the [kit build procedure](../docs/DEPLOYMENT.md#release-acceptance) from a reviewed source checkout. For a downloaded bundle, compare the archive with its SHA-256 digest from the trusted release channel before unpacking. Match the ref and commit in `candidate.json` to the intended source version, then verify the embedded `SHA256SUMS` in the unpacked directory. Use the verified `deploy/` templates from the same bundle. Create a new versioned installation each time. The venv stays at the path where it was created.

The commands below assume a Linux administrator shell, a verified bundle with `dist/`, and one wheel in that directory. Install `python3.12-venv`, `nginx`, `openssl` and `curl` on the host first. Run these examples in Bash.

```sh
sha256sum --check SHA256SUMS || exit 1
wheel=(dist/proofsieve-*-py3-none-any.whl)
test "${#wheel[@]}" -eq 1 && test -f "${wheel[0]}" || exit 1
release=/opt/proofsieve/releases/0.5.0
sudo install -d -o root -g root -m 0755 /opt/proofsieve/releases
sudo mkdir -m 0755 "$release"
sudo bash -ec '
  umask 022
  python3.12 -m venv "$1"
  "$1/bin/python" -m pip install --require-hashes --only-binary=:all: -r "$2"
  "$1/bin/python" -m pip install --no-deps "$3"
  "$1/bin/python" -m pip check
' _ "$release" "$PWD/requirements-linux-x86_64-py312.txt" "$PWD/${wheel[0]}"
"$release/bin/proofsieve" --version
```

For the first installation, point the service at this validated release with `sudo ln -s "$release" /opt/proofsieve/current`. During upgrades, switch the symlink only after the state backup in the recovery procedure below. Keep executable code root-owned and application state under the service account.

## Set up service and ingress

1. Create a `proofsieve` system user with primary group `proofsieve-ingress`, no home directory and no interactive shell. Add the Nginx worker identity to `proofsieve-ingress`. Use a dedicated proxy worker identity where required by your access policy. Restart Nginx after changing its worker's group membership. An ingress group member can traverse `/run/proofsieve-ingress` and connect to the API socket. The admin socket directory remains private.
2. Create `/etc/proofsieve/private` with mode `0700` and owner `proofsieve`. Copy `service.env.example` there as `service.env` with mode `0600`. Set the numeric group ID from `getent group proofsieve-ingress`, the intended HTTPS origin and the evidence retention days. A release update does not replace this file.
3. Create `/etc/proofsieve/private/access.json` with owner `proofsieve` and mode `0600`. Use `access.json.example` as a schema. Generate a separate random token for each identity and store its SHA-256 digest in the config. Give the raw token only to its intended caller. The example verifier may call `/verify`; add exact endpoint grants to use other paths. [Token setup and optional Keycloak service accounts](../docs/ACCESS.md#provision-access)
4. Render `nginx.conf.example` with the selected DNS name in `server_name`, the host check and the upstream `Host` header. Match the `PROOFSIEVE_PROXY_ORIGIN` value. Replace the example allowed network with the actual application network. Install the vhost in Nginx's `http` configuration. Install the certificate chain and key at the configured paths, or point both paths to the certificate manager's files. The DNS name must be in the certificate, and the private key must have restricted permissions.
5. Install the supplied unit under `/etc/systemd/system/`, then check both configurations before activation.

```sh
sudo install -m 0644 proofsieve.service /etc/systemd/system/proofsieve.service
sudo systemd-analyze verify /etc/systemd/system/proofsieve.service
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now proofsieve.service
sudo systemctl reload nginx.service
```

Run the last block from the `deploy/` directory. Inspect `journalctl -u proofsieve.service` through authorized system access. The unit creates `/var/lib/proofsieve` and the socket directories. Its process starts the default JSON policy until an authorized operator saves rules. Before opening the ingress to application traffic, verify the selected policy and endpoint grants with the application identity.

The supplied unit starts the verification service and the operator's signed export. To enable optional features, add a private systemd drop-in with an empty `ExecStart=` followed by the unit's `ExecStart` line with the additional arguments. Keep the socket-permission setup and base arguments. Enable only the features configured in the target. [Wallets](../docs/WALLET.md#configure-the-eudi-adapter-and-wallet-endpoint) · [Forwarding](../docs/FORWARDING.md) · [Document checks and DSS](../docs/DOCUMENT-CHECKS.md)

## Verify the installed service

Use a dedicated, narrowly scoped verifier token to check authenticated OpenAPI access over trusted HTTPS. The document should list the expected API version and only the intended verification paths. Then verify one allowed and one blocked synthetic input. An unauthenticated request must return `401`, and a valid token for a different endpoint must receive `403`. The ingress must refuse UI, rule administration and evidence paths even when sent an admin token. Keep raw tokens out of command arguments, shell history and captured logs.

Open the private UI through a locally bound SSH socket forward using an approved OS identity able to connect to the private Unix socket. The systemd service account does not need interactive login. Provision operator forwarding separately from the application and preserve the socket permissions.

```sh
ssh -N -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:24180:/run/proofsieve-admin/guard.sock operator@demo-host.example.test
```

Open `http://127.0.0.1:24180/apps/` on the operator workstation. Authenticate in Guard and Swagger with the appropriate ProofSieve token. For a decision-mode endpoint, verify the signed export against the expected evidence key. Test restart on a disposable Linux host by repeating scoped access, checking that the same rules and signed decision remain available, and checking replay behaviour where wallet or forwarding is enabled.

From the source checkout or the extracted source archive in `dist/`, run `python -m tests.deploy_ingress --proofsieve /absolute/release/bin/proofsieve --nginx /usr/sbin/nginx`. This release test runs the installed executable outside the source tree and starts real Nginx with a generated loopback certificate. It checks both listeners, API scope, approval and refusal, and signed evidence across a process restart. The host acceptance also runs the enabled systemd unit as the service user with a distinct proxy identity and checks reachability after reboot.

Use a disposable Ubuntu 24.04 VM for the host acceptance. Configure a test certificate and restrict the ingress to loopback. Install the exact service bundle and enable the real unit. On that VM, check that the proxy user can connect to the API socket and that the same user cannot open the operator socket. An unrelated OS identity must be refused on both. For a Debian-style `www-data` worker, an API connection without a bearer token should return `401`.

```sh
sudo -u www-data curl --unix-socket /run/proofsieve-ingress/api.sock \
  -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Host: proofsieve-api.example.test' http://localhost/openapi.json
sudo -u www-data curl --unix-socket /run/proofsieve-admin/guard.sock \
  -sS -o /dev/null http://127.0.0.1:24180/apps/
```

Repeat the trusted HTTPS checks, save the signed evidence of a synthetic decision and reboot the VM. After reboot, require systemd to start both services automatically, verify the saved decision under the same signing key, then make a new scoped request. Apply the same sequence to the rendered target settings before admitting application traffic.

## Upgrade, recovery and TLS rotation

Quiesce ingress and stop the service before a matched backup of the rules, evidence database and optional wallet journal. Keep the private configuration, trust settings and exact previous release with that backup. Switch the version symlink and start the service with the existing state. Verify the authorized OpenAPI response, one synthetic decision and previously signed evidence before reopening traffic. For a failed rollout, switch back using compatible state. Reconcile pending wallet receipts before downgrading and reconcile downstream deliveries before restoring older state. [Recovery procedure](../docs/DEPLOYMENT.md#shared-service-deployment) · [Interrupted wallet evidence](../docs/WALLET.md#recover-interrupted-evidence)

For an online target, provision the certificate through the target's certificate manager. Ensure renewed chains and keys reach the same Nginx paths, run `sudo nginx -t`, and reload Nginx only after it passes. Check the public DNS name and trusted TLS chain from a client, then rerun the authenticated OpenAPI probe. The HTTPS certificate, credential issuer trust, wallet request-signing certificate and evidence signing key have separate lifecycles.
