# ProofSieve 0.5.0

ProofSieve is a configurable verification and policy decision service. You can run the Python distribution locally or build the Linux installation kit from a reviewed source checkout. It serves scoped verification through an HTTPS API ingress and provides a separate operator workspace for rule administration and signed evidence.

## Changes since 0.4.0-rc.11

- The Builder links to the matching signed SD-JWT VC and mdoc examples in Guard. The scoped verifier sees credential rejection, policy denial, technical failure and delivery outcomes separately. Guard and Swagger use German or English controls.
- Wallet completion persists a receipt before writing evidence. An exact retry after a storage interruption leaves the operation blocked and can produce a single signed indeterminate decision. Decision identity remains stable across evidence retention. Operators can inspect outstanding receipts before rollback.
- Forwarding records approval and reserves the delivery atomically. An approved retry returns the original decision ID and delivery state. After evidence retention expires the reservation still blocks another send. Historic evidence remains as recorded, including the original decision linked to each delivery.
- The Guard preserves pending condition edits across language changes and requires the operator to apply or discard them before saving or checking a rule. SHACL preserves the lexical form of RDF literals for `sh:hasValue` and applies numeric bounds to Turtle shorthand.
- The release acceptance checks exact endpoint grants, signed evidence, EUDI and Credo wallet paths, Keycloak and DSS integration, versioned upgrade and recovery, and the installed wheel behind Nginx with TLS.
- The installation kit contains operator documentation, service and reverse-proxy templates and hash-locked dependencies for Ubuntu 24.04 amd64 with Python 3.12. The kit builder checks the exact wheel, source distribution and lock against the recorded build hashes.

## Install and upgrade

Follow the [Linux service installation](../deploy/README.md) for a verified bundle or use the [kit build procedure](DEPLOYMENT.md#release-acceptance). The [operator manual](MANUAL.md) covers the first rule, verification and signed Swagger export. Before upgrading, stop writes and back up rules, evidence, wallet journal and compatible private configuration together. Check pending wallet receipts before downgrading. [Deployment and recovery](DEPLOYMENT.md) · [Wallet evidence recovery](WALLET.md#recover-interrupted-evidence)

The wallet adapters and document-validation services require separate installation and trust configuration. Review the [optional Credo dependency assessment](../integrations/credo/README.md#dependency-audit) before enabling that profile. ProofSieve’s original code and documentation use [Apache License 2.0](../LICENSE). Bundled third-party notices accompany the distribution.
