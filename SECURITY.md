# Security

ProofSieve runs as a reference application on loopback or on a private Unix socket. Protected mode checks bearer identity and an exact endpoint grant before verification or administration. The private socket requires this mode and supports authenticated SSH forwarding for remote operator access. A shared service needs production transport, identity and token lifecycle procedures, and an explicit issuer trust and data handling policy. [Endpoint access](docs/ACCESS.md) · [Deployment boundary](docs/DEPLOYMENT.md)

The signed adapters check the credential against a configured public key and validate the disclosed data before ODRL evaluation. Production deployments must also establish issuer trust, define how to handle revocation, and verify holder or device binding when the protocol requires it. Use synthetic credentials in examples and bug reports.

Report a suspected vulnerability privately to the maintainers through the repository host's private reporting channel when available. Include the affected version, a description and a minimal synthetic reproduction. Keep live credentials, signing keys and personal data out of reports.
