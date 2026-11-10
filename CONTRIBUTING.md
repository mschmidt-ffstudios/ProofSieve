# Contributing

Use Python 3.10 or newer. Check which interpreter your shell selects before creating the virtual environment. The example uses Python 3.12. Substitute your supported interpreter if its command differs.

```sh
python3.12 --version
python3.12 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/python -m unittest discover -s tests -v
```

Run the Chromium checks from the repository root. Playwright is a test dependency installed separately from the ProofSieve runtime.

```sh
.venv/bin/python -m pip install playwright==1.60.0
.venv/bin/python -m playwright install chromium
.venv/bin/python -m tests.workspace_browser
.venv/bin/python -m tests.guard_browser
.venv/bin/python -m tests.guard_editor_browser
.venv/bin/python -m tests.operator_workflow_browser
.venv/bin/python -m tests.verifier_handoff_browser
.venv/bin/python -m tests.api_docs_browser
```

The workspace suite covers file round-trips, JSON and Turtle handoff, sourced examples and every synthetic Lab case in both languages. The Guard and Swagger suites exercise the protected operator and verifier flows. The [workflow test set](examples/acceptance/README.md#workflow-test-set) runs these layers together and documents the separate deployed wallet comparison.

Use synthetic data and throwaway keys in examples. Identify upstream material and record its provenance and terms. Keep real credentials, issuer signing keys, environment files and organization-specific settings in the private deployment workflow. [Deployment boundary](docs/DEPLOYMENT.md)

For changes to verification or policy evaluation, include the expected decision for a valid case and a rejection case. Keep the Guard's German and English UI labels aligned when changing operator-facing controls.
