# headless-w3c-e2e

Python-first executable harness for the holder-centered W3C VRD flow.

The package wraps SignifyPy/KERIA-style clients with in-memory wallet actors,
drives issuer issuance, holder import/admit, presentation transactions, and
verifier checks, then emits manifests that TypeScript, React, and local-stack
work can compare against.

It is not a production wallet SDK.
