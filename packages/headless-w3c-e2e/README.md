# headless-w3c-e2e

Python-first executable harness for the holder-centered W3C VRD flow.

The package wraps SignifyPy/KERIA-style clients with in-memory wallet actors,
drives issuer issuance, holder import/admit, presentation transactions, and
verifier checks, then emits manifests that TypeScript, React, and local-stack
work can compare against.

Verifier acceptance is live-service only. The harness expects Python, Node, and
Go verifier base URLs, builds runtime presentation descriptors for KERIA, lets
KERIA submit the holder VP-JWT, then polls the verifier service operation that
KERIA created. CLI-style stdin commands, fake in-process callables, direct
verifier library calls, and fixture-only verifier responses are not acceptance
evidence.

Signing remains an edge operation. KERIA may stage exact signing inputs and
verify submitted signatures, but wallet automation signs only policy-approved
requests with the holder or issuer edge key material.

It is not a production wallet SDK.
