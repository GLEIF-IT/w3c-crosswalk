# isomer Working Instructions

Keep Isomer work consistent across ACDC, W3C VC-JWT, did:webs resolution,
status projection, issue-hold-verify flow, and wallet integration.

## Session Start (Required)

Read, in order:

1. `AGENTS.md`
2. `.agents/PROJECT_LEARNINGS.md`
3. The task-relevant topic docs listed there
4. Any plan docs those topic docs reference
5. Sibling repos only when needed:
   - `../wallet` for holder/issuer seams
   - `../did-webs-resolver` for DID/key-state resolution
   - `../sally` for ACDC verifier behavior
   - `../w3c-signer` as legacy reference only
   - `../keripy` as the Python behavior reference

Then produce a concise current-state summary and implementation plan.

## Local Setup Rule

1. Install sibling Python deps into the local `.venv` as editable installs; do
   not rely on `PYTHONPATH` tricks.
2. Expected editable installs for integration work: `../keripy` and
   `../did-webs-resolver`.
3. Launch the vLEI schema service from the local `../vLEI` repo's
   `vLEI-server` binary and use `VLEI_ROOT` for schemas, credentials, and
   OOBIs.
4. Repo instructions and tests should assume those local installs or service
   binaries when integration behavior depends on them.

## Handoff Rule

For significant changes, update:

1. The relevant topic learnings doc(s)
2. `.agents/PROJECT_LEARNINGS.md` if cross-topic state changed
3. Relevant `plans/` docs if scope, assumptions, or sequencing changed

## Memory Model

1. `.agents/PROJECT_LEARNINGS.md` for routing and durable cross-topic memory
2. `.agents/learnings/PROJECT_LEARNINGS_*.md` for topic detail and handoff logs

## Hard Rules

### Signing

1. Use live KERIpy habitats (`Hab`, `Habery`) for signing.
2. Never introduce deterministic demo signers.
3. Use stable salts, passcodes, and aliases for deterministic results.
4. If a task looks easier with a fake signer, the seam is wrong; fix the code.

### Workflow

1. Use subprocesses only for long-lived external services such as witnesses,
   `vLEI-server`, and `did-webs-resolver`.
2. Do not shell out to `kli` for workflow steps when KERIpy doers or library
   APIs exist.
3. Integration helpers should run KERIpy doers in-process and assert through
   direct state inspection instead of CLI stdout.
4. Any workflow step that still depends on `kli` subprocesses is transitional
   debt.
5. Reuse KERIpy behavior directly when practical; add local helpers only when
   no reusable seam exists.
6. Prefer stock KERIpy `Doer` and `DoDoer` classes over Isomer-managed copies.
7. If a local managed doer is unavoidable, keep it narrow, document the cleanup
   seam it exposes, and treat it as debt.

### Documentation

1. Use concise Google-style docstrings for Python modules, classes, methods,
   and non-trivial functions.
2. Prefer present tense and behavior-first wording.
3. Explain coordination points, side effects, and failure modes, not obvious
   types.
4. Apply the same standard to tests, fixtures, workflow helpers, topology
   builders, and service shims.
5. For constants, prefer grouped maintainer comments over artificial docstrings.

### Tooling

1. Prefer the simplest command that solves the problem.
2. For local Python deps, try a direct editable install before adding wrappers
   or environment hacks.
3. Do not add symlink tricks or copied packaging internals when a simple
   command is enough.

### Debugging

1. Start with low-output debugging for service and integration failures.
2. Prefer `pytest --tb=short` or `--tb=line` unless a full traceback is clearly
   needed.
3. Read source and logs in the smallest useful slice first, then expand in
   small increments.
4. Treat added debug logging as temporary scaffolding and remove it quickly.
5. Before collecting more output, state the current hypothesis and the exact
   missing fact needed to confirm or reject it.
