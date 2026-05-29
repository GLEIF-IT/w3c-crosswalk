# Verifier-Initiated OpenID4VP CLI Parity Plan

## Summary

Implement a verifier-initiated OpenID4VP 1.0 flow across Python, Node, and Go
with one operator-facing surface: the Python `isomer` CLI.

The requirement is semantic parity, not identical runtime internals. Python may
keep its operation store. Node and Go may stay synchronous unless they need
async. The CLI/client layer hides those differences.

## Locked Protocol Decisions

- Target OpenID4VP 1.0 Final.
- Use request-object retrieval through `request_uri`.
- Use `response_mode=direct_post` and `response_uri`.
- Use `dcql_query` as the default request language.
- Treat Presentation Exchange `presentation_submission` as compatibility
  support, not the primary flow.
- Bind verifier identity exactly:
  - JWT VP `aud == request.client_id`
  - Data Integrity VP `proof.domain == request.client_id`
  - JWT VP `nonce == request.nonce`
  - Data Integrity VP `proof.challenge == request.nonce`

## Product Constraints

- `isomer verifier serve` launches Python by default, or Node/Go through
  backend selection flags.
- The same CLI commands must work against Python, Node, and Go.
- UI work starts against Python first.
- POC admin/control requests use KERI-signed requests from whitelisted AIDs,
  not shared secrets or password-only auth.
- Wallet-facing OpenID4VP endpoints remain standards-shaped and do not become
  KERI-specific endpoints.

## HTTP Surface

Verifier-side session helpers:

- `POST /openid4vp/requests`
- `GET /openid4vp/requests/{id}`
- `POST /openid4vp/requests/{id}/response`

Wallet-facing protocol endpoints:

- `GET /openid4vp/request-objects/{id}`
- `POST {response_uri}` with form-encoded authorization response

Admin/dashboard endpoints:

- `POST /admin/openid4vp/requests`
- `GET /admin/openid4vp/requests/{id}`
- `GET /admin/presentations`
- `GET /admin/presentations/{id}`
- optional `GET /admin/healthz`

## CLI Surface

- `isomer verifier serve`
- `isomer verifier request-vp`
- `isomer verifier get-vp-request`
- `isomer verifier submit-vp-response`
- `isomer vp respond`

`isomer vp respond` must:

1. resolve a request object from file, JSON, or `request_uri`;
2. inspect `client_id`, `nonce`, and requested credential format;
3. issue a request-bound VP;
4. package a standards-shaped authorization response;
5. either print it or POST it to `response_uri`.

## Session Semantics

- states: `pending`, `fulfilled`, `expired`
- initial TTL: 5 minutes
- single-use response consumption
- reject unknown, expired, consumed, wrong-state, wrong-aud, wrong-nonce, and
  malformed responses

Storage internals may differ by backend, but these semantics must match.

## Delivery Phases

### Phase 0: Lock Reference Contract

Keep this file as the active OpenID4VP contract. Treat Python operations as an
internal detail, DCQL as the default request language, and PE as compatibility.

### Phase 1: Python Reference Backend

Implement request object generation, request/session persistence,
wallet-facing request/response endpoints, VP binding enforcement, and a client
layer that hides Python operation polling.

### Phase 2: Signed Admin API

Add minimal admin/control endpoints, AID whitelist validation, presentation
list/detail endpoints, and signed request verification.

### Phase 3: Python-First Demo UIs

Build the verifier UI and holder/mobile surface against Python only:

- request creation
- QR/deep-link launch
- presentation status
- single presentation detail
- load/store one or more demo VC-JWTs
- respond to a request successfully

### Phase 4: Node Parity

Add OpenID4VP session semantics, admin API semantics, signed admin request
verification, and CLI compatibility to the Node backend. Keep raw verification
synchronous unless a real async need appears.

### Phase 5: Go Parity

Add the same OpenID4VP and admin semantics to the Go backend. Keep raw
verification synchronous unless a real async need appears.

### Phase 6: Cross-Backend Polish

Ensure unchanged CLI and UI flows work against Python, Node, and Go. Tighten
demo robustness and operator ergonomics after core semantics are proven.

## Test Plan

- Standards-shape tests for request objects and `direct_post` responses.
- Semantic rejection tests for wrong `state`, `aud`, `nonce`, expiry, and replay.
- CLI parity tests against Python, Node, and Go.
- Python-first UI tests before cross-backend UI tests.
- Compatibility tests only if PE support is retained.

## Non-Goals

- Do not force Python's operation abstraction onto Node and Go.
- Do not build a full verifier management platform.
- Do not start UI work before Python is a stable reference backend.
- Do not use shared secrets as the core POC admin trust model.
