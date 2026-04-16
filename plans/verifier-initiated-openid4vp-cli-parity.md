# Verifier-Initiated OpenID4VP CLI Parity Plan

## Summary

Implement a verifier-initiated OpenID4VP 1.0 flow across Python, Node, and Go
with one operator-facing orchestration surface: the Python `isomer` CLI.

The real requirement is semantic and operator parity, not Python runtime parity:

1. keep Python operations if useful
2. let Node/Go stay synchronous unless they truly need async
3. make the Python CLI tolerant of both result styles
4. require full parity only for the new OpenID4VP request flow and verification
   semantics

That means Python may continue using its internal operation store and doer model,
but that abstraction must not leak into the broader OpenID4VP flow. The CLI
should be able to drive any backend without the operator caring whether the
backend completed inline or via an operation handle.

This plan intentionally targets the current OpenID4VP 1.0 shape rather than a
bespoke verifier protocol:

- use a real authorization request / request object model
- use `request_uri` indirection for wallet-facing flows
- use `response_mode=direct_post`
- use `response_uri`
- use `dcql_query` as the default request language
- treat Presentation Exchange `presentation_submission` as compatibility support,
  not as the primary OpenID4VP model

Primary standards references:

- [OpenID for Verifiable Presentations 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [DIF Presentation Exchange 2.0](https://identity.foundation/presentation-exchange/spec/v2.0.0/)

Implementation sanity signal:

- [walt.id OpenID4VP guide](https://docs.walt.id/concepts/data-exchange-protocols/openid4vp)

## Standards Corrections To Lock Before Coding

### 1. Python operation resources are an internal detail

Python's existing `/operations/*` API exists because its verifier uses a
long-running background doer model. Node and Go do not need to mimic that just
for symmetry.

What matters:

- same verification semantics
- same OpenID4VP request/response behavior
- same `isomer` CLI UX

What does not matter:

- identical concurrency model
- identical polling routes
- identical storage internals

The Python API client used by the CLI should normalize both result styles:

- if a backend returns a terminal result directly, surface it directly
- if Python returns `202` plus an operation reference, poll until terminal

### 2. Our verifier session API is not itself OpenID4VP

We may still expose internal convenience endpoints such as:

- `POST /openid4vp/requests`
- `GET /openid4vp/requests/{id}`
- `POST /openid4vp/requests/{id}/response`

But those are verifier-side session management helpers, not the protocol spoken
to wallets.

The wallet-facing flow should remain standards-shaped:

1. verifier creates a request object
2. wallet receives a `request_uri`
3. wallet resolves the request object
4. wallet POSTs the authorization response to `response_uri`

The local session endpoints should help us construct and manage that flow, not
replace it with a bespoke Isomer-only protocol.

### 3. Use DCQL by default, not Presentation Exchange

OpenID4VP 1.0 Final uses `dcql_query` as the native request mechanism. Earlier
ecosystem practice often used Presentation Exchange `presentation_definition`,
but that should not be our primary model if we want broad standards alignment.

Therefore:

- the default verifier request object should carry `dcql_query`
- the default Isomer CLI flow should build and return a DCQL-backed request
- any Presentation Exchange support should be explicitly called compatibility
  behavior

### 4. `presentation_submission` is compatibility support

Presentation Exchange 2.0 still matters, especially for interop with deployed
wallets and verifier products. But it is a different spec layer.

So the rule should be:

- OpenID4VP request model: native, default
- PE `presentation_submission`: optional compatibility path

If we synthesize `presentation_submission`, it should be behind a compatibility
switch or profile, not baked into the core Isomer OpenID4VP flow as if it were
the only standard response model.

### 5. `client_id` must be handled exactly, not loosely

The W3C VC presentation examples in OpenID4VP bind the verifier identity
exactly:

- JWT VP: `aud` must equal the request's `client_id`
- Data Integrity VP: `domain` must equal the request's `client_id`
- `nonce` / `challenge` must equal the request nonce

So we must not reduce `client_id` to "some verifier base URL" in our mental
model. If we use a prefixed client identifier such as:

- `redirect_uri:https://verifier.example/response`
- `decentralized_identifier:did:webs:...`

then the VP binding must match that exact value.

## Product Constraints

- The same Python `isomer` CLI must drive the flow against Python, Node, or Go.
- `isomer verifier serve` is the front door for launching any backend.
- Backend selection flags:
  - default Python
  - `--verifier-node`
  - `--verifier-go`
- Python may keep internal operations.
- Node and Go may remain synchronous unless the new request flow genuinely
  forces async behavior.
- New OpenID4VP request flow semantics must match across all three backends.
- We also want a focused but polished end-user demo surface:
  - `isomer-mobile`: cross-platform holder app
  - `isomer-verifier-ui`: verifier dashboard / request creation app
- The UI work should begin only after the Python verifier has been adapted to
  the corrected OpenID4VP 1.0 plan, so the UIs target a known-good reference
  backend instead of unstable parallel drafts.

## Demo Product Surfaces

### `isomer-mobile`

Build a minimal but credible holder/presenter app in:

- `isomer-mobile`

Technology direction:

- TypeScript
- Ionic + Capacitor
- mobile-first, but usable in browser for development and demos

Responsibilities:

- hold one or more W3C VC-JWT artifacts locally
- load or fetch an OpenID4VP request object
- present a VC through the standards-shaped OpenID4VP flow
- show recent request / presentation history
- expose only the minimum wallet-like features needed for the demo

Non-goals for v1:

- production wallet storage hardening
- full credential management UX
- ACDC-based authorization workflows
- issuer/holder enrollment flows

### `isomer-verifier-ui`

Build a minimal verifier webapp in:

- `isomer-verifier-ui`

Technology direction:

- TypeScript web app
- modern browser-based dashboard
- designed to work against Python first, then Node and Go once backend parity
  lands

Responsibilities:

- create presentation requests
- display QR/deep-link style request launch material
- show incoming presentation status
- show a small recent-presentations dashboard
- drill into a single presentation result

Non-goals for v1:

- production admin auth
- multi-tenant administration
- rich analytics
- policy authoring UI

### Design direction

The apps should be deliberately minimal in features but strong in presentation:

- sleek, professional, polished visual design
- clear typography, spacing, and information hierarchy
- focused workflow with very little user confusion
- designed to "wow" in demos without pretending to be a complete production
  wallet or verifier suite

The mistake to avoid is visual or product sprawl. The right POC is:

- narrow feature set
- high design quality
- reliable end-to-end story

## Admin API And Request Authentication

The verifier dashboard work implies a small admin/control API on the verifier
backends in addition to the wallet-facing OpenID4VP endpoints.

### Security posture for the POC

We should keep security light, but not sloppy:

- do not use shared secrets as the core trust model
- do not use a password-only admin flow
- do use signed requests rooted in a KERI AID

### POC auth model

Use request signing compatible with `keri-ts` on browser/mobile clients:

- the browser dashboard and any local admin client derive or load a KERI AID
- requests to admin/control endpoints are signed with KERI-style signature
  headers
- the verifier accepts requests only from a local whitelist of authorized AIDs

This means:

- same AID + salt + passcode can deterministically recreate the signing identity
  for demo/admin use
- trust is based on signed requests, not on a shared password known to both
  sides
- the verifier can authenticate requests by verifying signatures against the
  whitelisted AIDs

### Scope of admin auth in v1

Protect only the control/dashboard API with signed requests:

- session/request creation
- recent presentations list
- presentation detail views
- any dashboard polling endpoints

The wallet-facing OpenID4VP endpoints remain standards-shaped and should not be
turned into a KERI-specific protocol.

### Future production direction

The hardcoded whitelist is only a POC stand-in.

Production direction would be:

- dynamic registration / onboarding
- stronger verifier authorization policy
- root-of-trust anchoring
- ultimately a trust model closer to ecosystem roots such as a GLEIF-rooted
  trust configuration

But that is explicitly out of scope for this first implementation.

## Target OpenID4VP Flow

### Verifier-side session creation

Internal endpoint:

- `POST /openid4vp/requests`

Purpose:

- create and persist one verifier-owned OpenID4VP session
- generate a request object
- generate a wallet-facing `request_uri`
- return session metadata for CLI/operator use

Returned metadata should include:

- `id`
- `request_uri`
- `request_object`
- `expires_at`
- `status`

### Wallet-facing request retrieval

Wallet-facing endpoint:

- `GET /openid4vp/request-objects/{id}` or equivalent stable request-object URL

Purpose:

- return the actual OpenID4VP authorization request object that a wallet would
  fetch from `request_uri`

Recommended request object fields for v1:

- `client_id`
- `response_type: "vp_token"`
- `response_mode: "direct_post"`
- `response_uri`
- `nonce`
- `state`
- `dcql_query`
- optionally `client_metadata`

### Wallet/holder response submission

Wallet-facing endpoint:

- `POST {response_uri}`

Standards behavior:

- request body is `application/x-www-form-urlencoded`
- includes at minimum:
  - `vp_token`
  - `state`
- may also include compatibility parameters if we support them

Internal session helper:

- `POST /openid4vp/requests/{id}/response`

Purpose:

- convenience endpoint for CLI and tests
- may accept JSON and internally transform to the same verification path used by
  the standards-facing `response_uri`

The important rule is that the standards-facing response path must exist and
must behave like OpenID4VP `direct_post`.

## Admin And Dashboard API Surface

In addition to the wallet-facing protocol seam, the verifier backends will need
an internal admin API used by `isomer-verifier-ui`.

This API does not need to be an industry-standard protocol, but it does need:

- consistent semantics across backends once parity lands
- signed-request authentication
- enough information to drive the demo dashboard cleanly

Recommended admin endpoints:

- `POST /admin/openid4vp/requests`
  - signed control-plane request creation
- `GET /admin/openid4vp/requests/{id}`
  - signed request/session detail
- `GET /admin/presentations`
  - recent presentations list
- `GET /admin/presentations/{id}`
  - one presentation result detail
- `GET /admin/healthz`
  - optional signed admin health/status document

Recommended response data:

- request/session identifiers
- current status
- created/updated timestamps
- verifier result summaries
- nested credential success/failure summaries
- enough metadata to render a compact operator dashboard

The admin API should be intentionally small. Avoid inventing an entire verifier
management platform for the POC.

## Required Verification Semantics Across Python, Node, and Go

### Shared VP binding checks

For JWT-based W3C VPs:

- `jwtPayload.iss == vp.holder`
- `jwtPayload.aud == request.client_id`
- `jwtPayload.nonce == request.nonce`
- `iat` numeric

For Data Integrity W3C VPs:

- `proof.challenge == request.nonce`
- `proof.domain == request.client_id`

All three backends must reject:

- unknown request/session
- expired request/session
- already consumed request/session
- wrong `state`
- wrong `aud`
- wrong `nonce`
- malformed response body
- invalid or unsupported VP/VC format

### Session rules

Request/session state:

- `pending`
- `fulfilled`
- `expired`

Initial policy:

- TTL 5 minutes
- single-use

Storage implementation may vary by backend, but semantics must match.

## HTTP Surface Area

### Common verifier capabilities

All three backends must support:

- `GET /healthz`
- verifier-initiated OpenID4VP request creation
- wallet-facing request object retrieval
- wallet-facing `direct_post` response handling
- raw VC/VP verification APIs already used by Isomer

### Raw verification endpoints

These do not need identical async behavior.

Python:

- may continue returning `202` + operation resource for `/verify/*`

Node and Go:

- may return terminal `200` results directly unless a real async need appears

The Python API client must abstract over both.

### OpenID4VP request/session endpoints

These do require semantic parity, but not necessarily identical internals.

Recommended common internal endpoints:

- `POST /openid4vp/requests`
- `GET /openid4vp/requests/{id}`
- `POST /openid4vp/requests/{id}/response`

Recommended common wallet-facing endpoint:

- `GET /openid4vp/request-objects/{id}`

The exact request-object path can be adjusted, but it should be stable enough to
serve as a real `request_uri`.

## CLI Plan

### `isomer verifier serve`

One command launches any backend:

- default Python
- `--verifier-node`
- `--verifier-go`

Common flags:

- `--host`
- `--port`
- `--resolver`
- `--public-base-url`
- `--resource-root`
- `--operation-root`
- `--operation-name`

Behavior:

- Python backend runs in-process using current doer model
- Node backend is launched as a subprocess by the Python CLI
- Go backend is launched as a subprocess by the Python CLI

The subprocess details are backend-specific, but CLI behavior should feel
uniform.

### New CLI commands

- `isomer verifier request-vp`
  - creates one OpenID4VP verifier session
  - returns request metadata and `request_uri`
- `isomer verifier get-vp-request`
  - fetches one stored verifier session by id
- `isomer verifier submit-vp-response`
  - submits a response body to one verifier session helper endpoint
- `isomer vp respond`
  - consumes a request object or `request_uri`
  - issues a request-bound VP
  - either prints the response body or auto-submits it

### `isomer vp respond` behavior

The holder/presenter flow should be:

1. resolve the request object from a file, inline JSON, or `request_uri`
2. inspect `client_id`, `nonce`, and requested VC format
3. issue the VP with the correct binding:
   - JWT VP: `aud = client_id`, `nonce = request.nonce`
   - Data Integrity VP: `domain = client_id`, `challenge = request.nonce`
4. package the response as a standards-shaped authorization response
5. either:
   - emit the response locally, or
   - POST it to `response_uri`

The same underlying logic should later be reusable by `isomer-mobile`, so the
CLI remains the first thin client of the holder flow rather than a throwaway
branch.

## Format Strategy

### Primary format for v1

Use JWT-based W3C VC/VP as the primary OpenID4VP flow because:

- our current artifacts are already VC-JWT / VP-JWT oriented
- OpenID4VP 1.0 explicitly documents JWT-based W3C VP examples
- Node and Go already verify our current JWT-based VP shape with `aud`/`nonce`

### Data Integrity VP support

Support DI-secured W3C VPs as a second standards-aligned path when requested,
making sure:

- `challenge` maps to request `nonce`
- `domain` maps to request `client_id`

### Presentation Exchange support

If we keep PE compatibility:

- make it explicit
- do not treat it as the mainline OpenID4VP 1.0 flow
- document that it exists for interoperability with wallets/verifiers that still
  expect `presentation_submission`

## Backend-by-Backend Work

## Dependency-Ordered Delivery Phases

### Phase 0: Lock the reference contract

Before implementation begins in earnest:

- keep this file as the authoritative plan
- keep the OpenID4VP 1.0 corrections locked
- treat Python operations as an internal detail
- treat DCQL as the default request language
- treat PE support as compatibility only

This phase is complete when the architecture is no longer ambiguous.

### Phase 1: Python verifier as the reference backend

Build the corrected OpenID4VP flow in Python first.

Goals:

- standards-shaped request object generation
- wallet-facing `request_uri`
- wallet-facing `response_uri` with `direct_post`
- request/session persistence
- VP binding enforcement for `client_id`, `nonce`, and `state`
- tolerant Python API client that hides Python operations

This phase is the reference implementation and the foundation for everything
else.

### Phase 2: Python admin API and signed control plane

Once Python OpenID4VP flow is correct:

- add the minimal signed admin/control API
- add AID whitelist validation
- add recent presentation / presentation detail endpoints
- add verifier-session control endpoints suitable for the dashboard

This gives the UI something stable and realistic to talk to.

### Phase 3: Build the demo UIs against Python

Build both frontend apps against the Python backend only at first.

#### Phase 3a: `isomer-verifier-ui`

- request creation screen
- QR/deep-link launch view
- recent presentations dashboard
- single presentation detail page
- signed requests using the admin API

#### Phase 3b: `isomer-mobile`

- load/store demo VC-JWT
- accept request object / request URI
- present a VP successfully to the Python verifier
- minimal history / status feedback

This sequencing is deliberate. If the UIs cannot work cleanly against Python,
they will only amplify confusion when Node and Go enter the picture.

### Phase 4: Node backend parity

Bring Node up to parity with the Python reference for:

- OpenID4VP request/session semantics
- admin API semantics
- signed admin request verification
- compatibility with the same Python `isomer` CLI
- compatibility with `isomer-verifier-ui`
- compatibility with `isomer-mobile`

Keep raw verification synchronous unless a real async need appears.

### Phase 5: Go backend parity

Bring Go up to parity with the Python reference for:

- OpenID4VP request/session semantics
- admin API semantics
- signed admin request verification
- compatibility with the same Python `isomer` CLI
- compatibility with `isomer-verifier-ui`
- compatibility with `isomer-mobile`

Again, keep raw verification synchronous unless a real async need appears.

### Phase 6: Cross-backend polish and demo hardening

Once all three backends work:

- ensure the same CLI flows work unchanged against all three
- ensure both UI apps can target all three
- tighten design polish
- tighten operational robustness
- add demo scripts / walkthroughs

This is where we optimize the demo experience, not where we discover the core
protocol design.

### Python

- keep existing operations abstraction for raw verification if useful
- add a Python verifier API client that hides operations from higher-level CLI
  commands
- extend raw VP verification to accept expected `audience` and `nonce`
- add verifier-session persistence for OpenID4VP request flow
- expose wallet-facing request object and `direct_post` response handling
- implement the first admin API
- implement signed admin request verification against a local AID whitelist

### Node

- keep raw verification synchronous unless real async pressure appears
- add verifier-session persistence for OpenID4VP request flow
- expose wallet-facing request object and `direct_post` response handling
- preserve current `audience` / `nonce` claim enforcement for JWT VP verification
- implement admin API parity after Python is proven
- implement signed admin request verification against the same whitelist model

### Go

- keep raw verification synchronous unless real async pressure appears
- add verifier-session persistence for OpenID4VP request flow
- expose wallet-facing request object and `direct_post` response handling
- preserve current `audience` / `nonce` claim enforcement for JWT VP verification
- implement admin API parity after Python is proven
- implement signed admin request verification against the same whitelist model

## Test Plan

### Standards-shape tests

Across Python, Node, and Go:

- request creation returns a valid request object with:
  - `client_id`
  - `response_type=vp_token`
  - `response_mode=direct_post`
  - `response_uri`
  - `nonce`
  - `state`
  - `dcql_query`
- wallet-facing `request_uri` resolves correctly
- `response_uri` accepts form-urlencoded `vp_token` + `state`

### Semantic rejection tests

Across Python, Node, and Go:

- wrong `state` rejected
- wrong `aud` rejected
- wrong `nonce` rejected
- expired request rejected
- replayed response rejected

### CLI parity tests

Against Python, Node, and Go servers alike:

- `isomer verifier serve` launches the selected backend
- `isomer verifier request-vp` works unchanged
- `isomer vp respond` works unchanged
- `isomer verifier submit-vp-response` works unchanged

### Python-first UI tests

Against Python first:

- `isomer-verifier-ui` can create a request through the signed admin API
- `isomer-verifier-ui` can display the request launch material
- `isomer-mobile` can consume the request and present successfully
- the dashboard shows the completed presentation
- the detail view shows nested credential verification outcome

### Cross-backend UI tests

Once Node and Go parity lands:

- `isomer-verifier-ui` works against Python, Node, and Go
- `isomer-mobile` works against Python, Node, and Go
- signed admin API requests verify correctly on all three backends

### Compatibility tests

If PE support is retained:

- compatibility mode emits and validates `presentation_submission`
- core OpenID4VP DCQL flow still works without PE fields

## Deliverables

### Code

- backend-selectable `isomer verifier serve`
- tolerant Python verifier API client
- OpenID4VP verifier-session endpoints
- admin/control API endpoints
- signed admin request verification with AID whitelist
- wallet-facing `request_uri` and `response_uri`
- `dcql_query`-based request construction
- `isomer verifier request-vp`
- `isomer verifier get-vp-request`
- `isomer verifier submit-vp-response`
- `isomer vp respond`
- `isomer-mobile`
- `isomer-verifier-ui`

### Documentation

- keep this file as the restartable canonical plan
- update `plans/isomer-w3c-sidecars.md` if sidecars are no longer merely thin
  acceptance harnesses
- update `.agents/PROJECT_LEARNINGS.md` after implementation if the operator
  mental model changes materially
- add operator/developer walkthrough docs for:
  - Python-first setup
  - demo mobile flow
  - dashboard flow
  - switching the same apps across Python, Node, and Go backends

## Final Design Principle

Build a standards-shaped OpenID4VP verifier flow with backend-specific internals
hidden behind a tolerant client layer.

Do not force Python's operations abstraction onto Node and Go.
Do not mistake Presentation Exchange compatibility for the core OpenID4VP 1.0
model.
Do not let internal verifier-session convenience endpoints replace the real
wallet-facing `request_uri` + `response_uri` protocol seam.
Do not start UI work before the Python reference backend is correct.
Do not build POC security around shared secrets when signed requests with
whitelisted AIDs are both feasible and architecturally cleaner.
