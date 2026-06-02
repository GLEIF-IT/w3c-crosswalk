# Portable Isomer Containers

The local stack runtime is image-only at the `w3c-crosswalk` boundary. Runtime
Compose files may reference images, package pins, and this repository's own
files. They must not require sibling source checkouts.

For verifier semantics, see `../docs/verifier-contract.md`.

## Build Verifier Images

Verifier images are built with `docker/compose.build.yml`. The normal local
stack remains image-only and consumes the resulting tags through `.env`.

The Node, Go, and dashboard Dockerfiles live with their app source under
`apps/`. The Python verifier Dockerfile remains under `docker/isomer-python/`
because Python Isomer is currently the root package. Build commands still use
the `w3c-crosswalk` repo root as the Docker context so Node can consume the
local `packages/webs-did-resolver` package and Go can copy
`src/vc_isomer/resources`.

```bash
make docker-verifiers-build
```

Images:

- `w3c-crosswalk/isomer-python:local`
- `w3c-crosswalk/isomer-node:local`
- `w3c-crosswalk/isomer-go:local`
- `w3c-crosswalk/isomer-dashboard:local`

The images expose:

- `GET /healthz`
- `POST /verify/vc`
- `POST /verify/vp` for Node and Go
- dashboard `GET /` and `POST /webhooks/presentations`

Future cleanup should publish `webs-did-resolver` as an NPM package and factor
Go verifier resources into `apps/isomer-go`; those are not required for the
current local stack.

## Full Local Stack

Create `.env` from `.env.example`, then run:

```bash
make local-up
make local-seed
make local-test
make local-down
```

`make local-test` consumes `.tmp/local-stack/w3c-vrd-chain-manifest.json` from
`make local-seed`, drives KERIA holder presentation transactions with edge
wallet signing, and collects live verifier evidence from the Python, Node, and
Go services.

Default host ports:

- KERIA admin/router/boot: `3901`, `3902`, `3903`
- `did:webs` resolver: `http://127.0.0.1:7678/1.0/identifiers`
- Python verifier: `http://127.0.0.1:8788`
- Node verifier: `http://127.0.0.1:8789`
- Go verifier: `http://127.0.0.1:8790`
- Verifier dashboard: `http://127.0.0.1:8791`

## Required Contract

- Configure image tags in `.env`; `.env.example` is the template.
- Use `DID_WEBS_REGISTRY_NAME_PREFIX=didwebs-designated-aliases`.
- Keep generated AID and registry names colonless.
- Keep actual DID strings such as `did:webs:...` unchanged.
- Run the React wallet browser smoke from the checked-out
  `signify-react-ts` source so it uses the local `signify-ts` dependency and
  current holder-presentation code.
