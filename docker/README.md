# Portable Isomer Containers

The local stack is image-only at the `w3c-crosswalk` boundary. Compose files
may reference images, package pins, and this repository's own files. They must
not require sibling source checkouts.

For verifier semantics, see `../docs/verifier-contract.md`.

## Build Verifier Images

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

## Full Local Stack

Create `.env` from `.env.example`, then run:

```bash
make local-up
make local-seed
make local-test
make local-down
```

Default host ports:

- KERIA admin/router/boot: `3901`, `3902`, `3903`
- Signify React wallet: `http://127.0.0.1:5177`
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
- Run `make portability-check` before changing Docker, package, or compose
  wiring.
