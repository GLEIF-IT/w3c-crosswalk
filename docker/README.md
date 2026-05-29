# Portable Isomer And Wallet Containers

Docker Compose files reference images, package pins, or this repository's own files;

- The Node verifier consumes `did-jwt-vc` from a pinned Git dependency. 
- The Go verifier consumes `vc-go` through a pinned non-local Go module replacement. 
- The Python verifier consumes `keri` from package metadata.

The wallet container defaults to the published `kentbull/signify-react-ts:<sha>` image,
built from the pinned `signify-react-ts` ref and a pinned `signify-ts` Git dependency.

## Verifier Images

Build the Python, Node, Go, and dashboard images from this repository:

```sh
make docker-verifiers-build
```

The verifier images expose:

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` for Node and Go
- dashboard `GET /` and `POST /webhooks/presentations`


## Full Local Stack

Default host ports:

- KERIA admin/router/boot: `3901`, `3902`, `3903`
- Signify React wallet: `http://127.0.0.1:5177`
- did:webs resolver: `http://127.0.0.1:7678/1.0/identifiers`
- Python verifier: `http://127.0.0.1:8788`
- Node verifier: `http://127.0.0.1:8789`
- Go verifier: `http://127.0.0.1:8790`
- Verifier dashboard: `http://127.0.0.1:8791`

### Starting the stack

Use the `Makefile` at the root of this repo to either clean up or start up a new deployment.

#### Cleanup

```sh
make local-down
```

#### Startup

TODO: change to migrate away from the bullctx artifact script
Prepare images with the bullctx artifact script, then start the stack:

```sh
make local-up
make local-seed
make local-project
make local-test
```

- `make local-seed` seeds GEDA -> LE via a SignifyPy helper inside the published `kentbull/sigpy:<sha>` 
  image and writes passcodes and metadata to a manifest at `.tmp/local-stack/w3c-vrd-chain-manifest.json`.

- `make local-project` reads that manifest, asks KERIA to project the seeded VRD ACDC
  credential to a W3C projection, auto-signs the W3C proof and VC-JWT requests through SignifyPy, 
  and  asserts that the Python, Node, and Go verifier operations all return `ok: true`.

- `make local-test` includes that projection check after the static portability
  guards, so run `make local-seed` first.

## Required Configuration

- Configure image tags in `.env`; `.env.example` is the template.
- Use `DID_WEBS_REGISTRY_NAME_PREFIX=didwebs-designated-aliases`.

