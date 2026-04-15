# Demo Scripts

`bootstrap-vrd-acdc-kli.sh` prepares the KERI/ACDC source side for the
isomer CLI walkthrough using KERIpy `kli` commands. By default it uses the
same KERI home as normal KLI usage. It does not redirect KERI state into `.tmp`
unless you explicitly set `KERI_HOME`.

It performs:

- GEDA inception
- delegated QVI inception
- LE inception
- GEDA, QVI, and LE registry inception
- QVI, LE, VRD Auth, and VRD issue -> grant -> mailbox sync -> admit
- export of the final VRD ACDC JSON and CESR artifacts
- generation of static did:webs artifacts for the QVI issuer DID

It can start bootstrap-only witness and vLEI helper services for you. The
witness helper is the same local three-witness stack used by the integration
harness, while the identity and credential workflow itself is driven by `kli`.

```bash
RESET=1 START_WITNESS_DEMO=1 START_VLEI_SERVER=1 ./scripts/demo/bootstrap-vrd-acdc-kli.sh
source .tmp/kli-vrd-acdc/out/env.sh
```

Use `serve-didwebs-static.sh` after bootstrap to host the generated did:webs
artifacts and run the resolver:

```bash
./scripts/demo/serve-didwebs-static.sh .tmp/kli-vrd-acdc/out/env.sh
```

Then continue with `docs/cli-e2e-walkthrough.md`.
