# signify-did-webs

Promise-based did:webs setup helpers for Signify wallets.

KERIA advertises the current did:webs setup descriptor for a managed identifier.
This package reads that descriptor, performs the missing edge-signed Signify
actions, and waits until KERIA reports did:webs readiness.

```ts
import { ensureDidWebsSetup } from "signify-did-webs";

await ensureDidWebsSetup({
  client,
  name: "issuer",
  timeoutMs: 120000,
  pollMs: 1000
});
```

The workflow is idempotent. Repeated calls check KERIA state before creating
the registry or issuing the designated-alias ACDC.
