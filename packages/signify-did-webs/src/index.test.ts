import assert from "node:assert/strict";
import test from "node:test";
import type {
  DidWebsSetupInfo,
  SignifyClient
} from "signify-ts";
import {
  ensureDidWebsSetup,
  getDidWebsSetup,
  waitForDidWebsReady
} from "./index.js";

type Call = [string, ...unknown[]];

function setup({
  ready = false,
  registryId = null,
  registryReady = false,
  credentialSaid = null,
  issueArgs
}: {
  ready?: boolean;
  registryId?: string | null;
  registryReady?: boolean;
  credentialSaid?: string | null;
  issueArgs?: DidWebsSetupInfo["designatedAlias"]["issueArgs"];
} = {}): DidWebsSetupInfo {
  const resolvedIssueArgs = issueArgs === undefined && registryId !== null
    ? {
        ri: registryId,
        s: "schema-said",
        a: {
          d: "",
          dt: "2026-06-05T00:00:00Z",
          ids: [
            "did:web:example.com:dws:Eaid",
            "did:webs:example.com:dws:Eaid"
          ]
        },
        r: { usageDisclaimer: { l: "usage" } }
      }
    : issueArgs ?? null;

  return {
    name: "aid1",
    aid: "Eaid",
    did: "did:webs:example.com:dws:Eaid",
    dws: ready ? "did:webs:example.com:dws:Eaid" : null,
    didJsonUrl: "https://example.com/dws/Eaid/did.json",
    keriCesrUrl: "https://example.com/dws/Eaid/keri.cesr",
    ready,
    registry: {
      name: "didwebs-designated-aliases-Eaid",
      registryId,
      ready: registryReady,
      createArgs: {
        name: "aid1",
        registryName: "didwebs-designated-aliases-Eaid"
      }
    },
    designatedAlias: {
      schema: "schema-said",
      credentialSaid,
      ready,
      issueArgs: resolvedIssueArgs
    }
  };
}

function clientFixture(setups: DidWebsSetupInfo[]) {
  const calls: Call[] = [];
  let last = setups[setups.length - 1] ?? setup();
  const pending = [...setups];
  const client = {
    didwebs() {
      return {
        async setup(name: string) {
          calls.push(["setup", name]);
          last = pending.shift() ?? last;
          return last;
        }
      };
    },
    registries() {
      return {
        async create(args: unknown) {
          calls.push(["create-registry", args]);
          return {
            async op() {
              calls.push(["registry-op"]);
              return { name: "registry-op", done: false };
            }
          };
        }
      };
    },
    credentials() {
      return {
        async issue(name: string, args: unknown) {
          calls.push(["issue-credential", name, args]);
          return { op: { name: "credential-op", done: false } };
        }
      };
    },
    operations() {
      return {
        async wait(op: { name: string }, options: { minSleep?: number; maxSleep?: number }) {
          calls.push(["wait", op.name, options.minSleep, options.maxSleep]);
          return { ...op, done: true };
        }
      };
    }
  } as unknown as SignifyClient;

  return { client, calls };
}

test("getDidWebsSetup delegates to client.didwebs().setup", async () => {
  const fixture = setup();
  const { client, calls } = clientFixture([fixture]);

  assert.deepEqual(await getDidWebsSetup({ client, name: "aid1" }), fixture);
  assert.deepEqual(calls, [["setup", "aid1"]]);
});

test("ensureDidWebsSetup returns immediately when ready", async () => {
  const ready = setup({ ready: true, registryId: "Eregistry", registryReady: true, credentialSaid: "Ecredential" });
  const { client, calls } = clientFixture([ready]);

  assert.deepEqual(await ensureDidWebsSetup({ client, name: "aid1" }), ready);
  assert.deepEqual(calls, [["setup", "aid1"]]);
});

test("ensureDidWebsSetup creates missing registry, issues DA ACDC, and waits ready", async () => {
  const ready = setup({ ready: true, registryId: "Eregistry", registryReady: true, credentialSaid: "Ecredential" });
  const { client, calls } = clientFixture([
    setup(),
    setup({ registryId: "Eregistry", registryReady: true }),
    ready
  ]);

  assert.deepEqual(await ensureDidWebsSetup({ client, name: "aid1", pollMs: 3 }), ready);
  assert.deepEqual(calls.map(call => call[0]), [
    "setup",
    "create-registry",
    "registry-op",
    "wait",
    "setup",
    "issue-credential",
    "wait",
    "setup"
  ]);
  assert.deepEqual(calls[1], [
    "create-registry",
    {
      name: "aid1",
      registryName: "didwebs-designated-aliases-Eaid"
    }
  ]);
  assert.deepEqual(calls[3], ["wait", "registry-op", 3, 3]);
  assert.equal(calls[5][1], "aid1");
});

test("ensureDidWebsSetup waits for an existing pending registry before issuing", async () => {
  const ready = setup({ ready: true, registryId: "Eregistry", registryReady: true, credentialSaid: "Ecredential" });
  const { client, calls } = clientFixture([
    setup({ registryId: "Eregistry", registryReady: false }),
    setup({ registryId: "Eregistry", registryReady: true }),
    ready
  ]);

  assert.deepEqual(await ensureDidWebsSetup({ client, name: "aid1", pollMs: 1 }), ready);
  assert.equal(calls.some(call => call[0] === "create-registry"), false);
  assert.equal(calls.some(call => call[0] === "issue-credential"), true);
});

test("ensureDidWebsSetup waits without reissuing when DA credential exists", async () => {
  const ready = setup({ ready: true, registryId: "Eregistry", registryReady: true, credentialSaid: "Ecredential" });
  const { client, calls } = clientFixture([
    setup({ registryId: "Eregistry", registryReady: true, credentialSaid: "Ecredential" }),
    ready
  ]);

  assert.deepEqual(await ensureDidWebsSetup({ client, name: "aid1", pollMs: 1 }), ready);
  assert.equal(calls.some(call => call[0] === "issue-credential"), false);
});

test("ensureDidWebsSetup rejects registry-ready descriptors without issueArgs", async () => {
  const { client } = clientFixture([
    setup({ registryId: "Eregistry", registryReady: true, issueArgs: null })
  ]);

  await assert.rejects(
    () => ensureDidWebsSetup({ client, name: "aid1" }),
    /did not include designated-alias issueArgs/
  );
});

test("waitForDidWebsReady polls until ready", async () => {
  const ready = setup({ ready: true, registryId: "Eregistry", registryReady: true, credentialSaid: "Ecredential" });
  const { client, calls } = clientFixture([
    setup({ registryId: "Eregistry", registryReady: true, credentialSaid: "Ecredential" }),
    ready
  ]);

  assert.deepEqual(await waitForDidWebsReady({ client, name: "aid1", pollMs: 1 }), ready);
  assert.deepEqual(calls.map(call => call[0]), ["setup", "setup"]);
});

test("waitForDidWebsReady honors abort signals", async () => {
  const controller = new AbortController();
  controller.abort(new Error("stop"));
  const { client } = clientFixture([setup()]);

  await assert.rejects(
    () => waitForDidWebsReady({ client, name: "aid1", signal: controller.signal }),
    /stop/
  );
});
