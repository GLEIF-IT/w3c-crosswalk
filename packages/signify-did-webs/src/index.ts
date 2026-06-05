import type {
  DidWebsSetupInfo,
  SignifyClient
} from "signify-ts";

export interface DidWebsSetupOptions {
  client: SignifyClient;
  name: string;
}

export interface DidWebsEnsureOptions extends DidWebsSetupOptions {
  timeoutMs?: number;
  pollMs?: number;
  signal?: AbortSignal;
}

export const DEFAULT_DID_WEBS_TIMEOUT_MS = 120000;
export const DEFAULT_DID_WEBS_POLL_MS = 1000;

export async function getDidWebsSetup({
  client,
  name
}: DidWebsSetupOptions): Promise<DidWebsSetupInfo> {
  return await client.didwebs().setup(name);
}

export async function ensureDidWebsSetup(
  options: DidWebsEnsureOptions
): Promise<DidWebsSetupInfo> {
  const { client, name } = options;
  const deadline = deadlineFromOptions(options);
  let setup = await getDidWebsSetup({ client, name });
  if (setup.ready) {
    return setup;
  }

  if (setup.registry.registryId === null) {
    throwIfAborted(options.signal);
    const registry = await client.registries().create(setup.registry.createArgs);
    await client.operations().wait(await registry.op(), waitOptions(options));
    setup = await getDidWebsSetup({ client, name });
  }

  if (!setup.registry.ready && !setup.ready) {
    setup = await waitForSetupState(
      options,
      deadline,
      candidate => candidate.ready || candidate.registry.ready,
      "did:webs registry"
    );
  }

  if (!setup.ready && setup.designatedAlias.credentialSaid === null) {
    if (setup.designatedAlias.issueArgs === null) {
      throw new Error(`KERIA did:webs setup for ${name} did not include designated-alias issueArgs`);
    }
    throwIfAborted(options.signal);
    const issuance = await client.credentials().issue(name, setup.designatedAlias.issueArgs);
    await client.operations().wait(issuance.op, waitOptions(options));
    setup = await getDidWebsSetup({ client, name });
  }

  if (setup.ready) {
    return setup;
  }

  return await waitForSetupState(
    options,
    deadline,
    candidate => candidate.ready,
    "did:webs readiness"
  );
}

export async function waitForDidWebsReady(
  options: DidWebsEnsureOptions
): Promise<DidWebsSetupInfo> {
  return await waitForSetupState(
    options,
    deadlineFromOptions(options),
    candidate => candidate.ready,
    "did:webs readiness"
  );
}

async function waitForSetupState(
  options: DidWebsEnsureOptions,
  deadline: number,
  predicate: (setup: DidWebsSetupInfo) => boolean,
  label: string
): Promise<DidWebsSetupInfo> {
  const { client, name } = options;
  while (true) {
    throwIfAborted(options.signal);
    const setup = await getDidWebsSetup({ client, name });
    if (predicate(setup)) {
      return setup;
    }
    await sleepForPoll(options, deadline, label);
  }
}

function waitOptions(options: DidWebsEnsureOptions) {
  const pollMs = normalizedPollMs(options.pollMs);
  return {
    signal: options.signal,
    minSleep: pollMs,
    maxSleep: pollMs,
    increaseFactor: 1
  };
}

function deadlineFromOptions(options: DidWebsEnsureOptions): number {
  return Date.now() + normalizedTimeoutMs(options.timeoutMs);
}

async function sleepForPoll(
  options: DidWebsEnsureOptions,
  deadline: number,
  label: string
): Promise<void> {
  const now = Date.now();
  if (now >= deadline) {
    throw new Error(`${label} timed out for ${options.name} after ${normalizedTimeoutMs(options.timeoutMs)}ms`);
  }
  await sleep(Math.min(normalizedPollMs(options.pollMs), deadline - now), options.signal);
}

function normalizedTimeoutMs(timeoutMs: number | undefined): number {
  if (timeoutMs === undefined) {
    return DEFAULT_DID_WEBS_TIMEOUT_MS;
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeoutMs must be a positive finite number");
  }
  return timeoutMs;
}

function normalizedPollMs(pollMs: number | undefined): number {
  if (pollMs === undefined) {
    return DEFAULT_DID_WEBS_POLL_MS;
  }
  if (!Number.isFinite(pollMs) || pollMs <= 0) {
    throw new Error("pollMs must be a positive finite number");
  }
  return pollMs;
}

async function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(done, ms);
    const onAbort = () => {
      clearTimeout(timeout);
      reject(abortError(signal));
    };
    function done() {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw abortError(signal);
  }
}

function abortError(signal?: AbortSignal): Error {
  return signal?.reason instanceof Error
    ? signal.reason
    : new Error("did:webs setup aborted");
}
