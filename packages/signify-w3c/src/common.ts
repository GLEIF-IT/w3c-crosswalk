export function utcTimestamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function canonicalizeDidWebs(did: string): string {
  if (!did.startsWith("did:webs:")) {
    return did;
  }
  if (did.toLowerCase().includes("%3a")) {
    return did;
  }

  const [body, query = ""] = did.split("?", 2);
  const segments = body.slice("did:webs:".length).split(":");
  if (segments.length < 3 || !/^\d+$/.test(segments[1] ?? "")) {
    return did;
  }

  const [domain, port, ...rest] = segments;
  const normalized = `did:webs:${domain}%3A${port}:${rest.join(":")}`;
  return query ? `${normalized}?${query}` : normalized;
}

export function canonicalizeDidUrl(value: string): string {
  const [did, fragment] = value.split("#", 2);
  const canonical = canonicalizeDidWebs(did);
  return fragment === undefined ? canonical : `${canonical}#${fragment}`;
}

export function saidUrn(said: string): string {
  return said ? `urn:said:${said}` : "";
}

export function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} is required`);
  }
  return value.trim();
}

export function requiredRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function unixTimestamp(value: string): number {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) {
    throw new Error(`invalid RFC3339 timestamp ${value}`);
  }
  return Math.floor(time / 1000);
}
