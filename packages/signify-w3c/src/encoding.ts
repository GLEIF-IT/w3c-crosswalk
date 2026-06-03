const BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function utf8String(value: Uint8Array): string {
  return new TextDecoder().decode(value);
}

export function base64UrlEncode(data: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("base64url");
  }
  let binary = "";
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlDecode(value: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Uint8Array.from(Buffer.from(value, "base64url"));
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
}

export function canonicalJsonBytes(data: unknown): Uint8Array {
  return utf8Bytes(canonicalJson(data));
}

export function canonicalJson(data: unknown): string {
  return JSON.stringify(sortJson(data));
}

export function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function encodeMultibaseBase58btc(data: Uint8Array): string {
  if (data.length === 0) {
    return "z";
  }

  let number = 0n;
  for (const byte of data) {
    number = (number << 8n) + BigInt(byte);
  }

  let encoded = "";
  while (number > 0n) {
    const remainder = Number(number % 58n);
    encoded = BASE58BTC_ALPHABET[remainder] + encoded;
    number /= 58n;
  }

  let leadingZeroes = 0;
  for (const byte of data) {
    if (byte !== 0) {
      break;
    }
    leadingZeroes += 1;
  }

  return `z${"1".repeat(leadingZeroes)}${encoded}`;
}

export function decodeMultibaseBase58btc(value: string): Uint8Array {
  if (!value.startsWith("z")) {
    throw new Error("expected multibase base58btc value with z prefix");
  }

  const encoded = value.slice(1);
  let number = 0n;
  for (const character of encoded) {
    const digit = BASE58BTC_ALPHABET.indexOf(character);
    if (digit < 0) {
      throw new Error(`invalid base58btc character ${character}`);
    }
    number = number * 58n + BigInt(digit);
  }

  const bytes: number[] = [];
  while (number > 0n) {
    bytes.unshift(Number(number & 0xffn));
    number >>= 8n;
  }

  let leadingZeroes = 0;
  for (const character of encoded) {
    if (character !== "1") {
      break;
    }
    leadingZeroes += 1;
  }

  return Uint8Array.from([...new Array(leadingZeroes).fill(0), ...bytes]);
}

export function rawSignatureFromCesrCigar(qb64: string): Uint8Array {
  if (!qb64.startsWith("0B")) {
    throw new Error("expected unindexed Ed25519 CESR signature");
  }
  const raw = base64UrlDecode(qb64.slice(2));
  if (raw.length !== 64) {
    throw new Error(`expected 64-byte Ed25519 signature, got ${raw.length}`);
  }
  return raw;
}

function sortJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortJson);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, sortJson(child)])
    );
  }
  return value;
}
