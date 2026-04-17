/**
 * Local multibase and base64url helpers used by the Node sidecar.
 *
 * The resolver and proof layers need small binary helpers, but the sidecar does
 * not otherwise depend on a broader encoding utility package.
 */
// Base58btc alphabet used by multibase `z...` values such as Multikey
// `publicKeyMultibase` fields and Data Integrity proof values.
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Decode one multibase base58btc value into raw bytes.
 */
export function decodeBase58btcMultibase(value: string): Uint8Array {
  if (!value.startsWith("z")) {
    throw new Error("expected multibase base58btc value with z prefix");
  }

  const encoded = value.slice(1);
  let number = 0n;
  for (const character of encoded) {
    const digit = ALPHABET.indexOf(character);
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

/**
 * Decode one base64url string into raw bytes.
 */
export function base64UrlDecode(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "base64url"));
}

/**
 * Encode raw bytes as base64url.
 */
export function base64UrlEncode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}
