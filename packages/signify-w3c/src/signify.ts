import type { SignifyClient } from "signify-ts";
import { rawSignatureFromCesrCigar } from "./encoding.js";
import type { Signer } from "./types.js";

export async function signerForIdentifier(
  client: SignifyClient,
  name: string,
  kid?: string
): Promise<Signer> {
  const hab = await client.identifiers().get(name);
  const keys = Array.isArray((hab as { state?: { k?: unknown } }).state?.k)
    ? (hab as { state: { k: string[] } }).state.k
    : [];
  const resolvedKid = kid ?? keys[0] ?? (hab as { prefix?: string }).prefix;
  if (typeof resolvedKid !== "string" || resolvedKid.length === 0) {
    throw new Error(`identifier ${name} does not expose a signing key`);
  }
  if (client.manager === null) {
    throw new Error("Signify client is not connected to a key manager");
  }
  const keeper = client.manager.get(hab);
  return {
    kid: resolvedKid,
    sign: async (data: Uint8Array): Promise<Uint8Array> => {
      const sigs = await keeper.sign(data, false);
      const signature = sigs[0] as string | { qb64: string };
      const qb64 = typeof signature === "string" ? signature : signature.qb64;
      return rawSignatureFromCesrCigar(qb64);
    }
  };
}
