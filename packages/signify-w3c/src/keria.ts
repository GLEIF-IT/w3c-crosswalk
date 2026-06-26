import type { SignifyClient } from "signify-ts";
import { Exchanges } from "signify-ts";
import { W3C_GRANT_ROUTE } from "./constants.js";
import { requiredString } from "./common.js";
import { issueVcJwt, issueVpJwt } from "./jwt.js";
import { statusUrl, transposeAcdcToW3cVc } from "./profile.js";
import { signerForIdentifier } from "./signify.js";
import type { JsonObject, W3CHeldCredential, W3CIssuanceContext, W3CPresentationResult } from "./types.js";

export class W3CKeriaClient {
  constructor(private readonly client: SignifyClient) {}

  async createIssuance(name: string, sourceCredentialSaid: string): Promise<W3CIssuanceContext> {
    const res = await this.client.fetch(
      `/identifiers/${name}/w3c/issuances`,
      "POST",
      { sourceCredentialSaid }
    );
    return await res.json();
  }

  async issuance(name: string, issuanceId: string): Promise<W3CIssuanceContext> {
    const res = await this.client.fetch(
      `/identifiers/${name}/w3c/issuances/${encodeURIComponent(issuanceId)}`,
      "GET",
      null
    );
    return await res.json();
  }

  async submitVcJwt(name: string, issuanceId: string, vcJwt: string): Promise<W3CIssuanceContext> {
    const res = await this.client.fetch(
      `/identifiers/${name}/w3c/issuances/${encodeURIComponent(issuanceId)}/vc-jwt`,
      "POST",
      { vcJwt }
    );
    return await res.json();
  }

  async deliverIssuance(name: string, issuance: W3CIssuanceContext): Promise<W3CIssuanceContext> {
    const issuanceId = requiredString(issuance.issuanceId ?? issuance.d, "W3C issuance id");
    const sender = await this.client.identifiers().get(name);
    const issuerAid = requiredString(issuance.issuerAid, "W3C issuance issuer AID");
    if ((sender as { prefix?: string }).prefix !== issuerAid) {
      throw new Error(`W3C issuance ${issuanceId} belongs to ${issuerAid}, not ${(sender as { prefix?: string }).prefix ?? name}`);
    }
    const payload = {
      holderAid: requiredString(issuance.holderAid, "W3C issuance holder AID"),
      holderDid: requiredString(issuance.holderDid, "W3C issuance holder DID"),
      issuerAid,
      issuerDid: requiredString(issuance.issuerDid, "W3C issuance issuer DID"),
      sourceCredentialSaid: requiredString(issuance.sourceCredentialSaid, "W3C issuance source credential SAID"),
      schemaSaid: requiredString(issuance.schemaSaid, "W3C issuance schema SAID"),
      issuanceId,
      vcJwt: requiredString(issuance.vcJwt, "W3C issuance VC-JWT"),
      statusUrl: requiredString(issuance.statusUrl, "W3C issuance status URL"),
      profile: requiredString(issuance.profile, "W3C issuance profile")
    };
    const [exn, sigs, atc] = await new Exchanges(this.client).createExchangeMessage(
      sender as never,
      W3C_GRANT_ROUTE,
      payload,
      {},
      payload.holderAid
    );
    const res = await this.client.fetch(
      `/identifiers/${name}/w3c/issuances/${encodeURIComponent(issuanceId)}/grant`,
      "POST",
      { exn: exn.sad, sigs, atc, rec: [payload.holderAid] }
    );
    return await res.json();
  }

  async credentials(name: string): Promise<W3CHeldCredential[]> {
    const res = await this.client.fetch(`/identifiers/${name}/w3c/credentials`, "GET", null);
    const body = await res.json();
    return body.credentials;
  }

  async credential(name: string, credentialId: string): Promise<W3CHeldCredential> {
    const res = await this.client.fetch(
      `/identifiers/${name}/w3c/credentials/${encodeURIComponent(credentialId)}`,
      "GET",
      null
    );
    return await res.json();
  }

  async present(name: string, descriptor: JsonObject, vpJwt: string): Promise<W3CPresentationResult> {
    const res = await this.client.fetch(
      `/identifiers/${name}/w3c/presentations`,
      "POST",
      { ...descriptor, vpJwt }
    );
    return await res.json();
  }
}

export async function issueW3CCredential({
  client,
  issuerName,
  sourceCredentialSaid,
  timeoutMs = 120000,
  pollMs = 1000
}: {
  client: SignifyClient;
  issuerName: string;
  sourceCredentialSaid: string;
  timeoutMs?: number;
  pollMs?: number;
}): Promise<W3CIssuanceContext> {
  const w3c = new W3CKeriaClient(client);
  let issuance = await w3c.createIssuance(issuerName, sourceCredentialSaid);
  if (!issuance.vcJwt) {
    const sourceCredential = issuance.sourceCredential;
    if (sourceCredential === undefined) {
      throw new Error("KERIA issuance context did not include sourceCredential");
    }
    const statusBaseUrl = typeof issuance.statusBaseUrl === "string"
      ? issuance.statusBaseUrl
      : statusUrl(issuance.statusUrl.replace(/\/status\/[^/]+$/u, ""), sourceCredentialSaid).replace(`/status/${sourceCredentialSaid}`, "");
    const unsecuredVc = transposeAcdcToW3cVc(sourceCredential, {
      issuerDid: issuance.issuerDid,
      statusBaseUrl
    });
    const signer = await signerForIdentifier(client, issuerName);
    const { vcJwt } = await issueVcJwt(unsecuredVc, {
      signer,
      verificationMethod: `${issuance.issuerDid}#${signer.kid}`
    });
    issuance = await w3c.submitVcJwt(issuerName, issuance.issuanceId, vcJwt);
  }

  const timeoutAt = Date.now() + timeoutMs;
  while (Date.now() < timeoutAt) {
    if (issuance.state === "grant_sent" && issuance.vcJwt) {
      return issuance;
    }
    if (issuance.state === "issued" || issuance.state === "delivery_pending") {
      issuance = await w3c.deliverIssuance(issuerName, issuance);
      continue;
    }
    if (issuance.state === "failed") {
      throw new Error(issuance.error ?? `W3C issuance ${issuance.issuanceId} failed`);
    }
    await delay(pollMs);
    issuance = await w3c.issuance(issuerName, issuance.issuanceId);
  }
  throw new Error(`Timed out waiting for W3C issuance delivery ${issuance.issuanceId}. Last state: ${issuance.state}.`);
}

export async function presentW3CCredential({
  client,
  holderName,
  credentialId,
  verifierRequest
}: {
  client: SignifyClient;
  holderName: string;
  credentialId: string;
  verifierRequest: JsonObject;
}): Promise<W3CPresentationResult> {
  const w3c = new W3CKeriaClient(client);
  const credential = await w3c.credential(holderName, credentialId);
  const vcJwt = requiredString(credential.vcJwt, "held W3C VC-JWT");
  const signer = await signerForIdentifier(client, holderName);
  const audience = stringValue(verifierRequest.aud) ?? stringValue(verifierRequest.client_id);
  const nonce = stringValue(verifierRequest.nonce);
  const { vpJwt } = await issueVpJwt([vcJwt], {
    holderDid: credential.holderDid,
    signer,
    audience,
    nonce
  });
  return await w3c.present(holderName, { ...verifierRequest, credentialId }, vpJwt);
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}
