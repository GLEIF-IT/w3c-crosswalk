import assert from "node:assert/strict";
import test from "node:test";
import { sha512 } from "@noble/hashes/sha512";
import {
  VRD_SCHEMA,
  base64UrlDecode,
  base64UrlEncode,
  canonicalizeDidWebs,
  decodeJwt,
  issueVcJwt,
  issueVpJwt,
  rawSignatureFromCesrCigar,
  transposeAcdcToW3cVc
} from "./index.js";
import type { Signer } from "./index.js";

const signer: Signer = {
  kid: "Eissuer-key",
  sign: data => sha512(data)
};

const acdc = {
  d: "Ecredential",
  i: "Eissuer",
  s: VRD_SCHEMA,
  ri: "Eregistry",
  a: {
    i: "Eholder",
    AID: "Eholder",
    DID: "did:webs:example.com:dws:Eholder",
    LegalName: "Example Holder",
    HeadquartersAddress: "1 Main St, Suite 2, Denver, CO 80202, US",
    dt: "2026-06-03T00:00:00Z"
  },
  e: {
    le: {
      n: "ElegalEntity",
      s: "ElegalEntitySchema"
    }
  },
  r: {
    usageDisclaimer: { l: "usage" },
    issuanceDisclaimer: { l: "issuance" },
    privacyDisclaimer: { l: "privacy" }
  }
};

test("canonicalizeDidWebs repairs local host-port DIDs", () => {
  assert.equal(
    canonicalizeDidWebs("did:webs:127.0.0.1:3902:dws:Eissuer"),
    "did:webs:127.0.0.1%3A3902:dws:Eissuer"
  );
});

test("base64url helpers round-trip raw signature bytes", () => {
  const raw = new Uint8Array(64).fill(7);
  const qb64 = `0B${base64UrlEncode(raw)}`;
  assert.deepEqual(rawSignatureFromCesrCigar(qb64), raw);
  assert.deepEqual(base64UrlDecode(base64UrlEncode(raw)), raw);
});

test("transposeAcdcToW3cVc projects the Isomer VRD profile", () => {
  const vc = transposeAcdcToW3cVc(acdc, {
    issuerDid: "did:webs:127.0.0.1:3902:dws:Eissuer",
    statusBaseUrl: "http://127.0.0.1:3902/w3c/vc"
  });

  assert.equal(vc.id, "urn:said:Ecredential");
  assert.equal(vc.issuer, "did:webs:127.0.0.1%3A3902:dws:Eissuer");
  assert.deepEqual(vc.type, ["VerifiableCredential", "VRDCredential", "KERIIsomerCredential"]);
  assert.deepEqual((vc.credentialSubject as Record<string, unknown>).id, "did:webs:example.com:dws:Eholder");
});

test("issueVcJwt builds a compact VC-JWT with embedded Data Integrity proof", async () => {
  const vc = transposeAcdcToW3cVc(acdc, {
    issuerDid: "did:webs:example.com:dws:Eissuer",
    statusBaseUrl: "http://status.example/w3c/vc"
  });
  const { vcJwt, securedVc } = await issueVcJwt(vc, {
    signer,
    verificationMethod: "did:webs:example.com:dws:Eissuer#Eissuer-key",
    proofCreated: "2026-06-03T00:00:00Z"
  });

  const decoded = decodeJwt(vcJwt);
  assert.equal(decoded.header.alg, "EdDSA");
  assert.equal(decoded.header.typ, "JWT");
  assert.equal(decoded.payload.iss, "did:webs:example.com:dws:Eissuer");
  assert.equal((securedVc.proof as Record<string, unknown>).proofValue?.toString().startsWith("z"), true);
});

test("issueVpJwt embeds VC-JWT strings and binds audience and nonce", async () => {
  const { vpJwt } = await issueVpJwt(["vc.jwt.value"], {
    holderDid: "did:webs:example.com:dws:Eholder",
    signer: { ...signer, kid: "Eholder-key" },
    audience: "https://verifier.example",
    nonce: "nonce-1",
    presentationId: "urn:uuid:test"
  });

  const decoded = decodeJwt(vpJwt);
  assert.equal(decoded.payload.iss, "did:webs:example.com:dws:Eholder");
  assert.equal(decoded.payload.aud, "https://verifier.example");
  assert.equal(decoded.payload.nonce, "nonce-1");
  assert.deepEqual(
    ((decoded.payload.vp as Record<string, unknown>).verifiableCredential as string[]),
    ["vc.jwt.value"]
  );
});
