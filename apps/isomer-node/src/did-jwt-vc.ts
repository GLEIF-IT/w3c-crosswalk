/**
 * Thin `did-jwt-vc` adapters for the sidecar verifier.
 *
 * `did-jwt-vc` owns VC-JWT and VP-JWT envelope validation and signature
 * verification. The sidecar still verifies embedded Data Integrity proofs and
 * projected status records separately because those checks live outside the
 * JWT VC library boundary.
 */
import { verifyCredential, verifyPresentation } from "did-jwt-vc";
import type { Resolvable } from "did-resolver";
import type { Operation } from "effection";
import { promiseToOperation } from "./effection.js";

/**
 * Verify one VC-JWT envelope and signature through `did-jwt-vc`.
 *
 * This does not verify the embedded Data Integrity proof or credential status.
 */
export function verifyCredentialJwtOp(
  token: string,
  resolver: Resolvable
): Operation<void> {
  return promiseToOperation(async () => {
    await verifyCredential(token, resolver, { policies: { format: true } });
  });
}

/**
 * Verify one VP-JWT envelope and signature through `did-jwt-vc`.
 *
 * This does not verify embedded credential status or embedded Data Integrity
 * proofs within nested VCs; the sidecar handles those separately.
 */
export function verifyPresentationJwtOp(
  token: string,
  resolver: Resolvable,
  options: { audience?: string; nonce?: string }
): Operation<void> {
  return promiseToOperation(async () => {
    await verifyPresentation(token, resolver, {
      domain: options.audience,
      challenge: options.nonce,
      policies: { format: true }
    });
  });
}
