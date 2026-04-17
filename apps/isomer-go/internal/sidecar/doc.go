// Package sidecar implements the Go external verifier used by Isomer's W3C
// acceptance tests.
//
// The package owns only the narrow W3C-facing verification pipeline:
// decoding VC-JWTs and VP-JWTs, checking local claim relationships, resolving
// current did:webs key state through the HTTP resolver service, verifying
// embedded Data Integrity proofs, consulting projected credential status, and
// recursively checking nested VC-JWTs inside VP-JWTs.
//
// It does not attempt Python Isomer's TEL-aware ACDC/W3C pair verification.
package sidecar
