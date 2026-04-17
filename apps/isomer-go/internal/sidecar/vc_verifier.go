package sidecar

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trustbloc/vc-go/dataintegrity/models"
)

// vcChecks records which VC verification stages completed successfully.
type vcChecks struct {
	JWTEnvelopeValid        bool
	SignatureValid          bool
	DataIntegrityProofValid bool
	StatusActive            bool
	VCGoParsed              bool
}

// mapValue converts the typed check set into the stable JSON shape exposed by
// the sidecar HTTP API.
func (c vcChecks) mapValue() map[string]any {
	return map[string]any{
		"jwtEnvelopeValid":        c.JWTEnvelopeValid,
		"signatureValid":          c.SignatureValid,
		"dataIntegrityProofValid": c.DataIntegrityProofValid,
		"statusActive":            c.StatusActive,
		"vcGoParsed":              c.VCGoParsed,
	}
}

// VerifyVC runs the Go sidecar's VC-JWT verification pipeline and returns the
// stable HTTP response shape expected by integration callers.
func (v *verifier) VerifyVC(ctx context.Context, token string) *verificationResult {
	checks := vcChecks{}
	result := newVerificationResult("vc+jwt", checks.mapValue())

	parts, err := decodeJWT(token)
	if err != nil {
		return result.fail(err)
	}

	vc, err := credentialFromJWT(parts)
	if err != nil {
		return result.fail(err)
	}
	result.Payload = vc

	if err = validateVCClaims(parts.Payload, vc); err != nil {
		return result.fail(err)
	}
	checks.JWTEnvelopeValid = true
	result.Checks = checks.mapValue()

	// This vc-go parse step is structural only in the sidecar's current setup.
	// It does not resolve did:webs key state here because proof checks are
	// disabled and no DID resolver is passed into the parser.
	if err = v.parser.ParseCredential(token); err != nil {
		return result.fail(err)
	}
	checks.VCGoParsed = true
	result.Checks = checks.mapValue()

	// did:webs resolution for JOSE happens here: verifyJWTSignature follows the
	// JWT `kid` through v.resolver.publicJWK(...) into didWebsResolver.resolve(...).
	if err = v.verifyJWTSignature(ctx, parts); err != nil {
		return result.fail(err)
	}
	checks.SignatureValid = true
	result.Checks = checks.mapValue()

	// did:webs resolution for the embedded proof happens inside the trustbloc
	// Data Integrity verifier because newVerifier wired v.resolver in as its
	// DIDResolver dependency.
	if err = v.verifyDataIntegrityProof(vc); err != nil {
		return result.fail(err)
	}
	checks.DataIntegrityProofValid = true
	result.Checks = checks.mapValue()

	if err = v.verifyCredentialStatus(ctx, vc); err != nil {
		return result.fail(err)
	}
	checks.StatusActive = true
	result.Checks = checks.mapValue()

	result.OK = true
	return result
}

// credentialFromJWT requires the `vc` claim and returns it as a JSON object.
func credentialFromJWT(parts *jwtParts) (map[string]any, error) {
	vc := asMap(parts.Payload["vc"])
	if vc == nil {
		return nil, fmt.Errorf("missing vc claim")
	}
	return vc, nil
}

// verifyJWTSignature resolves the current verification key and checks the JOSE
// signature bytes against that resolved JWK.
func (v *verifier) verifyJWTSignature(ctx context.Context, parts *jwtParts) error {
	// We keep JOSE verification explicit here even though vc-go parses the JWT,
	// because the sidecar wants the key-resolution seam and signature failure
	// reporting to stay obvious to maintainers.
	kid := asString(parts.Header["kid"])
	jwk, err := v.resolver.publicJWK(ctx, kid)
	if err != nil {
		return err
	}
	return verifyJWTSignature(parts, jwk)
}

// verifyDataIntegrityProof verifies the embedded VC proof block against the
// resolved did:webs verification method.
func (v *verifier) verifyDataIntegrityProof(vc map[string]any) error {
	vcBytes, err := json.Marshal(vc)
	if err != nil {
		return err
	}
	if err = v.proofChecker.VerifyProof(vcBytes, &models.ProofOptions{
		Purpose:   "assertionMethod",
		ProofType: models.DataIntegrityProof,
	}); err != nil {
		return fmt.Errorf("Data Integrity proof verification failed: %w", err)
	}
	return nil
}

// verifyCredentialStatus fetches the projected W3C status document and rejects
// revoked credentials.
func (v *verifier) verifyCredentialStatus(ctx context.Context, vc map[string]any) error {
	status, err := v.statusClient.Fetch(ctx, statusURL(vc))
	if err != nil {
		return err
	}
	// Missing credentialStatus means there is no projected W3C status resource to
	// dereference for this credential, so the harness treats the credential as
	// active rather than inventing a missing-status failure mode.
	if !statusIsRevoked(status) {
		return nil
	}
	return fmt.Errorf("credential %v is revoked", status["credSaid"])
}
