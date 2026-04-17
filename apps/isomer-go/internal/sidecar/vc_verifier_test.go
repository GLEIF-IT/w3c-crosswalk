// Semantic contract tests for VC-JWT verification behavior in the Go sidecar.
package sidecar

import (
	"context"
	"errors"
	"testing"
)

func TestVerifyVCRejectsMalformedJWT(t *testing.T) {
	publicKey, _ := testKeyPair()
	verifier, _ := newVerifierUnderTest(publicKey)

	result := verifier.VerifyVC(context.Background(), "not-a-jwt")

	mustError(t, result, "expected compact JWT")
}

func TestVerifyVCRejectsClaimMismatch(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, _ := newVerifierUnderTest(publicKey)

	payload := validVCPayload("https://status.example/cred-1")
	payload["vc"].(map[string]any)["issuer"] = "did:webs:issuer.example:dws:Eother"
	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, payload, privateKey)

	result := verifier.VerifyVC(context.Background(), token)

	mustError(t, result, "JWT iss does not match vc.issuer")
}

func TestVerifyVCReportsResolverFailure(t *testing.T) {
	_, privateKey := testKeyPair()
	status := &stubStatusClient{responses: map[string]map[string]any{}, errors: map[string]error{}}
	verifier := &verifier{
		resolver:     stubResolver{err: errors.New("resolver unavailable")},
		parser:       stubParser{},
		proofChecker: stubProofChecker{},
		statusClient: status,
	}

	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, validVCPayload("https://status.example/cred-1"), privateKey)

	result := verifier.VerifyVC(context.Background(), token)

	mustError(t, result, "resolver unavailable")
	if result.Checks["signatureValid"] != false {
		t.Fatalf("expected signatureValid=false, got %#v", result.Checks)
	}
}

func TestVerifyVCRejectsRevokedCredential(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, status := newVerifierUnderTest(publicKey)
	status.responses["https://status.example/cred-1"] = map[string]any{
		"revoked":  true,
		"credSaid": "Eabc123",
	}

	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, validVCPayload("https://status.example/cred-1"), privateKey)

	result := verifier.VerifyVC(context.Background(), token)

	mustError(t, result, "is revoked")
}

func TestVerifyVCTreatsMissingStatusURLAsActive(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, status := newVerifierUnderTest(publicKey)

	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, validVCPayload(""), privateKey)

	result := verifier.VerifyVC(context.Background(), token)

	if !result.OK {
		t.Fatalf("expected success, got %#v", result)
	}
	if result.Checks["statusActive"] != true {
		t.Fatalf("expected statusActive=true, got %#v", result.Checks)
	}
	if len(status.requested) != 1 || status.requested[0] != "" {
		t.Fatalf("expected empty status lookup, got %#v", status.requested)
	}
}
