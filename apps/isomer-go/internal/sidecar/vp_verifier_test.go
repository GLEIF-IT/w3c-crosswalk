// Semantic contract tests for VP-JWT verification behavior in the Go sidecar.
package sidecar

import (
	"context"
	"testing"
)

func TestVerifyVPRejectsAudienceMismatch(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, _ := newVerifierUnderTest(publicKey)
	nested := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, validVCPayload(""), privateKey)
	payload := validVPPayload(nested)
	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:holder.example:dws:Eholder#key-1"}, payload, privateKey)

	result := verifier.VerifyVP(context.Background(), token, "wrong-audience", "nonce-123")

	mustError(t, result, "JWT aud does not match expected audience")
}

func TestVerifyVPRejectsNonceMismatch(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, _ := newVerifierUnderTest(publicKey)
	nested := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, validVCPayload(""), privateKey)
	payload := validVPPayload(nested)
	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:holder.example:dws:Eholder#key-1"}, payload, privateKey)

	result := verifier.VerifyVP(context.Background(), token, "aud-123", "wrong-nonce")

	mustError(t, result, "JWT nonce does not match expected nonce")
}

func TestVerifyVPRejectsInvalidCredentialListShape(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, _ := newVerifierUnderTest(publicKey)
	payload := validVPPayload("nested")
	payload["vp"].(map[string]any)["verifiableCredential"] = "not-a-list"
	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:holder.example:dws:Eholder#key-1"}, payload, privateKey)

	result := verifier.VerifyVP(context.Background(), token, "aud-123", "nonce-123")

	mustError(t, result, "vp.verifiableCredential must be a list")
}

func TestVerifyVPRejectsNonStringNestedCredential(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, _ := newVerifierUnderTest(publicKey)
	payload := validVPPayload("")
	payload["vp"].(map[string]any)["verifiableCredential"] = []any{map[string]any{"vc": "object"}}
	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:holder.example:dws:Eholder#key-1"}, payload, privateKey)

	result := verifier.VerifyVP(context.Background(), token, "aud-123", "nonce-123")

	mustError(t, result, "only nested VC-JWT strings are supported")
	if result.Checks["embeddedCredentialsVerified"] != float64(0) && result.Checks["embeddedCredentialsVerified"] != 0 {
		t.Fatalf("expected zero verified credentials, got %#v", result.Checks)
	}
}

func TestVerifyVPPropagatesNestedVCFailures(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, status := newVerifierUnderTest(publicKey)
	status.responses["https://status.example/revoked"] = map[string]any{
		"revoked":  true,
		"credSaid": "Erevoked",
	}
	nested := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, validVCPayload("https://status.example/revoked"), privateKey)
	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:holder.example:dws:Eholder#key-1"}, validVPPayload(nested), privateKey)

	result := verifier.VerifyVP(context.Background(), token, "aud-123", "nonce-123")

	mustError(t, result, "nested credential: credential Erevoked is revoked")
}

func TestVerifyVPCountsVerifiedNestedCredentials(t *testing.T) {
	publicKey, privateKey := testKeyPair()
	verifier, _ := newVerifierUnderTest(publicKey)
	nested := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:issuer.example:dws:Eissuer#key-1"}, validVCPayload(""), privateKey)
	token := makeSignedJWT(t, map[string]any{"alg": "EdDSA", "kid": "did:webs:holder.example:dws:Eholder#key-1"}, validVPPayload(nested), privateKey)

	result := verifier.VerifyVP(context.Background(), token, "aud-123", "nonce-123")

	if !result.OK {
		t.Fatalf("expected success, got %#v", result)
	}
	if result.Checks["embeddedCredentialsVerified"] != 1 {
		t.Fatalf("expected one verified credential, got %#v", result.Checks)
	}
	if len(result.Nested) != 1 || !result.Nested[0].OK {
		t.Fatalf("expected one successful nested result, got %#v", result.Nested)
	}
}
