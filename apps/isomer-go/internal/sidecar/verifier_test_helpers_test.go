// Shared test fixtures and stub seams for the Go verifier unit tests.
package sidecar

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// stubParser lets tests force vc-go parser failures without involving the real
// trustbloc parser.
type stubParser struct {
	credentialErr   error
	presentationErr error
}

func (s stubParser) ParseCredential(string) error {
	return s.credentialErr
}

func (s stubParser) ParsePresentation(string) error {
	return s.presentationErr
}

// stubResolver returns one pre-selected JWK or resolver error for signature
// verification tests.
type stubResolver struct {
	jwk map[string]any
	err error
}

func (s stubResolver) publicJWK(context.Context, string) (map[string]any, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.jwk, nil
}

// stubProofChecker lets tests force embedded proof verification failures.
type stubProofChecker struct {
	err error
}

func (s stubProofChecker) VerifyProof([]byte, *ProofOptions) error {
	return s.err
}

// stubStatusClient captures status lookups and returns canned projected status
// documents.
type stubStatusClient struct {
	responses map[string]map[string]any
	errors    map[string]error
	requested []string
}

func (s *stubStatusClient) Fetch(_ context.Context, url string) (map[string]any, error) {
	s.requested = append(s.requested, url)
	if err, ok := s.errors[url]; ok {
		return nil, err
	}
	if response, ok := s.responses[url]; ok {
		return response, nil
	}
	return nil, nil
}

// newVerifierUnderTest returns a verifier with overridable seams and a shared
// status stub for inspection in tests.
func newVerifierUnderTest(publicKey ed25519.PublicKey) (*verifier, *stubStatusClient) {
	status := &stubStatusClient{
		responses: map[string]map[string]any{},
		errors:    map[string]error{},
	}
	return &verifier{
		resolver:     stubResolver{jwk: publicJWK(publicKey)},
		parser:       stubParser{},
		proofChecker: stubProofChecker{},
		statusClient: status,
	}, status
}

// publicJWK encodes an Ed25519 public key as the OKP JWK shape the sidecar
// expects from resolved DID methods.
func publicJWK(publicKey ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(publicKey),
	}
}

// makeSignedJWT builds one real EdDSA compact JWT for unit tests that need
// end-to-end JOSE verification to pass locally.
func makeSignedJWT(t *testing.T, header, payload map[string]any, privateKey ed25519.PrivateKey) string {
	t.Helper()

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	headerPart := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := []byte(headerPart + "." + payloadPart)
	signature := ed25519.Sign(privateKey, signingInput)

	return headerPart + "." + payloadPart + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// testKeyPair returns a stable Ed25519 keypair so test fixtures remain
// deterministic across runs.
func testKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

// validVCPayload returns the representative VC-JWT payload used across the VC
// verification tests.
func validVCPayload(statusURL string) map[string]any {
	payload := map[string]any{
		"iss": "did:webs:issuer.example:dws:Eissuer",
		"sub": "did:webs:holder.example:dws:Eholder",
		"jti": "urn:vc:test:123",
		"iat": 1700000000,
		"nbf": 1700000000,
		"vc": map[string]any{
			"issuer": "did:webs:issuer.example:dws:Eissuer",
			"id":     "urn:vc:test:123",
			"credentialSubject": map[string]any{
				"id": "did:webs:holder.example:dws:Eholder",
			},
			"proof": map[string]any{"type": "DataIntegrityProof"},
		},
	}
	if statusURL != "" {
		payload["vc"].(map[string]any)["credentialStatus"] = map[string]any{"id": statusURL}
	}
	return payload
}

// validVPPayload returns the representative VP-JWT payload used across nested
// VC verification tests.
func validVPPayload(nested string) map[string]any {
	return map[string]any{
		"iss":   "did:webs:holder.example:dws:Eholder",
		"aud":   "aud-123",
		"nonce": "nonce-123",
		"iat":   1700000000,
		"vp": map[string]any{
			"holder":               "did:webs:holder.example:dws:Eholder",
			"verifiableCredential": []any{nested},
		},
	}
}

// mustError asserts that one verification result failed and, when requested,
// contains a particular error substring.
func mustError(t *testing.T, result *verificationResult, contains string) {
	t.Helper()
	if result.OK {
		t.Fatal("expected failure result")
	}
	if len(result.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
	if contains == "" {
		return
	}
	if !containsError(result.Errors, contains) {
		t.Fatalf("expected error containing %q, got %#v", contains, result.Errors)
	}
}

// containsError reports whether any sidecar error string contains the expected
// test substring.
func containsError(errorsList []string, want string) bool {
	for _, err := range errorsList {
		if strings.Contains(err, want) {
			return true
		}
	}
	return false
}
