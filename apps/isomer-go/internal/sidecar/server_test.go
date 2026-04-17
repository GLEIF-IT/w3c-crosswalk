// HTTP contract tests for the isomer-go sidecar routes.
//
// These tests lock the public route behavior: health, bad-body handling,
// required-token failures, request forwarding into the verifier seam, and panic
// recovery.
package sidecar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeVerifier records the request data the handlers forward into the runtime
// seam and can optionally panic to exercise recovery behavior.
type fakeVerifier struct {
	vcResult *verificationResult
	vpResult *verificationResult

	vcPanic bool
	vpPanic bool

	lastVCToken string
	lastVPToken string
	lastVPAud   string
	lastVPNonce string
}

// VerifyVC satisfies the handler seam for VC route tests.
func (f *fakeVerifier) VerifyVC(_ context.Context, token string) *verificationResult {
	if f.vcPanic {
		panic("boom")
	}
	f.lastVCToken = token
	return f.vcResult
}

// VerifyVP satisfies the handler seam for VP route tests.
func (f *fakeVerifier) VerifyVP(_ context.Context, token, audience, nonce string) *verificationResult {
	if f.vpPanic {
		panic("boom")
	}
	f.lastVPToken = token
	f.lastVPAud = audience
	f.lastVPNonce = nonce
	return f.vpResult
}

func TestHealthEndpoint(t *testing.T) {
	server := newServerWithVerifier(Config{}, &fakeVerifier{})
	response := sendRequest(t, server.handler(), http.MethodGet, "/healthz", "")

	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}

	body := decodeBody(t, response)
	if body["ok"] != true {
		t.Fatalf("expected ok health response, got %#v", body)
	}
	if body["service"] != "isomer-go" {
		t.Fatalf("expected service name, got %#v", body)
	}
}

func TestVerifyVCHandlerPassesTokenToVerifier(t *testing.T) {
	verifier := &fakeVerifier{
		vcResult: &verificationResult{
			OK:       true,
			Kind:     "vc+jwt",
			Errors:   []string{},
			Warnings: []string{},
			Checks:   map[string]any{"jwtEnvelopeValid": true},
		},
	}
	server := newServerWithVerifier(Config{}, verifier)

	response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vc", `{"token":"abc"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}
	if verifier.lastVCToken != "abc" {
		t.Fatalf("expected token to reach verifier, got %q", verifier.lastVCToken)
	}
}

func TestVerifyVPHandlerPassesAudienceAndNonce(t *testing.T) {
	verifier := &fakeVerifier{
		vpResult: &verificationResult{
			OK:       true,
			Kind:     "vp+jwt",
			Errors:   []string{},
			Warnings: []string{},
			Checks:   map[string]any{"jwtEnvelopeValid": true},
		},
	}
	server := newServerWithVerifier(Config{}, verifier)

	response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vp", `{"token":"abc","audience":"aud","nonce":"n-1"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}
	if verifier.lastVPToken != "abc" || verifier.lastVPAud != "aud" || verifier.lastVPNonce != "n-1" {
		t.Fatalf("unexpected verifier inputs: token=%q audience=%q nonce=%q", verifier.lastVPToken, verifier.lastVPAud, verifier.lastVPNonce)
	}
}

func TestVerifyHandlersRejectBadJSON(t *testing.T) {
	server := newServerWithVerifier(Config{}, &fakeVerifier{})

	for _, path := range []string{"/verify/vc", "/verify/vp"} {
		response := sendRequest(t, server.handler(), http.MethodPost, path, `{"token":`)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d", path, response.Code)
		}
		body := decodeBody(t, response)
		if body["ok"] != false {
			t.Fatalf("%s: expected ok=false, got %#v", path, body)
		}
	}
}

func TestVerifyHandlersRequireToken(t *testing.T) {
	server := newServerWithVerifier(Config{}, &fakeVerifier{})

	for _, path := range []string{"/verify/vc", "/verify/vp"} {
		response := sendRequest(t, server.handler(), http.MethodPost, path, `{}`)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d", path, response.Code)
		}
		body := decodeBody(t, response)
		if body["error"] != "verification request requires token" {
			t.Fatalf("%s: unexpected body %#v", path, body)
		}
	}
}

func TestRecoverHandlerReturnsJSONOnVerifierPanic(t *testing.T) {
	server := newServerWithVerifier(Config{}, &fakeVerifier{vcPanic: true})

	response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vc", `{"token":"abc"}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", response.Code)
	}
	body := decodeBody(t, response)
	if body["kind"] != "sidecar" {
		t.Fatalf("expected sidecar panic body, got %#v", body)
	}
	errors, _ := body["errors"].([]any)
	if len(errors) != 1 || !strings.Contains(errors[0].(string), "sidecar panic") {
		t.Fatalf("expected panic error, got %#v", body)
	}
}

// sendRequest drives one route through the in-memory HTTP handler under test.
func sendRequest(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// decodeBody decodes one JSON response body into a plain map for test
// assertions.
func decodeBody(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}
