// HTTP contract tests for the isomer-go sidecar routes.
//
// These tests lock the public route behavior: health, bad-body handling,
// required-token failures, request forwarding into the verifier seam, and panic
// recovery.
package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
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

// fakeWebhook records successful webhook attempts.
type fakeWebhook struct {
	presentationCalls int
	credentialCalls   int
}

// SendPresentation satisfies the presentation webhook seam.
func (f *fakeWebhook) SendPresentation(_ context.Context, _ *verificationResult) string {
	f.presentationCalls++
	return ""
}

// SendCredential satisfies the credential webhook seam.
func (f *fakeWebhook) SendCredential(_ context.Context, _ *verificationResult) string {
	f.credentialCalls++
	return ""
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

func TestVerifyVCHandlerReturnsAcceptedOperation(t *testing.T) {
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

	var name string
	logs := captureLogs(t, func() {
		response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vc", `{"token":"abc"}`)
		if response.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", response.Code)
		}

		body := decodeBody(t, response)
		name, _ = body["name"].(string)
		if !regexp.MustCompile(`^verify-vc\.`).MatchString(name) {
			t.Fatalf("expected verify-vc operation name, got %#v", body)
		}
		if body["done"] != false {
			t.Fatalf("expected pending operation, got %#v", body)
		}

		listResponse := sendRequest(t, server.handler(), http.MethodGet, "/operations", "")
		if listResponse.Code != http.StatusOK {
			t.Fatalf("expected operations list 200, got %d", listResponse.Code)
		}
		listBody := decodeArrayBody(t, listResponse)
		if len(listBody) != 1 || listBody[0]["name"] != name {
			t.Fatalf("expected operation in list, got %#v", listBody)
		}

		filteredResponse := sendRequest(t, server.handler(), http.MethodGet, "/operations?type=verify-vc", "")
		if filteredResponse.Code != http.StatusOK {
			t.Fatalf("expected filtered operations list 200, got %d", filteredResponse.Code)
		}
		filteredBody := decodeArrayBody(t, filteredResponse)
		if len(filteredBody) != 1 || filteredBody[0]["name"] != name {
			t.Fatalf("expected filtered operation in list, got %#v", filteredBody)
		}

		completed := waitForOperation(t, server.handler(), name)
		if verifier.lastVCToken != "abc" {
			t.Fatalf("expected token to reach verifier, got %q", verifier.lastVCToken)
		}
		metadata, _ := completed["metadata"].(map[string]any)
		if metadata["state"] != "completed" {
			t.Fatalf("expected completed operation, got %#v", completed)
		}
		responseBody, _ := completed["response"].(map[string]any)
		if responseBody["kind"] != "vc+jwt" {
			t.Fatalf("expected VC result in operation response, got %#v", completed)
		}
	})
	received := findLog(t, logs, "verification.received", map[string]any{"operationName": name})
	if received["token"] != "abc" || received["tokenLength"] != float64(3) || received["tokenSha256"] != "ba7816bf8f01cfea" {
		t.Fatalf("unexpected received log: %#v", received)
	}
	resultLog := findLog(t, logs, "verification.result", map[string]any{"operationName": name})
	if resultLog["ok"] != true || resultLog["kind"] != "vc+jwt" {
		t.Fatalf("unexpected result log: %#v", resultLog)
	}
	skipped := findLog(t, logs, "webhook.skipped", map[string]any{"artifactKind": "vc+jwt"})
	if skipped["reason"] != "no_webhook_url" {
		t.Fatalf("unexpected webhook skipped log: %#v", skipped)
	}
}

func TestVerifyVCHandlerStoresFailedOperation(t *testing.T) {
	server := newServerWithVerifier(Config{}, &fakeVerifier{vcPanic: true})

	var name string
	logs := captureLogs(t, func() {
		response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vc", `{"token":"abc"}`)
		if response.Code != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", response.Code)
		}
		body := decodeBody(t, response)
		name, _ = body["name"].(string)

		failed := waitForOperation(t, server.handler(), name)
		metadata, _ := failed["metadata"].(map[string]any)
		if metadata["state"] != "failed" {
			t.Fatalf("expected failed operation, got %#v", failed)
		}
		errorBody, _ := failed["error"].(map[string]any)
		if errorBody["code"] != float64(http.StatusInternalServerError) || !strings.Contains(errorBody["message"].(string), "sidecar panic") {
			t.Fatalf("expected panic operation error, got %#v", failed)
		}
	})
	resultLog := findLog(t, logs, "verification.result", map[string]any{"operationName": name})
	if resultLog["ok"] != false || !strings.Contains(resultLog["errors"].([]any)[0].(string), "sidecar panic") {
		t.Fatalf("unexpected failure log: %#v", resultLog)
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

	logs := captureLogs(t, func() {
		response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vp", `{"token":"abc","audience":"aud","nonce":"n-1"}`)
		if response.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", response.Code)
		}
		if verifier.lastVPToken != "abc" || verifier.lastVPAud != "aud" || verifier.lastVPNonce != "n-1" {
			t.Fatalf("unexpected verifier inputs: token=%q audience=%q nonce=%q", verifier.lastVPToken, verifier.lastVPAud, verifier.lastVPNonce)
		}
	})
	received := findLog(t, logs, "verification.received", map[string]any{"artifactKind": "vp+jwt"})
	if received["route"] != "/verify/vp" || received["token"] != "abc" {
		t.Fatalf("unexpected received log: %#v", received)
	}
	resultLog := findLog(t, logs, "verification.result", map[string]any{"artifactKind": "vp+jwt"})
	if resultLog["ok"] != true || resultLog["kind"] != "vp+jwt" {
		t.Fatalf("unexpected result log: %#v", resultLog)
	}
}

func TestVerifyVPHandlerSendsWebhookAfterSuccess(t *testing.T) {
	verifier := &fakeVerifier{
		vpResult: &verificationResult{
			OK:       true,
			Kind:     "vp+jwt",
			Errors:   []string{},
			Warnings: []string{},
			Checks:   map[string]any{"jwtEnvelopeValid": true},
		},
	}
	webhook := &fakeWebhook{}
	server := newServerWithVerifierAndWebhook(Config{WebhookURL: "http://dashboard.test/webhooks/presentations"}, verifier, webhook)

	response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vp", `{"token":"abc"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}
	if webhook.presentationCalls != 1 {
		t.Fatalf("expected one presentation webhook call, got %d", webhook.presentationCalls)
	}
}

func TestVerifyVCHandlerSendsWebhookAfterSuccess(t *testing.T) {
	verifier := &fakeVerifier{
		vcResult: &verificationResult{
			OK:       true,
			Kind:     "vc+jwt",
			Errors:   []string{},
			Warnings: []string{},
			Checks:   map[string]any{"jwtEnvelopeValid": true},
		},
	}
	webhook := &fakeWebhook{}
	server := newServerWithVerifierAndWebhook(Config{WebhookURL: "http://dashboard.test/webhooks/presentations"}, verifier, webhook)

	response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vc", `{"token":"abc"}`)
	if response.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", response.Code)
	}
	body := decodeBody(t, response)
	name, _ := body["name"].(string)
	completed := waitForOperation(t, server.handler(), name)
	metadata, _ := completed["metadata"].(map[string]any)
	if metadata["state"] != "completed" {
		t.Fatalf("expected completed operation, got %#v", completed)
	}
	if webhook.credentialCalls != 1 {
		t.Fatalf("expected one credential webhook call, got %d", webhook.credentialCalls)
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

func TestRecoverHandlerReturnsJSONOnVPVerifierPanic(t *testing.T) {
	server := newServerWithVerifier(Config{}, &fakeVerifier{vpPanic: true})

	response := sendRequest(t, server.handler(), http.MethodPost, "/verify/vp", `{"token":"abc"}`)
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

func decodeArrayBody(t *testing.T, response *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var body []map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func waitForOperation(t *testing.T, handler http.Handler, name string) map[string]any {
	t.Helper()
	for attempt := 0; attempt < 40; attempt++ {
		response := sendRequest(t, handler, http.MethodGet, "/operations/"+name, "")
		if response.Code != http.StatusOK {
			t.Fatalf("expected operation lookup 200, got %d", response.Code)
		}
		body := decodeBody(t, response)
		if body["done"] == true {
			return body
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("operation %s did not complete", name)
	return nil
}

func captureLogs(t *testing.T, callback func()) []map[string]any {
	t.Helper()
	var buffer bytes.Buffer
	originalWriter := log.Writer()
	originalFlags := log.Flags()
	log.SetOutput(&buffer)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(originalWriter)
		log.SetFlags(originalFlags)
	}()

	callback()

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	events := []map[string]any{}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		start := strings.Index(line, "{")
		if start < 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(line[start:]), &event); err != nil {
			t.Fatalf("invalid log line %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

func findLog(t *testing.T, logs []map[string]any, event string, fields map[string]any) map[string]any {
	t.Helper()
	for _, item := range logs {
		if item["event"] != event {
			continue
		}
		matched := true
		for key, value := range fields {
			if item[key] != value {
				matched = false
				break
			}
		}
		if matched {
			return item
		}
	}
	t.Fatalf("missing log %q with %#v in %#v", event, fields, logs)
	return nil
}
