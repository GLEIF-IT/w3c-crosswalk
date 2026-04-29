package sidecar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildPresentationWebhookEventIncludesDecodedPayloads(t *testing.T) {
	result := &verificationResult{
		OK:       true,
		Kind:     "vp+jwt",
		Errors:   []string{},
		Warnings: []string{},
		Payload: map[string]any{
			"id":                   "urn:example:vp",
			"holder":               "did:webs:holder",
			"verifiableCredential": []any{"raw-vc-jwt"},
		},
		Checks: map[string]any{"signatureValid": true},
		Nested: []*verificationResult{{
			OK:       true,
			Kind:     "vc+jwt",
			Errors:   []string{},
			Warnings: []string{},
			Payload: map[string]any{
				"id":                "urn:example:vc",
				"issuer":            "did:webs:issuer",
				"type":              []any{"VerifiableCredential", "VRDCredential"},
				"credentialSubject": map[string]any{"id": "did:webs:holder"},
			},
			Checks: map[string]any{"signatureValid": true},
		}},
	}

	event := buildPresentationWebhookEvent(Config{VerifierID: "go-test"}, result)
	rendered, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	presentation := event["presentation"].(map[string]any)
	types := presentation["credentialTypes"].([]string)
	if len(types) != 2 || types[1] != "VRDCredential" {
		t.Fatalf("unexpected credential types: %#v", types)
	}
	verifier := event["verifier"].(map[string]any)
	if verifier["language"] != "Go" {
		t.Fatalf("unexpected verifier metadata: %#v", verifier)
	}
	if strings.Contains(string(rendered), "raw-vc-jwt") {
		t.Fatalf("event contains raw token: %s", rendered)
	}
}

func TestBuildCredentialWebhookEventIncludesDecodedPayload(t *testing.T) {
	result := &verificationResult{
		OK:       true,
		Kind:     "vc+jwt",
		Errors:   []string{},
		Warnings: []string{},
		Payload: map[string]any{
			"id":                "urn:example:vc",
			"issuer":            "did:webs:issuer",
			"type":              []any{"VerifiableCredential", "VRDCredential"},
			"credentialSubject": map[string]any{"id": "did:webs:holder"},
		},
		Checks: map[string]any{"signatureValid": true},
	}

	event := buildCredentialWebhookEvent(Config{VerifierID: "go-test"}, result)
	presentation := event["presentation"].(map[string]any)
	types := presentation["credentialTypes"].([]string)
	if len(types) != 2 || types[1] != "VRDCredential" {
		t.Fatalf("unexpected credential types: %#v", types)
	}
	if presentation["kind"] != "vc+jwt" || presentation["holder"] != "did:webs:holder" {
		t.Fatalf("unexpected presentation metadata: %#v", presentation)
	}
	verification := event["verification"].(map[string]any)
	nested := verification["nested"].([]map[string]any)
	if len(nested) != 0 {
		t.Fatalf("expected no nested verification summaries, got %#v", nested)
	}
}

func TestWebhookDispatcherLogsRequestBodyAndResponse(t *testing.T) {
	result := &verificationResult{
		OK:       true,
		Kind:     "vc+jwt",
		Errors:   []string{},
		Warnings: []string{},
		Payload: map[string]any{
			"id":                "urn:example:vc",
			"issuer":            "did:webs:issuer",
			"type":              []any{"VerifiableCredential", "VRDCredential"},
			"credentialSubject": map[string]any{"id": "did:webs:holder"},
		},
		Checks: map[string]any{"signatureValid": true},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	dispatcher := newWebhookDispatcher(Config{VerifierID: "go-test", WebhookURL: server.URL})
	logs := captureLogs(t, func() {
		warning := dispatcher.SendCredential(context.Background(), result)
		if warning != "" {
			t.Fatalf("unexpected warning: %s", warning)
		}
	})

	request := findLog(t, logs, "webhook.request", map[string]any{"artifactKind": "vc+jwt"})
	if request["webhookUrl"] != server.URL {
		t.Fatalf("unexpected webhook request log: %#v", request)
	}
	body := request["body"].(map[string]any)
	presentation := body["presentation"].(map[string]any)
	credentials := presentation["credentials"].([]any)
	credential := credentials[0].(map[string]any)
	if credential["id"] != "urn:example:vc" {
		t.Fatalf("unexpected webhook body log: %#v", body)
	}
	response := findLog(t, logs, "webhook.response", map[string]any{"eventId": request["eventId"]})
	if response["httpStatus"] != float64(http.StatusAccepted) || response["ok"] != true {
		t.Fatalf("unexpected webhook response log: %#v", response)
	}
}

func TestWebhookDispatcherLogsSkippedAndErrorOutcomes(t *testing.T) {
	result := &verificationResult{
		OK:       true,
		Kind:     "vc+jwt",
		Errors:   []string{},
		Warnings: []string{},
		Payload:  map[string]any{"id": "urn:example:vc"},
		Checks:   map[string]any{"signatureValid": true},
	}

	skippedLogs := captureLogs(t, func() {
		warning := newWebhookDispatcher(Config{VerifierID: "go-test"}).SendCredential(context.Background(), result)
		if warning != "" {
			t.Fatalf("unexpected warning: %s", warning)
		}
	})
	skipped := findLog(t, skippedLogs, "webhook.skipped", map[string]any{"artifactKind": "vc+jwt"})
	if skipped["reason"] != "no_webhook_url" {
		t.Fatalf("unexpected skipped log: %#v", skipped)
	}

	errorLogs := captureLogs(t, func() {
		warning := newWebhookDispatcher(Config{VerifierID: "go-test", WebhookURL: "://bad-url"}).SendCredential(context.Background(), result)
		if !strings.Contains(warning, "dashboard webhook failed") {
			t.Fatalf("expected webhook warning, got %q", warning)
		}
	})
	errorLog := findLog(t, errorLogs, "webhook.error", map[string]any{"artifactKind": "vc+jwt"})
	if !strings.Contains(errorLog["error"].(string), "missing protocol scheme") {
		t.Fatalf("unexpected error log: %#v", errorLog)
	}
}
