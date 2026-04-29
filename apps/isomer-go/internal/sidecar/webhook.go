package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const presentationVerifiedEvent = "isomer.presentation.verified.v1"

// presentationWebhook sends successful verification events to an observer.
type presentationWebhook interface {
	SendPresentation(ctx context.Context, result *verificationResult) string
	SendCredential(ctx context.Context, result *verificationResult) string
}

// webhookDispatcher owns best-effort webhook delivery for the Go sidecar.
type webhookDispatcher struct {
	config Config
	client *http.Client
}

// newWebhookDispatcher constructs the default dashboard webhook dispatcher.
func newWebhookDispatcher(config Config) presentationWebhook {
	return &webhookDispatcher{
		config: config,
		client: &http.Client{Timeout: 3 * time.Second},
	}
}

// SendPresentation posts one successful VP result and returns a warning on
// delivery failure. Verification truth is not changed by webhook delivery.
func (d *webhookDispatcher) SendPresentation(ctx context.Context, result *verificationResult) string {
	return d.send(ctx, buildPresentationWebhookEvent(d.config, result))
}

// SendCredential posts one successful VC result and returns a warning on
// delivery failure. Verification truth is not changed by webhook delivery.
func (d *webhookDispatcher) SendCredential(ctx context.Context, result *verificationResult) string {
	return d.send(ctx, buildCredentialWebhookEvent(d.config, result))
}

func (d *webhookDispatcher) send(ctx context.Context, event map[string]any) string {
	eventID := stringValue(event["eventId"])
	artifactKind := artifactKindFromWebhookEvent(event)
	if d.config.WebhookURL == "" {
		logVerifierEvent("webhook.skipped", map[string]any{
			"verifier":     effectiveVerifierID(d.config),
			"eventId":      eventID,
			"artifactKind": artifactKind,
			"reason":       "no_webhook_url",
		})
		return ""
	}

	body, err := json.Marshal(event)
	if err != nil {
		logVerifierEvent("webhook.error", map[string]any{
			"verifier":     effectiveVerifierID(d.config),
			"webhookUrl":   d.config.WebhookURL,
			"eventId":      eventID,
			"artifactKind": artifactKind,
			"error":        fmt.Sprintf("marshal webhook body: %v", err),
		})
		return fmt.Sprintf("dashboard webhook failed: %v", err)
	}
	logVerifierEvent("webhook.request", map[string]any{
		"verifier":     effectiveVerifierID(d.config),
		"webhookUrl":   d.config.WebhookURL,
		"eventId":      eventID,
		"artifactKind": artifactKind,
		"body":         event,
	})
	requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, d.config.WebhookURL, bytes.NewReader(body))
	if err != nil {
		logVerifierEvent("webhook.error", map[string]any{
			"verifier":     effectiveVerifierID(d.config),
			"webhookUrl":   d.config.WebhookURL,
			"eventId":      eventID,
			"artifactKind": artifactKind,
			"error":        err.Error(),
		})
		return fmt.Sprintf("dashboard webhook failed: %v", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	response, err := d.client.Do(request)
	if err != nil {
		logVerifierEvent("webhook.error", map[string]any{
			"verifier":     effectiveVerifierID(d.config),
			"webhookUrl":   d.config.WebhookURL,
			"eventId":      eventID,
			"artifactKind": artifactKind,
			"error":        err.Error(),
		})
		return fmt.Sprintf("dashboard webhook failed: %v", err)
	}
	defer response.Body.Close()
	logVerifierEvent("webhook.response", map[string]any{
		"verifier":     effectiveVerifierID(d.config),
		"webhookUrl":   d.config.WebhookURL,
		"eventId":      eventID,
		"artifactKind": artifactKind,
		"httpStatus":   response.StatusCode,
		"ok":           response.StatusCode < 400,
	})
	if response.StatusCode >= 400 {
		return fmt.Sprintf("dashboard webhook returned HTTP %d", response.StatusCode)
	}
	return ""
}

// buildPresentationWebhookEvent creates the dashboard event without raw JWTs.
func buildPresentationWebhookEvent(config Config, result *verificationResult) map[string]any {
	credentials := credentialEntries(result.Nested)
	return map[string]any{
		"type":       presentationVerifiedEvent,
		"eventId":    eventID(),
		"verifiedAt": time.Now().UTC().Format(time.RFC3339),
		"verifier":   goVerifierMetadata(config),
		"presentation": map[string]any{
			"kind":            result.Kind,
			"id":              stringField(result.Payload, "id"),
			"holder":          stringField(result.Payload, "holder"),
			"credentialTypes": credentialTypes(credentials),
			"payload":         presentationPayload(result.Payload, credentials),
			"credentials":     credentials,
		},
		"verification": map[string]any{
			"ok":       result.OK,
			"kind":     result.Kind,
			"checks":   cloneMap(result.Checks),
			"warnings": append([]string{}, result.Warnings...),
			"nested":   nestedVerificationSummaries(result.Nested),
		},
	}
}

// buildCredentialWebhookEvent creates the dashboard event for one verified VC.
func buildCredentialWebhookEvent(config Config, result *verificationResult) map[string]any {
	credentials := credentialEntries([]*verificationResult{result})
	var credential map[string]any
	if len(credentials) > 0 {
		credential = credentials[0]
	} else {
		credential = map[string]any{}
	}
	return map[string]any{
		"type":       presentationVerifiedEvent,
		"eventId":    eventID(),
		"verifiedAt": time.Now().UTC().Format(time.RFC3339),
		"verifier":   goVerifierMetadata(config),
		"presentation": map[string]any{
			"kind":            result.Kind,
			"id":              credential["id"],
			"holder":          credential["subject"],
			"credentialTypes": credentialTypes(credentials),
			"payload":         cloneMap(result.Payload),
			"credentials":     credentials,
		},
		"verification": map[string]any{
			"ok":       result.OK,
			"kind":     result.Kind,
			"checks":   cloneMap(result.Checks),
			"warnings": append([]string{}, result.Warnings...),
			"nested":   []map[string]any{},
		},
	}
}

// goVerifierMetadata returns stable dashboard metadata for the Go verifier.
func goVerifierMetadata(config Config) map[string]any {
	label := config.VerifierLabel
	if label == "" {
		label = "Isomer Go"
	}
	id := config.VerifierID
	if id == "" {
		id = "isomer-go"
	}
	return map[string]any{
		"id":       id,
		"label":    label,
		"type":     "isomer-go",
		"language": "Go",
		"libraries": []map[string]string{
			{"name": "trustbloc/vc-go", "role": "VC/VP parsing and Data Integrity verification"},
			{"name": "trustbloc/did-go", "role": "DID document parsing"},
			{"name": "json-gold", "role": "JSON-LD processing"},
			{"name": "local JOSE checks", "role": "JWT signature verification"},
		},
	}
}

func credentialEntries(nested []*verificationResult) []map[string]any {
	credentials := []map[string]any{}
	for _, item := range nested {
		payload := item.Payload
		subject := asMap(payload["credentialSubject"])
		var subjectID any
		if subject != nil {
			subjectID = subject["id"]
		}
		credentials = append(credentials, map[string]any{
			"kind":    item.Kind,
			"id":      payload["id"],
			"issuer":  payload["issuer"],
			"subject": subjectID,
			"types":   stringList(payload["type"]),
			"payload": cloneMap(payload),
		})
	}
	return credentials
}

func presentationPayload(payload map[string]any, credentials []map[string]any) map[string]any {
	if payload == nil {
		return nil
	}
	cleaned := cloneMap(payload)
	summaries := []map[string]any{}
	for _, credential := range credentials {
		summaries = append(summaries, map[string]any{
			"kind":   credential["kind"],
			"id":     credential["id"],
			"issuer": credential["issuer"],
			"types":  credential["types"],
		})
	}
	cleaned["verifiableCredential"] = summaries
	return cleaned
}

func nestedVerificationSummaries(nested []*verificationResult) []map[string]any {
	summaries := []map[string]any{}
	for _, item := range nested {
		summaries = append(summaries, map[string]any{
			"ok":       item.OK,
			"kind":     item.Kind,
			"checks":   cloneMap(item.Checks),
			"warnings": append([]string{}, item.Warnings...),
			"errors":   append([]string{}, item.Errors...),
		})
	}
	return summaries
}

func credentialTypes(credentials []map[string]any) []string {
	seen := map[string]bool{}
	types := []string{}
	for _, credential := range credentials {
		for _, item := range stringList(credential["types"]) {
			if !seen[item] {
				seen[item] = true
				types = append(types, item)
			}
		}
	}
	return types
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []string:
		return append([]string{}, typed...)
	case []any:
		result := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return []string{}
	}
}

func stringField(payload map[string]any, key string) any {
	if payload == nil {
		return nil
	}
	if value, ok := payload[key].(string); ok {
		return value
	}
	return nil
}

func artifactKindFromWebhookEvent(event map[string]any) any {
	if presentation := asMap(event["presentation"]); presentation != nil {
		if kind := stringValue(presentation["kind"]); kind != "" {
			return kind
		}
	}
	if verification := asMap(event["verification"]); verification != nil {
		if kind := stringValue(verification["kind"]); kind != "" {
			return kind
		}
	}
	return nil
}

func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	body, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	var cloned map[string]any
	if err = json.Unmarshal(body, &cloned); err != nil {
		return map[string]any{}
	}
	return cloned
}

func eventID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}
