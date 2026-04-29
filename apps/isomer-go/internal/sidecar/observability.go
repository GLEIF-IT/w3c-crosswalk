package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
)

const tokenHashHexLength = 16

func tokenObservability(token string) map[string]any {
	digest := sha256.Sum256([]byte(token))
	return map[string]any{
		"token":       token,
		"tokenLength": len(token),
		"tokenSha256": hex.EncodeToString(digest[:])[:tokenHashHexLength],
	}
}

func logVerifierEvent(event string, fields map[string]any) {
	body := map[string]any{"event": event}
	for key, value := range fields {
		body[key] = value
	}
	rendered, err := json.Marshal(body)
	if err != nil {
		log.SetFlags(0)
		log.Print(`{"event":"verifier.log_error","error":"failed to marshal verifier log event"}`)
		return
	}
	log.SetFlags(0)
	log.Print(string(rendered))
}

func logVerificationReceived(config Config, route, artifactKind, operationName, token string) {
	fields := map[string]any{
		"verifier":     effectiveVerifierID(config),
		"route":        route,
		"artifactKind": artifactKind,
	}
	if operationName != "" {
		fields["operationName"] = operationName
	}
	for key, value := range tokenObservability(token) {
		fields[key] = value
	}
	logVerifierEvent("verification.received", fields)
}

func logVerificationResult(config Config, artifactKind, operationName string, result *verificationResult) {
	fields := map[string]any{
		"verifier":     effectiveVerifierID(config),
		"artifactKind": artifactKind,
		"ok":           result.OK,
		"kind":         result.Kind,
		"checks":       result.Checks,
		"warnings":     result.Warnings,
		"errors":       result.Errors,
	}
	if operationName != "" {
		fields["operationName"] = operationName
	}
	logVerifierEvent("verification.result", fields)
}

func logVerificationError(config Config, artifactKind, operationName string, recovered any) {
	message := "sidecar panic"
	if recovered != nil {
		message = "sidecar panic: " + stringify(recovered)
	}
	fields := map[string]any{
		"verifier":     effectiveVerifierID(config),
		"artifactKind": artifactKind,
		"ok":           false,
		"kind":         artifactKind,
		"checks":       map[string]any{},
		"warnings":     []string{},
		"errors":       []string{message},
		"error":        map[string]any{"code": httpStatusInternalServerError, "message": message},
	}
	if operationName != "" {
		fields["operationName"] = operationName
	}
	logVerifierEvent("verification.result", fields)
}

func effectiveVerifierID(config Config) string {
	if config.VerifierID != "" {
		return config.VerifierID
	}
	return "isomer-go"
}

func stringify(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}
