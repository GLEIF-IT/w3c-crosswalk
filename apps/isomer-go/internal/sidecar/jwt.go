package sidecar

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type jwtParts struct {
	Header       map[string]any
	Payload      map[string]any
	SigningInput []byte
	Signature    []byte
}

func decodeJWT(token string) (*jwtParts, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("expected compact JWT with three parts")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWT signature: %w", err)
	}

	var header map[string]any
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}
	var payload map[string]any
	if err = json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("parse JWT payload: %w", err)
	}

	return &jwtParts{
		Header:       header,
		Payload:      payload,
		SigningInput: []byte(parts[0] + "." + parts[1]),
		Signature:    signature,
	}, nil
}

func verifyJWTSignature(parts *jwtParts, jwk map[string]any) error {
	if parts.Header["alg"] != "EdDSA" {
		return fmt.Errorf("unsupported alg: %v", parts.Header["alg"])
	}
	x, ok := jwk["x"].(string)
	if !ok || x == "" {
		return errors.New("Ed25519 JWK is missing x")
	}
	key, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return fmt.Errorf("decode Ed25519 JWK x: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(key), parts.SigningInput, parts.Signature) {
		return errors.New("JWT signature verification failed")
	}
	return nil
}

func asMap(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

func asString(value any) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}
