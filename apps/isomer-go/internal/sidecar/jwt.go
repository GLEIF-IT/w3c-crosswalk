package sidecar

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// jwtParts stores the structurally decoded pieces of one compact JWT.
type jwtParts struct {
	Header       map[string]any
	Payload      map[string]any
	SigningInput []byte
	Signature    []byte
}

// decodeJWT parses one compact JWT into its decoded header, payload, signing
// input, and detached signature bytes.
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

// verifyJWTSignature checks an EdDSA compact JWT signature against one resolved
// Ed25519 JWK.
func verifyJWTSignature(parts *jwtParts, jwk map[string]any) error {
	if parts.Header["alg"] != "EdDSA" {
		return fmt.Errorf("unsupported alg: %v", parts.Header["alg"])
	}
	if !isEd25519JWK(jwk) {
		return errors.New("Ed25519 JWK is missing x")
	}
	x := jwk["x"].(string)
	key, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return fmt.Errorf("decode Ed25519 JWK x: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(key), parts.SigningInput, parts.Signature) {
		return errors.New("JWT signature verification failed")
	}
	return nil
}

// asMap narrows one generic decoded JSON value to a plain object.
func asMap(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return nil
}

// asString returns the string form of a decoded JSON value when available.
func asString(value any) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

// isEd25519JWK checks whether the sidecar has enough JWK material to perform
// local Ed25519 signature verification.
func isEd25519JWK(jwk map[string]any) bool {
	x := asString(jwk["x"])
	return x != ""
}
