package sidecar

import "context"

// Config captures the runtime inputs needed to launch the HTTP sidecar.
type Config struct {
	Host          string
	Port          int
	ResolverURL   string
	ResourceRoot  string
	WebhookURL    string
	VerifierID    string
	VerifierLabel string
}

// Validate rejects incomplete runtime configuration before the server boots.
func (c Config) Validate() error {
	if c.ResolverURL == "" {
		return errMissingResolverURL
	}
	return nil
}

// verifyRequest is the JSON body accepted by the HTTP verify endpoints.
type verifyRequest struct {
	Token    string `json:"token"`
	Audience string `json:"audience,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

// verificationResult is the shared top-level response shape returned for VC and
// VP verification requests.
type verificationResult struct {
	OK       bool                  `json:"ok"`
	Kind     string                `json:"kind"`
	Errors   []string              `json:"errors"`
	Warnings []string              `json:"warnings"`
	Payload  map[string]any        `json:"payload,omitempty"`
	Checks   map[string]any        `json:"checks"`
	Nested   []*verificationResult `json:"nested,omitempty"`
}

// Verifier is the narrow runtime seam used by the HTTP handlers.
//
// The interface exists primarily as a test seam so route tests can validate the
// HTTP contract without constructing the full crypto, DID, and status pipeline.
type Verifier interface {
	VerifyVC(ctx context.Context, token string) *verificationResult
	VerifyVP(ctx context.Context, token, audience, nonce string) *verificationResult
}
