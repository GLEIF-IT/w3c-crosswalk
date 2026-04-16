package sidecar

type Config struct {
	Host         string
	Port         int
	ResolverURL  string
	ResourceRoot string
}

type verifyRequest struct {
	Token    string `json:"token"`
	Audience string `json:"audience,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

type verificationResult struct {
	OK       bool                  `json:"ok"`
	Kind     string                `json:"kind"`
	Errors   []string              `json:"errors"`
	Warnings []string              `json:"warnings"`
	Payload  map[string]any        `json:"payload,omitempty"`
	Checks   map[string]any        `json:"checks"`
	Nested   []*verificationResult `json:"nested,omitempty"`
}
