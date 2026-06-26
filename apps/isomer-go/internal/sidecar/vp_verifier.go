package sidecar

import (
	"context"
	"fmt"
	"strings"
)

// vpChecks records which VP verification stages completed successfully.
type vpChecks struct {
	JWTEnvelopeValid            bool
	SignatureValid              bool
	VCGoParsed                  bool
	EmbeddedSubjectsMatchHolder bool
	EmbeddedCredentialsVerified int
}

// mapValue converts the typed check set into the stable JSON shape exposed by
// the sidecar HTTP API.
func (c vpChecks) mapValue() map[string]any {
	return map[string]any{
		"jwtEnvelopeValid":                      c.JWTEnvelopeValid,
		"signatureValid":                        c.SignatureValid,
		"vcGoParsed":                            c.VCGoParsed,
		"embeddedCredentialSubjectsMatchHolder": c.EmbeddedSubjectsMatchHolder,
		"embeddedCredentialsVerified":           c.EmbeddedCredentialsVerified,
	}
}

// VerifyVP runs the Go sidecar's VP-JWT verification pipeline and recursively
// verifies each nested VC-JWT through the same VC workflow.
func (v *verifier) VerifyVP(ctx context.Context, token, audience, nonce string) *verificationResult {
	checks := vpChecks{}
	result := newVerificationResult("vp+jwt", checks.mapValue())
	result.Nested = []*verificationResult{}

	parts, err := decodeJWT(token)
	if err != nil {
		return result.fail(err)
	}

	vp, err := presentationFromJWT(parts)
	if err != nil {
		return result.fail(err)
	}
	result.Payload = vp

	if err = validateVPClaims(parts.Payload, vp, audience, nonce); err != nil {
		return result.fail(err)
	}
	checks.JWTEnvelopeValid = true
	result.Checks = checks.mapValue()

	// This vc-go parse step is structural only in the current VP flow. It does
	// not resolve did:webs key state because proof checks are disabled here too.
	if err = v.parser.ParsePresentation(token); err != nil {
		return result.fail(err)
	}
	checks.VCGoParsed = true
	result.Checks = checks.mapValue()

	// did:webs resolution for the top-level VP JWT happens here through the JWT
	// `kid` lookup in v.resolver.publicJWK(...).
	if err = v.verifyJWTSignature(ctx, parts); err != nil {
		return result.fail(err)
	}
	checks.SignatureValid = true
	result.Checks = checks.mapValue()

	if err = v.verifyNestedCredentials(ctx, vp, result, &checks); err != nil {
		return result.fail(err)
	}

	result.Checks = checks.mapValue()
	result.OK = len(result.Errors) == 0
	return result
}

// presentationFromJWT requires the `vp` claim and returns it as a JSON object.
func presentationFromJWT(parts *jwtParts) (map[string]any, error) {
	vp := asMap(parts.Payload["vp"])
	if vp == nil {
		return nil, fmt.Errorf("missing vp claim")
	}
	return vp, nil
}

// verifyNestedCredentials enforces the expected VP embedded-credential shape
// and verifies each nested VC-JWT sequentially.
func (v *verifier) verifyNestedCredentials(
	ctx context.Context,
	vp map[string]any,
	result *verificationResult,
	checks *vpChecks,
) error {
	credentials, ok := vp["verifiableCredential"].([]any)
	if !ok {
		return fmt.Errorf("vp.verifiableCredential must be a list")
	}

	holder := asString(vp["holder"])
	if holder == "" {
		return fmt.Errorf("VP holder DID is missing")
	}
	subjectsMatchHolder := true
	for _, credential := range credentials {
		token, ok := credential.(string)
		if !ok {
			result.Errors = append(result.Errors, "only nested VC-JWT strings are supported")
			continue
		}

		// Each nested VC re-enters VerifyVC, so its own JOSE and embedded-proof
		// did:webs resolution happens inside that recursive call.
		nested := v.VerifyVC(ctx, token)
		result.Nested = append(result.Nested, nested)
		if !nested.OK {
			for _, nestedErr := range nested.Errors {
				result.Errors = append(result.Errors, "nested credential: "+nestedErr)
			}
			continue
		}

		checks.EmbeddedCredentialsVerified += 1
		if !embeddedSubjectMatchesHolder(holder, nested) {
			result.Errors = append(result.Errors, "embedded credential subject DID does not match VP holder")
			subjectsMatchHolder = false
		}
	}

	checks.EmbeddedSubjectsMatchHolder = subjectsMatchHolder
	return nil
}

// embeddedSubjectMatchesHolder binds a successful nested VC subject to the
// top-level VP holder DID.
func embeddedSubjectMatchesHolder(holder string, nested *verificationResult) bool {
	payload := nested.Payload
	if payload == nil {
		return false
	}
	subject := asMap(payload["credentialSubject"])
	if subject == nil {
		return false
	}
	subjectID := asString(subject["id"])
	return subjectID != "" && canonicalizeDIDWebs(subjectID) == canonicalizeDIDWebs(holder)
}

// canonicalizeDIDWebs repairs the common local-stack did:webs host:port
// encoding variant before DID comparison.
func canonicalizeDIDWebs(value string) string {
	if !strings.HasPrefix(value, "did:webs:") || strings.Contains(strings.ToLower(value), "%3a") {
		return value
	}

	body, query, hasQuery := strings.Cut(value, "?")
	segments := strings.Split(strings.TrimPrefix(body, "did:webs:"), ":")
	if len(segments) < 3 || !isDecimalPort(segments[1]) {
		return value
	}

	normalized := "did:webs:" + segments[0] + "%3A" + segments[1] + ":" + strings.Join(segments[2:], ":")
	if hasQuery {
		return normalized + "?" + query
	}
	return normalized
}

func isDecimalPort(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
