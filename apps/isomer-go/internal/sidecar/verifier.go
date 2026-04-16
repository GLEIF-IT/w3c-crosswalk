package sidecar

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/models"
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
	"github.com/trustbloc/vc-go/verifiable"
)

type verifier struct {
	resolver *didWebsResolver
	di       *dataintegrity.Verifier
}

func newVerifier(config Config) (*verifier, error) {
	resolver := newDIDWebsResolver(config.ResolverURL)
	loader := newLocalDocumentLoader(config.ResourceRoot)
	di, err := dataintegrity.NewVerifier(
		&dataintegrity.Options{DIDResolver: resolver},
		eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{LDDocumentLoader: loader}),
	)
	if err != nil {
		return nil, err
	}
	return &verifier{resolver: resolver, di: di}, nil
}

func (v *verifier) verifyVC(token string) *verificationResult {
	result := &verificationResult{
		Kind:     "vc+jwt",
		Errors:   []string{},
		Warnings: []string{},
		Checks: map[string]any{
			"jwtEnvelopeValid":        false,
			"signatureValid":          false,
			"dataIntegrityProofValid": false,
			"statusActive":            false,
			"vcGoParsed":              false,
		},
	}
	parts, err := decodeJWT(token)
	if err != nil {
		return result.fail(err)
	}
	vc := asMap(parts.Payload["vc"])
	if vc == nil {
		return result.fail(fmt.Errorf("missing vc claim"))
	}
	result.Payload = vc
	if err = validateVCClaims(parts.Payload, vc); err != nil {
		return result.fail(err)
	}
	result.Checks["jwtEnvelopeValid"] = true

	if _, err = verifiable.ParseCredential([]byte(token), verifiable.WithCredDisableValidation(), verifiable.WithDisabledProofCheck()); err != nil {
		return result.fail(fmt.Errorf("vc-go parse credential: %w", err))
	}
	result.Checks["vcGoParsed"] = true

	kid := asString(parts.Header["kid"])
	jwk, err := v.resolver.publicJWK(kid)
	if err != nil {
		return result.fail(err)
	}
	if err = verifyJWTSignature(parts, jwk); err != nil {
		return result.fail(err)
	}
	result.Checks["signatureValid"] = true

	vcBytes, err := json.Marshal(vc)
	if err != nil {
		return result.fail(err)
	}
	if err = v.di.VerifyProof(vcBytes, &models.ProofOptions{
		Purpose:   "assertionMethod",
		ProofType: models.DataIntegrityProof,
	}); err != nil {
		return result.fail(fmt.Errorf("Data Integrity proof verification failed: %w", err))
	}
	result.Checks["dataIntegrityProofValid"] = true

	status, err := fetchStatus(statusURL(vc))
	if err != nil {
		return result.fail(err)
	}
	if !statusRevoked(status) {
		result.Checks["statusActive"] = true
	} else {
		return result.fail(fmt.Errorf("credential %v is revoked", status["credSaid"]))
	}
	result.OK = true
	return result
}

func (v *verifier) verifyVP(token, audience, nonce string) *verificationResult {
	result := &verificationResult{
		Kind:     "vp+jwt",
		Errors:   []string{},
		Warnings: []string{},
		Checks: map[string]any{
			"jwtEnvelopeValid":            false,
			"signatureValid":              false,
			"vcGoParsed":                  false,
			"embeddedCredentialsVerified": 0,
		},
		Nested: []*verificationResult{},
	}
	parts, err := decodeJWT(token)
	if err != nil {
		return result.fail(err)
	}
	vp := asMap(parts.Payload["vp"])
	if vp == nil {
		return result.fail(fmt.Errorf("missing vp claim"))
	}
	result.Payload = vp
	if err = validateVPClaims(parts.Payload, vp, audience, nonce); err != nil {
		return result.fail(err)
	}
	result.Checks["jwtEnvelopeValid"] = true

	if _, err = verifiable.ParsePresentation(
		[]byte(token),
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithDisabledJSONLDChecks(),
	); err != nil {
		return result.fail(fmt.Errorf("vc-go parse presentation: %w", err))
	}
	result.Checks["vcGoParsed"] = true

	kid := asString(parts.Header["kid"])
	jwk, err := v.resolver.publicJWK(kid)
	if err != nil {
		return result.fail(err)
	}
	if err = verifyJWTSignature(parts, jwk); err != nil {
		return result.fail(err)
	}
	result.Checks["signatureValid"] = true

	credentials, ok := vp["verifiableCredential"].([]any)
	if !ok {
		return result.fail(fmt.Errorf("vp.verifiableCredential must be a list"))
	}
	for _, credential := range credentials {
		token, ok := credential.(string)
		if !ok {
			result.Errors = append(result.Errors, "only nested VC-JWT strings are supported")
			continue
		}
		nested := v.verifyVC(token)
		result.Nested = append(result.Nested, nested)
		if !nested.OK {
			for _, nestedErr := range nested.Errors {
				result.Errors = append(result.Errors, "nested credential: "+nestedErr)
			}
		}
	}
	result.Checks["embeddedCredentialsVerified"] = len(result.Nested)
	result.OK = len(result.Errors) == 0
	return result
}

func (r *verificationResult) fail(err error) *verificationResult {
	r.Errors = append(r.Errors, err.Error())
	r.OK = false
	return r
}

func validateVCClaims(jwtPayload, vc map[string]any) error {
	if issuer := asString(vc["issuer"]); issuer != "" && asString(jwtPayload["iss"]) != issuer {
		return fmt.Errorf("JWT iss does not match vc.issuer")
	}
	if id := asString(vc["id"]); id != "" && asString(jwtPayload["jti"]) != id {
		return fmt.Errorf("JWT jti does not match vc.id")
	}
	if subject := asMap(vc["credentialSubject"]); subject != nil {
		if id := asString(subject["id"]); id != "" && asString(jwtPayload["sub"]) != id {
			return fmt.Errorf("JWT sub does not match credentialSubject.id")
		}
	}
	if _, ok := jwtPayload["iat"].(float64); !ok {
		return fmt.Errorf("VC-JWT requires numeric iat")
	}
	if _, ok := jwtPayload["nbf"].(float64); !ok {
		return fmt.Errorf("VC-JWT requires numeric nbf")
	}
	return nil
}

func validateVPClaims(jwtPayload, vp map[string]any, audience, nonce string) error {
	if holder := asString(vp["holder"]); holder != "" && asString(jwtPayload["iss"]) != holder {
		return fmt.Errorf("JWT iss does not match vp.holder")
	}
	if audience != "" && asString(jwtPayload["aud"]) != audience {
		return fmt.Errorf("JWT aud does not match expected audience")
	}
	if nonce != "" && asString(jwtPayload["nonce"]) != nonce {
		return fmt.Errorf("JWT nonce does not match expected nonce")
	}
	if _, ok := jwtPayload["iat"].(float64); !ok {
		return fmt.Errorf("VP-JWT requires numeric iat")
	}
	return nil
}

func statusURL(vc map[string]any) string {
	if status := asMap(vc["credentialStatus"]); status != nil {
		return asString(status["id"])
	}
	return ""
}

func fetchStatus(url string) (map[string]any, error) {
	if url == "" {
		return nil, nil
	}
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch credential status: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("credential status returned HTTP %d", response.StatusCode)
	}
	var status map[string]any
	if err = json.Unmarshal(body, &status); err != nil {
		return nil, err
	}
	return status, nil
}

func statusRevoked(status map[string]any) bool {
	if status == nil {
		return false
	}
	revoked, _ := status["revoked"].(bool)
	return revoked
}
