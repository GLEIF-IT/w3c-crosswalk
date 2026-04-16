package sidecar

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

var didDocumentContexts = []any{
	"https://www.w3.org/ns/did/v1",
	"https://w3id.org/security/suites/jws-2020/v1",
}

type didWebsResolver struct {
	baseURL string
	client  *http.Client
	cache   map[string]*did.DocResolution
}

func newDIDWebsResolver(baseURL string) *didWebsResolver {
	return &didWebsResolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{},
		cache:   map[string]*did.DocResolution{},
	}
}

func (r *didWebsResolver) Resolve(id string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	didID := strings.Split(id, "#")[0]
	if cached := r.cache[didID]; cached != nil {
		return cached, nil
	}

	response, err := r.client.Get(r.baseURL + "/" + didID)
	if err != nil {
		return nil, fmt.Errorf("resolve did:webs: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("read did:webs response: %w", err)
	}
	if response.StatusCode >= 400 {
		return nil, fmt.Errorf("did:webs resolver returned HTTP %d", response.StatusCode)
	}

	docBytes, err := didDocumentBytes(body)
	if err != nil {
		return nil, err
	}
	doc, err := did.ParseDocument(docBytes)
	if err != nil {
		return nil, fmt.Errorf("parse DID document: %w", err)
	}
	resolution := &did.DocResolution{DIDDocument: doc}
	r.cache[didID] = resolution
	return resolution, nil
}

func (r *didWebsResolver) publicJWK(kid string) (map[string]any, error) {
	// The Go sidecar stays JWK-first on this seam: it extracts JSONWebKey data
	// from the resolved verification method and does not currently synthesize a
	// Multikey/publicKeyMultibase view the way the Python path does.
	resolution, err := r.Resolve(kid)
	if err != nil {
		return nil, err
	}
	fragment := kid
	if strings.Contains(kid, "#") {
		fragment = strings.SplitN(kid, "#", 2)[1]
	}
	for _, method := range resolution.DIDDocument.VerificationMethod {
		if method.ID == kid || method.ID == "#"+fragment || strings.HasSuffix(method.ID, "#"+fragment) {
			bytes, err := json.Marshal(method.JSONWebKey())
			if err != nil {
				return nil, err
			}
			var jwk map[string]any
			if err = json.Unmarshal(bytes, &jwk); err != nil {
				return nil, err
			}
			if len(jwk) == 0 {
				return nil, fmt.Errorf("verification method %s did not expose publicKeyJwk", kid)
			}
			return jwk, nil
		}
	}
	return nil, fmt.Errorf("verification method %s not found in resolved DID document", kid)
}

func didDocumentBytes(body []byte) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parse did:webs response: %w", err)
	}
	docBytes := body
	if rawDoc, ok := envelope["didDocument"]; ok {
		docBytes = rawDoc
	}

	var document map[string]any
	if err := json.Unmarshal(docBytes, &document); err != nil {
		return nil, fmt.Errorf("parse did:webs DID document: %w", err)
	}
	normalizeDIDDocument(document)
	normalized, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("serialize normalized DID document: %w", err)
	}
	return normalized, nil
}

func normalizeDIDDocument(document map[string]any) {
	if _, ok := document["@context"]; !ok {
		document["@context"] = didDocumentContexts
	}
	methods, _ := document["verificationMethod"].([]any)
	for _, item := range methods {
		method := asMap(item)
		if method == nil {
			continue
		}
		// Preserve the existing key material shape. The Go path normalizes method
		// type and verification relationships for trustbloc DID parsing, but does
		// not add synthesized publicKeyMultibase or publicKeyJwk fields here.
		if isSupportedEdDSAType(asString(method["type"])) {
			continue
		}
		if jwk := asMap(method["publicKeyJwk"]); jwk != nil && jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" {
			method["type"] = "JsonWebKey2020"
		}
	}
	normalizeDIDRelationship(document, "assertionMethod", methods)
	normalizeDIDRelationship(document, "authentication", methods)
}

func normalizeDIDRelationship(document map[string]any, relationship string, methods []any) {
	existing, _ := document[relationship].([]any)
	var normalized []any
	for _, item := range existing {
		if reference, ok := item.(string); ok {
			if method := findMethodByReference(methods, reference); method != nil {
				normalized = append(normalized, method)
			}
			continue
		}
		if asMap(item) != nil {
			normalized = append(normalized, item)
		}
	}
	if len(normalized) == 0 {
		normalized = methods
	}
	document[relationship] = normalized
}

func findMethodByReference(methods []any, reference string) map[string]any {
	fragment := strings.TrimPrefix(reference, "#")
	if strings.Contains(reference, "#") {
		fragment = strings.SplitN(reference, "#", 2)[1]
	}
	for _, item := range methods {
		method := asMap(item)
		if method == nil {
			continue
		}
		id := asString(method["id"])
		if id == reference || id == "#"+fragment || strings.HasSuffix(id, "#"+fragment) {
			return method
		}
	}
	return nil
}

func isSupportedEdDSAType(methodType string) bool {
	switch methodType {
	case "ED25519SignatureVerification", "Ed25519VerificationKey2018", "Ed25519VerificationKey2020", "JsonWebKey2020", "Multikey":
		return true
	default:
		return false
	}
}
