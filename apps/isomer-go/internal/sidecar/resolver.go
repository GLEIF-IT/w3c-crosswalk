package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/trustbloc/did-go/doc/did"
	vdrapi "github.com/trustbloc/did-go/vdr/api"
)

// didDocumentContexts is the minimum DID/JWS context set needed for the local
// trustbloc DID parser to accept normalized did:webs documents.
var didDocumentContexts = []any{
	"https://www.w3.org/ns/did/v1",
	"https://w3id.org/security/suites/jws-2020/v1",
}

// didWebsResolver adapts the HTTP did-webs-resolver service into the DID
// resolution and JWK lookup seams used by the Go sidecar.
type didWebsResolver struct {
	baseURL string
	client  *http.Client
	mu      sync.RWMutex
	cache   map[string]*did.DocResolution
}

// newDIDWebsResolver builds the default did:webs resolver client with a small
// in-memory per-DID cache.
func newDIDWebsResolver(baseURL string) *didWebsResolver {
	return &didWebsResolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 10 * time.Second},
		cache:   map[string]*did.DocResolution{},
	}
}

// Resolve satisfies trustbloc's DID resolver interface.
//
// The interface does not accept a context, so the public method delegates to
// the context-aware internal resolver with a background context.
func (r *didWebsResolver) Resolve(id string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	return r.resolve(context.Background(), id)
}

// resolve fetches one did:webs document through the HTTP resolver service and
// caches the parsed result by DID, not by fragment.
func (r *didWebsResolver) resolve(ctx context.Context, id string) (*did.DocResolution, error) {
	didID := strings.Split(id, "#")[0]
	if cached := r.cachedResolution(didID); cached != nil {
		return cached, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/"+didID, nil)
	if err != nil {
		return nil, fmt.Errorf("build did:webs request: %w", err)
	}
	response, err := r.client.Do(request)
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
	r.storeResolution(didID, resolution)
	return resolution, nil
}

// publicJWK returns the public JWK view for the verification method referenced
// by one `kid`-style identifier.
func (r *didWebsResolver) publicJWK(ctx context.Context, kid string) (map[string]any, error) {
	// The Go sidecar stays JWK-first on this seam: it extracts JSONWebKey data
	// from the resolved verification method and does not currently synthesize a
	// Multikey/publicKeyMultibase view the way the Python path does.
	resolution, err := r.resolve(ctx, kid)
	if err != nil {
		return nil, err
	}
	for _, method := range resolution.DIDDocument.VerificationMethod {
		if methodMatchesKID(method.ID, kid) {
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

// cachedResolution returns the current cached resolution for one DID.
func (r *didWebsResolver) cachedResolution(didID string) *did.DocResolution {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cache[didID]
}

// storeResolution memoizes one parsed DID document unless another goroutine
// already cached the same DID.
func (r *didWebsResolver) storeResolution(didID string, resolution *did.DocResolution) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.cache[didID]; existing != nil {
		return
	}
	r.cache[didID] = resolution
}

// didDocumentBytes extracts and normalizes the DID document body from one
// resolver response envelope.
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

// normalizeDIDDocument patches resolver output into the subset of DID document
// shape the Go verifier stack expects.
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

// normalizeDIDRelationship expands string references into embedded method
// objects because trustbloc consumers are easier to satisfy in that form.
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

// findMethodByReference resolves one string relationship reference against the
// available verification methods.
func findMethodByReference(methods []any, reference string) map[string]any {
	for _, item := range methods {
		method := asMap(item)
		if method == nil {
			continue
		}
		if methodMatchesKID(asString(method["id"]), reference) {
			return method
		}
	}
	return nil
}

// methodMatchesKID matches exact, fragment-only, and document-scoped fragment
// references for one verification method identifier.
func methodMatchesKID(methodID, kid string) bool {
	if methodID == kid {
		return true
	}

	fragment := kid
	if strings.Contains(kid, "#") {
		fragment = strings.SplitN(kid, "#", 2)[1]
	}

	return methodID == "#"+fragment || strings.HasSuffix(methodID, "#"+fragment)
}

// isSupportedEdDSAType reports whether the verification method already uses a
// trustbloc-compatible Ed25519 key type.
func isSupportedEdDSAType(methodType string) bool {
	switch methodType {
	case "ED25519SignatureVerification", "Ed25519VerificationKey2018", "Ed25519VerificationKey2020", "JsonWebKey2020", "Multikey":
		return true
	default:
		return false
	}
}
