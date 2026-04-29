// Resolver normalization tests for the did:webs adapter layer.
package sidecar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestDIDDocumentBytesNormalizesKERIKeyMethods(t *testing.T) {
	body := []byte(`{
		"didDocument": {
			"id": "did:webs:example.com:dws:Eabc",
			"verificationMethod": [{
				"id": "#key-1",
				"type": "JsonWebKey",
				"controller": "did:webs:example.com:dws:Eabc",
				"publicKeyJwk": {
					"kty": "OKP",
					"crv": "Ed25519",
					"x": "11qYAYKxCrfVS_3u3lIBX7hLTXruxN4B0qVd2zSYXK0"
				},
				"publicKeyMultibase": "z6Mkv9CtaGfyKqGjca3n8cVaeyy1T1412Kyy4Q2p5gz8yqyq"
			}],
			"assertionMethod": ["#key-1"]
		}
	}`)

	normalized, err := didDocumentBytes(body)
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err = json.Unmarshal(normalized, &document); err != nil {
		t.Fatal(err)
	}

	methods := document["verificationMethod"].([]any)
	method := methods[0].(map[string]any)
	if method["type"] != "JsonWebKey2020" {
		t.Fatalf("expected JsonWebKey2020 method, got %#v", method["type"])
	}
	if _, ok := method["publicKeyMultibase"]; ok {
		t.Fatal("expected publicKeyMultibase to be removed when publicKeyJwk is available")
	}
	if document["@context"] == nil {
		t.Fatal("expected DID context to be added")
	}
	if len(document["assertionMethod"].([]any)) != 1 {
		t.Fatalf("expected assertionMethod to reference the normalized method, got %#v", document["assertionMethod"])
	}
	if len(document["authentication"].([]any)) != 1 {
		t.Fatalf("expected authentication to reference the normalized method, got %#v", document["authentication"])
	}
}

func TestPublicJWKFindsVerificationMethodByFragment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"didDocument": {
				"id": "did:webs:example.com:dws:Eabc",
				"verificationMethod": [{
					"id": "did:webs:example.com:dws:Eabc#key-1",
					"type": "JsonWebKey2020",
					"controller": "did:webs:example.com:dws:Eabc",
					"publicKeyJwk": {
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "11qYAYKxCrfVS_3u3lIBX7hLTXruxN4B0qVd2zSYXK0"
					},
					"publicKeyMultibase": "z6Mkv9CtaGfyKqGjca3n8cVaeyy1T1412Kyy4Q2p5gz8yqyq"
				}]
			}
		}`))
	}))
	defer server.Close()

	resolver := newDIDWebsResolver(server.URL)
	jwk, err := resolver.publicJWK(context.Background(), "did:webs:example.com:dws:Eabc#key-1")
	if err != nil {
		t.Fatal(err)
	}
	if jwk["x"] != "11qYAYKxCrfVS_3u3lIBX7hLTXruxN4B0qVd2zSYXK0" {
		t.Fatalf("unexpected JWK %#v", jwk)
	}
}

func TestDIDWebsResolverConcurrentCacheAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"didDocument": {
				"id": "did:webs:example.com:dws:Eabc",
				"verificationMethod": [{
					"id": "#key-1",
					"type": "JsonWebKey2020",
					"controller": "did:webs:example.com:dws:Eabc",
					"publicKeyJwk": {
						"kty": "OKP",
						"crv": "Ed25519",
						"x": "11qYAYKxCrfVS_3u3lIBX7hLTXruxN4B0qVd2zSYXK0"
					}
				}]
			}
		}`))
	}))
	defer server.Close()

	resolver := newDIDWebsResolver(server.URL)
	var waitGroup sync.WaitGroup
	for index := 0; index < 16; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			jwk, err := resolver.publicJWK(context.Background(), "did:webs:example.com:dws:Eabc#key-1")
			if err != nil {
				t.Error(err)
				return
			}
			if jwk["crv"] != "Ed25519" {
				t.Errorf("unexpected JWK %#v", jwk)
			}
		}()
	}
	waitGroup.Wait()
}
