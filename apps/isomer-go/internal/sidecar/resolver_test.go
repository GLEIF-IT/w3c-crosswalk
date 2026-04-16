package sidecar

import (
	"encoding/json"
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
				}
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
