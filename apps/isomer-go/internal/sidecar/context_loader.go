package sidecar

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/piprate/json-gold/ld"
)

type localDocumentLoader struct {
	root  string
	cache map[string]any
}

func newLocalDocumentLoader(root string) *localDocumentLoader {
	return &localDocumentLoader{root: root, cache: map[string]any{}}
}

func (l *localDocumentLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	filename, ok := map[string]string{
		"https://www.w3.org/2018/credentials/v1":          "vc-v1.jsonld",
		"https://w3id.org/security/data-integrity/v2":     "security-data-integrity-v2.jsonld",
		"https://www.gleif.org/contexts/isomer-v1.jsonld": "isomer-v1.jsonld",
	}[url]
	if !ok {
		return nil, fmt.Errorf("no local JSON-LD context registered for %s", url)
	}
	if _, ok = l.cache[url]; !ok {
		path := filepath.Join(l.root, "src", "vc_isomer", "resources", "contexts", filename)
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var document any
		if err = json.Unmarshal(body, &document); err != nil {
			return nil, err
		}
		l.cache[url] = document
	}
	return &ld.RemoteDocument{
		DocumentURL: url,
		Document:    l.cache[url],
	}, nil
}
