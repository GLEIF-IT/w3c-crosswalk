package sidecar

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/piprate/json-gold/ld"
)

// localDocumentLoader pins the small set of JSON-LD contexts used by Isomer's
// VC projection so verification never depends on remote context fetches.
type localDocumentLoader struct {
	root  string
	mu    sync.RWMutex
	cache map[string]any
}

// newLocalDocumentLoader builds one pinned local JSON-LD loader rooted at the
// Python Isomer resource tree.
func newLocalDocumentLoader(root string) *localDocumentLoader {
	return &localDocumentLoader{root: root, cache: map[string]any{}}
}

// LoadDocument returns one pinned JSON-LD context from disk and caches it for
// later reuse.
func (l *localDocumentLoader) LoadDocument(url string) (*ld.RemoteDocument, error) {
	filename, ok := map[string]string{
		"https://www.w3.org/2018/credentials/v1":          "vc-v1.jsonld",
		"https://w3id.org/security/data-integrity/v2":     "security-data-integrity-v2.jsonld",
		"https://www.gleif.org/contexts/isomer-v1.jsonld": "isomer-v1.jsonld",
	}[url]
	if !ok {
		return nil, fmt.Errorf("no local JSON-LD context registered for %s", url)
	}

	l.mu.RLock()
	document, ok := l.cache[url]
	l.mu.RUnlock()
	if !ok {
		path := filepath.Join(l.root, "src", "vc_isomer", "resources", "contexts", filename)
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		var loaded any
		if err = json.Unmarshal(body, &loaded); err != nil {
			return nil, err
		}

		l.mu.Lock()
		if cached, exists := l.cache[url]; exists {
			document = cached
		} else {
			l.cache[url] = loaded
			document = loaded
		}
		l.mu.Unlock()
	}
	return &ld.RemoteDocument{
		DocumentURL: url,
		Document:    document,
	}, nil
}
