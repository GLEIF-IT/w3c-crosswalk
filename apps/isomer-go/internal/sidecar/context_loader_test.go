// Contract tests for the pinned local JSON-LD context loader.
package sidecar

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLocalDocumentLoaderConcurrentAccess(t *testing.T) {
	root := t.TempDir()
	contextPath := filepath.Join(root, "src", "vc_isomer", "resources", "contexts")
	if err := os.MkdirAll(contextPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contextPath, "vc-v1.jsonld"), []byte(`{"@context":"vc"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	loader := newLocalDocumentLoader(root)
	var waitGroup sync.WaitGroup

	for index := 0; index < 16; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			document, err := loader.LoadDocument("https://www.w3.org/2018/credentials/v1")
			if err != nil {
				t.Error(err)
				return
			}
			if document.DocumentURL != "https://www.w3.org/2018/credentials/v1" {
				t.Errorf("unexpected document %#v", document)
			}
		}()
	}

	waitGroup.Wait()
}
