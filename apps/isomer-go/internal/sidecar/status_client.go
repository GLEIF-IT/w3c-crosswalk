package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// statusClient fetches the projected W3C credential status documents used by
// the sidecar's revocation check.
type statusClient struct {
	client *http.Client
}

// newStatusClient builds the default HTTP client used for status dereferencing.
func newStatusClient() *statusClient {
	return &statusClient{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Fetch dereferences one projected credential status URL and decodes the JSON
// response body.
func (c *statusClient) Fetch(ctx context.Context, url string) (map[string]any, error) {
	if url == "" {
		return nil, nil
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build credential status request: %w", err)
	}

	response, err := c.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch credential status: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= http.StatusBadRequest {
		return nil, fmt.Errorf("credential status returned HTTP %d", response.StatusCode)
	}

	var status map[string]any
	if err = json.Unmarshal(body, &status); err != nil {
		return nil, err
	}
	return status, nil
}

// statusURL extracts the projected W3C credential status URL from one VC
// payload.
func statusURL(vc map[string]any) string {
	if status := asMap(vc["credentialStatus"]); status != nil {
		return asString(status["id"])
	}
	return ""
}

// statusIsRevoked applies the narrow revocation rule the sidecar cares about.
func statusIsRevoked(status map[string]any) bool {
	if status == nil {
		return false
	}
	revoked, _ := status["revoked"].(bool)
	return revoked
}
