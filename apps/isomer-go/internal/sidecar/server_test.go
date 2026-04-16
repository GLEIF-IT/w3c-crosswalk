package sidecar

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHealthEndpoint(t *testing.T) {
	server := &http.Server{Addr: "127.0.0.1:0", Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "isomer-go"})
	})}
	listener, err := (&netListenConfig{}).Listen(context.Background(), "tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())

	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	if err = json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["ok"] != true {
		t.Fatalf("expected ok health response, got %#v", body)
	}
}

type netListenConfig struct{}

func (netListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	var config net.ListenConfig
	return config.Listen(ctx, network, address)
}
