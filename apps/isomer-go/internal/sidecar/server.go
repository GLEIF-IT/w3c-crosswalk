package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Server struct {
	config   Config
	verifier *verifier
}

func NewServer(config Config) (*Server, error) {
	verifier, err := newVerifier(config)
	if err != nil {
		return nil, err
	}
	return &Server{config: config, verifier: verifier}, nil
}

func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /verify/vc", s.verifyVC)
	mux.HandleFunc("POST /verify/vp", s.verifyVP)

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.config.Host, s.config.Port),
		Handler:           recoverHandler(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		log.Printf("isomer-go listening on http://%s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errs <- err
		}
		close(errs)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errs:
		return err
	}
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "isomer-go"})
}

func (s *Server) verifyVC(w http.ResponseWriter, r *http.Request) {
	var request verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "verification request requires token"})
		return
	}
	writeJSON(w, http.StatusOK, s.verifier.verifyVC(request.Token))
}

func (s *Server) verifyVP(w http.ResponseWriter, r *http.Request) {
	var request verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "verification request requires token"})
		return
	}
	writeJSON(w, http.StatusOK, s.verifier.verifyVP(request.Token, request.Audience, request.Nonce))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func recoverHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				writeJSON(w, http.StatusInternalServerError, verificationResult{
					OK:       false,
					Kind:     "sidecar",
					Errors:   []string{fmt.Sprintf("sidecar panic: %v", recovered)},
					Warnings: []string{},
					Checks:   map[string]any{},
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
