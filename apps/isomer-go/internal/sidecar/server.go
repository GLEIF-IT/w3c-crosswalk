package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Server owns the HTTP surface for the Go verifier sidecar.
type Server struct {
	config     Config
	verifier   Verifier
	webhook    presentationWebhook
	operations *operationMonitor
}

// NewServer constructs the production server with the default verifier
// pipeline wired from the runtime config.
func NewServer(config Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	verifier, err := newVerifier(config)
	if err != nil {
		return nil, err
	}
	return newServerWithVerifier(config, verifier), nil
}

// newServerWithVerifier injects a verifier implementation for tests and other
// callers that already own the runtime seams.
func newServerWithVerifier(config Config, verifier Verifier) *Server {
	return newServerWithVerifierAndWebhook(config, verifier, newWebhookDispatcher(config))
}

// newServerWithVerifierAndWebhook injects verifier and webhook seams for tests.
func newServerWithVerifierAndWebhook(config Config, verifier Verifier, webhook presentationWebhook) *Server {
	return &Server{
		config:     config,
		verifier:   verifier,
		webhook:    webhook,
		operations: newOperationMonitor(),
	}
}

// Run starts the HTTP server and blocks until it shuts down or returns an
// unrecoverable listen error.
func (s *Server) Run(ctx context.Context) error {
	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", s.config.Host, s.config.Port),
		Handler:           s.handler(),
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

// handler builds the full route surface wrapped in panic recovery.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /verify/vc", s.verifyVC)
	mux.HandleFunc("POST /verify/vp", s.verifyVP)
	mux.HandleFunc("GET /operations", s.listOperations)
	mux.HandleFunc("GET /operations/{name}", s.getOperation)
	return recoverHandler(mux)
}

// health reports that the sidecar process is ready to receive verification
// requests.
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "isomer-go"})
}

// verifyVC validates one HTTP VC verification request and delegates the actual
// verification work to the injected runtime.
func (s *Server) verifyVC(w http.ResponseWriter, r *http.Request) {
	var request verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "verification request requires token"})
		return
	}
	operation := s.operations.submit("verify-vc", func(ctx context.Context, operationName string) *verificationResult {
		defer func() {
			if recovered := recover(); recovered != nil {
				logVerificationError(s.config, "vc+jwt", operationName, recovered)
				panic(recovered)
			}
		}()
		result := s.verifier.VerifyVC(ctx, request.Token)
		if result.OK {
			if warning := s.webhook.SendCredential(ctx, result); warning != "" {
				result.Warnings = append(result.Warnings, warning)
			}
		}
		logVerificationResult(s.config, "vc+jwt", operationName, result)
		return result
	})
	logVerificationReceived(s.config, "/verify/vc", "vc+jwt", operation.Name, request.Token)
	writeJSON(w, http.StatusAccepted, operation)
}

// verifyVP validates one HTTP VP verification request and delegates the actual
// verification work to the injected runtime.
func (s *Server) verifyVP(w http.ResponseWriter, r *http.Request) {
	var request verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.Token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "verification request requires token"})
		return
	}
	logVerificationReceived(s.config, "/verify/vp", "vp+jwt", "", request.Token)
	defer func() {
		if recovered := recover(); recovered != nil {
			logVerificationError(s.config, "vp+jwt", "", recovered)
			panic(recovered)
		}
	}()
	result := s.verifier.VerifyVP(r.Context(), request.Token, request.Audience, request.Nonce)
	if result.OK {
		if warning := s.webhook.SendPresentation(r.Context(), result); warning != "" {
			result.Warnings = append(result.Warnings, warning)
		}
	}
	logVerificationResult(s.config, "vp+jwt", "", result)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) listOperations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.operations.list(r.URL.Query().Get("type")))
}

func (s *Server) getOperation(w http.ResponseWriter, r *http.Request) {
	operation, ok := s.operations.get(r.PathValue("name"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "operation not found"})
		return
	}
	writeJSON(w, http.StatusOK, operation)
}

// writeJSON serializes one response body with the sidecar's JSON content type.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// newVerificationResult allocates one empty result object with the expected
// sidecar response fields already initialized.
func newVerificationResult(kind string, checks map[string]any) *verificationResult {
	return &verificationResult{
		Kind:     kind,
		Errors:   []string{},
		Warnings: []string{},
		Checks:   checks,
	}
}

// fail appends one terminal error and marks the result unsuccessful.
func (r *verificationResult) fail(err error) *verificationResult {
	r.Errors = append(r.Errors, err.Error())
	r.OK = false
	return r
}

// recoverHandler converts unexpected panics into the normal JSON error shape so
// callers do not receive a broken HTTP response.
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
