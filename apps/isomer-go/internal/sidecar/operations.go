package sidecar

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type operationMetadata struct {
	State       string `json:"state"`
	SubmittedAt string `json:"submittedAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type operationError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type operationDocument struct {
	Name     string              `json:"name"`
	Done     bool                `json:"done"`
	Metadata operationMetadata   `json:"metadata"`
	Response *verificationResult `json:"response,omitempty"`
	Error    *operationError     `json:"error,omitempty"`
}

type operationMonitor struct {
	mu      sync.RWMutex
	records map[string]operationDocument
}

func newOperationMonitor() *operationMonitor {
	return &operationMonitor{records: map[string]operationDocument{}}
}

func (m *operationMonitor) submit(operationType string, task func(context.Context, string) *verificationResult) operationDocument {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	document := operationDocument{
		Name: fmt.Sprintf("%s.%s", operationType, randomOperationID()),
		Done: false,
		Metadata: operationMetadata{
			State:       "pending",
			SubmittedAt: now,
			UpdatedAt:   now,
		},
	}

	m.mu.Lock()
	m.records[document.Name] = document
	m.mu.Unlock()

	go m.run(document.Name, task)
	return document
}

func (m *operationMonitor) list(operationType string) []operationDocument {
	m.mu.RLock()
	defer m.mu.RUnlock()

	operations := make([]operationDocument, 0, len(m.records))
	for _, document := range m.records {
		if operationType != "" && !strings.HasPrefix(document.Name, operationType+".") {
			continue
		}
		operations = append(operations, document)
	}
	return operations
}

func (m *operationMonitor) get(name string) (operationDocument, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	document, ok := m.records[name]
	return document, ok
}

func (m *operationMonitor) run(name string, task func(context.Context, string) *verificationResult) {
	m.update(name, func(document operationDocument) operationDocument {
		document.Metadata.State = "running"
		document.Metadata.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return document
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			m.fail(name, &operationError{
				Code:    httpStatusInternalServerError,
				Message: fmt.Sprintf("sidecar panic: %v", recovered),
			})
		}
	}()

	m.complete(name, task(ctx, name))
}

func (m *operationMonitor) complete(name string, response *verificationResult) {
	m.update(name, func(document operationDocument) operationDocument {
		document.Done = true
		document.Metadata.State = "completed"
		document.Metadata.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		document.Response = response
		return document
	})
}

func (m *operationMonitor) fail(name string, err *operationError) {
	m.update(name, func(document operationDocument) operationDocument {
		document.Done = true
		document.Metadata.State = "failed"
		document.Metadata.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		document.Error = err
		return document
	})
}

func (m *operationMonitor) update(name string, update func(operationDocument) operationDocument) {
	m.mu.Lock()
	defer m.mu.Unlock()

	document, ok := m.records[name]
	if !ok {
		return
	}
	m.records[name] = update(document)
}

func randomOperationID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

const httpStatusInternalServerError = 500
