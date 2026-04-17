package sidecar

import (
	"context"

	"github.com/trustbloc/vc-go/dataintegrity"
	"github.com/trustbloc/vc-go/dataintegrity/suite/eddsa2022"
)

// keyResolver returns the public JWK material used for JOSE verification.
type keyResolver interface {
	publicJWK(ctx context.Context, kid string) (map[string]any, error)
}

// credentialParser exposes the narrow vc-go parsing steps the sidecar cares
// about for VC-JWTs and VP-JWTs.
type credentialParser interface {
	ParseCredential(token string) error
	ParsePresentation(token string) error
}

// proofVerifier wraps the Data Integrity verification seam used for embedded VC
// proofs.
type proofVerifier interface {
	VerifyProof(doc []byte, opts *ProofOptions) error
}

// statusGetter fetches projected credential status documents from Isomer's W3C
// status endpoint.
type statusGetter interface {
	Fetch(ctx context.Context, url string) (map[string]any, error)
}

// verifier owns the effectful collaborators for the Go verification pipeline.
type verifier struct {
	resolver     keyResolver
	parser       credentialParser
	proofChecker proofVerifier
	statusClient statusGetter
}

// newVerifier constructs the production verification pipeline from config and
// the default resolver, parser, proof, and status dependencies.
func newVerifier(config Config) (*verifier, error) {
	resolver := newDIDWebsResolver(config.ResolverURL)
	loader := newLocalDocumentLoader(config.ResourceRoot)
	di, err := dataintegrity.NewVerifier(
		// trustbloc's Data Integrity verifier resolves proof verification methods
		// through this DID resolver when VerifyProof runs later in the VC flow.
		&dataintegrity.Options{DIDResolver: resolver},
		eddsa2022.NewVerifierInitializer(&eddsa2022.VerifierInitializerOptions{LDDocumentLoader: loader}),
	)
	if err != nil {
		return nil, err
	}

	return &verifier{
		resolver:     resolver,
		parser:       vcGoParser{},
		proofChecker: wrapProofVerifier{Verifier: di},
		statusClient: newStatusClient(),
	}, nil
}
