package sidecar

import "github.com/trustbloc/vc-go/dataintegrity/models"

// ProofOptions aliases the trustbloc proof options type so internal seams can
// depend on a small local name.
type ProofOptions = models.ProofOptions

// wrapProofVerifier adapts the concrete trustbloc verifier to the local proof
// interface used by the verifier runtime.
type wrapProofVerifier struct {
	Verifier interface {
		VerifyProof(doc []byte, opts *models.ProofOptions) error
	}
}

// VerifyProof forwards one proof verification request to the wrapped trustbloc
// verifier.
func (w wrapProofVerifier) VerifyProof(doc []byte, opts *ProofOptions) error {
	return w.Verifier.VerifyProof(doc, opts)
}
