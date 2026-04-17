package sidecar

import (
	"fmt"

	"github.com/trustbloc/vc-go/verifiable"
)

// vcGoParser is the narrow vc-go parsing adapter used by the verifier runtime.
type vcGoParser struct{}

// ParseCredential checks that vc-go can parse the credential artifact through
// its VC-JWT path without performing the sidecar's separate proof checks.
func (vcGoParser) ParseCredential(token string) error {
	if _, err := verifiable.ParseCredential(
		[]byte(token),
		verifiable.WithCredDisableValidation(),
		verifiable.WithDisabledProofCheck(),
	); err != nil {
		return fmt.Errorf("vc-go parse credential: %w", err)
	}
	return nil
}

// ParsePresentation checks that vc-go can parse the presentation artifact
// through its current VP-JWT path.
func (vcGoParser) ParsePresentation(token string) error {
	// VP JSON-LD stays disabled until the local vc-go stack can accept the
	// Isomer VP shape through its full JSON-LD path without regressing the
	// acceptance harness.
	if _, err := verifiable.ParsePresentation(
		[]byte(token),
		verifiable.WithPresDisabledProofCheck(),
		verifiable.WithDisabledJSONLDChecks(),
	); err != nil {
		return fmt.Errorf("vc-go parse presentation: %w", err)
	}
	return nil
}
