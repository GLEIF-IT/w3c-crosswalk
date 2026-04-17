package sidecar

import "errors"

// validateVCClaims enforces the local VC-JWT claim relationships the sidecar
// expects before deeper cryptographic checks run.
func validateVCClaims(jwtPayload, vc map[string]any) error {
	if err := requireOptionalClaimMatch(
		asString(jwtPayload["iss"]),
		asString(vc["issuer"]),
		"JWT iss does not match vc.issuer",
	); err != nil {
		return err
	}
	if err := requireOptionalClaimMatch(
		asString(jwtPayload["jti"]),
		asString(vc["id"]),
		"JWT jti does not match vc.id",
	); err != nil {
		return err
	}

	if subject := asMap(vc["credentialSubject"]); subject != nil {
		if err := requireOptionalClaimMatch(
			asString(jwtPayload["sub"]),
			asString(subject["id"]),
			"JWT sub does not match credentialSubject.id",
		); err != nil {
			return err
		}
	}

	if err := requireNumericClaim(jwtPayload, "iat", "VC-JWT requires numeric iat"); err != nil {
		return err
	}
	if err := requireNumericClaim(jwtPayload, "nbf", "VC-JWT requires numeric nbf"); err != nil {
		return err
	}
	return nil
}

// validateVPClaims enforces the local VP-JWT claim relationships the sidecar
// expects before nested verification begins.
func validateVPClaims(jwtPayload, vp map[string]any, audience, nonce string) error {
	if err := requireOptionalClaimMatch(
		asString(jwtPayload["iss"]),
		asString(vp["holder"]),
		"JWT iss does not match vp.holder",
	); err != nil {
		return err
	}
	if err := requireOptionalClaimMatch(
		asString(jwtPayload["aud"]),
		audience,
		"JWT aud does not match expected audience",
	); err != nil {
		return err
	}
	if err := requireOptionalClaimMatch(
		asString(jwtPayload["nonce"]),
		nonce,
		"JWT nonce does not match expected nonce",
	); err != nil {
		return err
	}
	return requireNumericClaim(jwtPayload, "iat", "VP-JWT requires numeric iat")
}

// requireOptionalClaimMatch fails only when the expected value is present and
// the actual value does not match it.
func requireOptionalClaimMatch(actual, expected, message string) error {
	if claimMatchesExpected(actual, expected) {
		return nil
	}
	return errors.New(message)
}

// claimMatchesExpected implements the sidecar's "empty expected means optional"
// matching rule for JWT claim checks.
func claimMatchesExpected(actual, expected string) bool {
	return expected == "" || actual == expected
}

// requireNumericClaim enforces that one decoded JWT payload claim was parsed as
// a JSON number.
func requireNumericClaim(payload map[string]any, claim, message string) error {
	if _, ok := payload[claim].(float64); ok {
		return nil
	}
	return errors.New(message)
}
