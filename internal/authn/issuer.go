package authn

import "context"

// Issuer handles authentication and trust-entry validation for a specific
// identity provider. Each supported issuer type has its own implementation.
type Issuer interface {
	// URL returns the canonical issuer URL (must match the iss claim).
	URL() string

	// Authenticate validates a token from this issuer and returns a Principal.
	// Role booleans are always false for non-primary issuers.
	Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error)

	// ValidateTrustEntry validates that sub is a well-formed identity for
	// this issuer type. Returns a user-facing error if invalid.
	// Called at RegisterSubject and ModifyTrust time.
	ValidateTrustEntry(sub string) error
}
