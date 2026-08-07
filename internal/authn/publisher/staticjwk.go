package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// StaticJWKIssuer validates tokens from a scanner issuer that authenticates
// using a pre-registered public key (no OIDC discovery).
// Instances are ephemeral — created per authentication attempt from a stored JWK.
type StaticJWKIssuer struct {
	url      string
	jwk      *json.RawMessage
	notAfter time.Time
	jtiStore JTIStore
}

// NewStaticJWKIssuer creates a per-request issuer from a retrieved JWK record.
func NewStaticJWKIssuer(issuerURL string, storedJWK *json.RawMessage, notAfter time.Time, jtiStore JTIStore) *StaticJWKIssuer {
	return &StaticJWKIssuer{
		url:      issuerURL,
		jwk:      storedJWK,
		notAfter: notAfter,
		jtiStore: jtiStore,
	}
}

func (s *StaticJWKIssuer) URL() string { return s.url }

func (s *StaticJWKIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	if time.Now().UTC().After(s.notAfter) {
		return nil, fmt.Errorf("JWK for issuer %s has expired (not_after: %s)", s.url, s.notAfter)
	}

	set, err := jwk.ParseString(string(*s.jwk))
	if err != nil {
		return nil, fmt.Errorf("parsing static JWK for issuer %s: %w", s.url, err)
	}

	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(s.url),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("static JWK validation failed for %s: %w", s.url, err)
	}

	if iss, ok := tok.Issuer(); !ok || iss != s.url {
		return nil, fmt.Errorf("static JWK issuer mismatch: got %q expected %q", iss, s.url)
	}

	// Enforce iat-based total lifetime ≤ 10 minutes.
	// Checking remaining time is insufficient: a 60-minute token presented in its final
	// 10 minutes would pass that check, leaving a 60-minute replay window.
	iat, ok := tok.IssuedAt()
	if !ok {
		return nil, fmt.Errorf("static JWK token missing iat claim")
	}
	expiry, ok := tok.Expiration()
	if !ok {
		return nil, fmt.Errorf("static JWK token missing exp claim")
	}
	if expiry.Sub(iat) > 10*time.Minute {
		return nil, fmt.Errorf("static JWK token lifetime exceeds 10-minute maximum (iat-to-exp: %s)", expiry.Sub(iat))
	}

	jti, ok := tok.JwtID()
	if !ok || jti == "" {
		return nil, fmt.Errorf("static JWK token missing jti claim")
	}
	if s.jtiStore != nil {
		remaining := time.Until(expiry)
		if remaining <= 0 {
			remaining = time.Second
		}
		if err := s.jtiStore.ClaimJTI(ctx, jti, remaining); err != nil {
			return nil, fmt.Errorf("jti replay check failed: %w", err)
		}
	}

	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("static JWK token missing sub claim")
	}

	return &Principal{Issuer: s.url, Sub: sub}, nil
}

// ValidateTrustEntry enforces the scanner identity convention: issuer == sub.
// The synthetic issuerID doubles as the sub — this links the JWK to the trust entry.
func (s *StaticJWKIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	if sub != s.url {
		return fmt.Errorf("static JWK issuer trust entries must have issuer == sub (got issuer=%q sub=%q); the scanner identity is the issuer ID", s.url, sub)
	}
	return nil
}
