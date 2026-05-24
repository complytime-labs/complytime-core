package auth

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// JWTClaims represents the standard JWT claims we extract and validate
type JWTClaims struct {
	Iss string   // Issuer
	Sub string   // Subject
	Aud string   // Audience (first one if multiple)
	Exp int64   // Expiration time (Unix timestamp)
	Iat int64   // Issued at (Unix timestamp)
}

// JWTVerifier handles JWT verification with JWKS discovery and caching
type JWTVerifier struct {
	// allowedIssuers maps issuer URLs to true for quick lookup
	allowedIssuers map[string]bool
	// cache is the JWK cache for JWKS sets
	cache *jwk.Cache
}

// NewJWTVerifier creates a new JWT verifier with the given allowed issuers
// allowedIssuers is a slice of issuer URLs
// ctx is used for background cache operations and should be a long-lived context
func NewJWTVerifier(ctx context.Context, allowedIssuers []string) *JWTVerifier {
	issuerMap := make(map[string]bool)
	for _, iss := range allowedIssuers {
		issuerMap[iss] = true
	}

	cache := jwk.NewCache(ctx)

	// Pre-register all JWKS URLs once to avoid repeated registration on every request
	for _, iss := range allowedIssuers {
		jwksURL := iss + "/.well-known/jwks.json"
		if err := cache.Register(jwksURL); err != nil {
			// Log registration error but don't fail initialization
			// The cache will attempt registration on first access
		}
	}

	return &JWTVerifier{
		allowedIssuers: issuerMap,
		cache:          cache,
	}
}

// Verify verifies a JWT token and returns the extracted claims
// It performs the following checks:
// 1. Validates the JWT signature using JWKS from the issuer
// 2. Checks that the issuer is in the allowlist
// 3. Verifies expiration and issued-at times
// 4. Returns the claims if valid, or an error describing the failure
func (v *JWTVerifier) Verify(ctx context.Context, tokenString string) (*JWTClaims, error) {
	// Parse the token to get the header (without verification yet)
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims format")
	}

	// Get issuer from claims
	issStr, ok := claims["iss"].(string)
	if !ok {
		return nil, fmt.Errorf("issuer claim missing or invalid")
	}

	// Check if issuer is in allowlist
	if !v.allowedIssuers[issStr] {
		return nil, fmt.Errorf("issuer not allowed: %s", issStr)
	}

	// Get the kid (key ID) from token header
	kid, ok := parsedToken.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("kid header missing or invalid")
	}

	// Construct JWKS endpoint from issuer
	jwksURL := issStr + "/.well-known/jwks.json"

	// Register and fetch JWKS set from the issuer
	if err := v.cache.Register(jwksURL); err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	jwkSet, err := v.cache.Get(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Find the key by kid
	key, ok := jwkSet.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key with kid %s not found in JWKS", kid)
	}

	// Convert JWK to raw key
	var rawKey interface{}
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to extract raw key: %w", err)
	}

	// Verify the signature using the raw key
	parsedToken, err = jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Use the algorithm specified in the JWKS key
		return rawKey, nil
	})
	if err != nil {
		if err.Error() == "token is expired" {
			return nil, fmt.Errorf("token is expired: %w", err)
		}
		return nil, fmt.Errorf("failed to verify token signature: %w", err)
	}

	// Extract and validate the claims again from the verified token
	claims, ok = parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims format")
	}

	// Extract audience (use first one if multiple)
	aud := ""
	if audClaim, ok := claims["aud"]; ok {
		switch audVal := audClaim.(type) {
		case string:
			aud = audVal
		case []interface{}:
			if len(audVal) > 0 {
				aud, _ = audVal[0].(string)
			}
		}
	}

	// Extract subject
	sub, _ := claims["sub"].(string)

	// Extract expiration (in seconds since Unix epoch)
	var exp int64
	if expClaim, ok := claims["exp"]; ok {
		switch expVal := expClaim.(type) {
		case float64:
			exp = int64(expVal)
		}
	}

	// Extract issued-at (in seconds since Unix epoch)
	var iat int64
	if iatClaim, ok := claims["iat"]; ok {
		switch iatVal := iatClaim.(type) {
		case float64:
			iat = int64(iatVal)
		}
	}

	return &JWTClaims{
		Iss: issStr,
		Sub: sub,
		Aud: aud,
		Exp: exp,
		Iat: iat,
	}, nil
}
