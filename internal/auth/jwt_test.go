package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

// TestJWTVerifierValidToken tests verification of a valid JWT token
func TestJWTVerifierValidToken(t *testing.T) {
	// Generate EC256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Convert to JWK for JWKS endpoint
	jwkKey, err := jwk.FromRaw(privateKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "test-key-id"))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.ES256))

	// Extract x, y coordinates for JWKS response
	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	// Create JWKS response
	jwksResponse := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   x,
				"y":   y,
				"kid": "test-key-id",
				"alg": "ES256",
				"use": "sig",
			},
		},
	}

	// Create mock JWKS endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	// Use test server as issuer
	issuer := server.URL
	subject := "test-user"
	audience := "test-service"
	now := time.Now()

	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-id"
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	// Create JWT verifier with allowed issuer
	ctx := context.Background()
	verifier := NewJWTVerifier(ctx, []string{issuer}, "")

	// Verify token
	jwtClaims, err := verifier.Verify(ctx, tokenString)
	require.NoError(t, err)
	require.NotNil(t, jwtClaims)
	require.Equal(t, issuer, jwtClaims.Iss)
	require.Equal(t, subject, jwtClaims.Sub)
	require.Equal(t, audience, jwtClaims.Aud)
}

// TestJWTVerifierExpiredToken tests that expired tokens are rejected
func TestJWTVerifierExpiredToken(t *testing.T) {
	// Generate EC256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Convert to JWK for JWKS endpoint
	jwkKey, err := jwk.FromRaw(privateKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "test-key-id"))

	// Extract x, y coordinates for JWKS response
	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	// Create JWKS response
	jwksResponse := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   x,
				"y":   y,
				"kid": "test-key-id",
				"alg": "ES256",
				"use": "sig",
			},
		},
	}

	// Create mock JWKS endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	// Create JWT claims with expiration in the past
	issuer := server.URL
	subject := "test-user"
	audience := "test-service"
	now := time.Now()

	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(-1 * time.Hour)), // Expired
		IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-id"
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	// Create JWT verifier with allowed issuer
	ctx := context.Background()
	verifier := NewJWTVerifier(ctx, []string{issuer}, "")

	// Verify token should fail
	jwtClaims, err := verifier.Verify(ctx, tokenString)
	require.Error(t, err)
	require.Nil(t, jwtClaims)
	require.Contains(t, err.Error(), "expired")
}

// TestJWTVerifierUnknownIssuer tests that tokens from unknown issuers are rejected
func TestJWTVerifierUnknownIssuer(t *testing.T) {
	// Generate EC256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Convert to JWK for JWKS endpoint
	jwkKey, err := jwk.FromRaw(privateKey.PublicKey)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "test-key-id"))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.ES256))

	// Extract x, y coordinates for JWKS response
	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	// Create JWKS response
	jwksResponse := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "EC",
				"crv": "P-256",
				"x":   x,
				"y":   y,
				"kid": "test-key-id",
				"alg": "ES256",
				"use": "sig",
			},
		},
	}

	// Create mock JWKS endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	// Create JWT claims with unknown issuer
	unknownIssuer := "https://unknown.com"
	subject := "test-user"
	audience := "test-service"
	now := time.Now()

	claims := jwt.RegisteredClaims{
		Issuer:    unknownIssuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(now),
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-id"
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	// Create JWT verifier with only one allowed issuer (not the unknown one)
	allowedIssuer := "https://allowed.com"
	ctx := context.Background()
	verifier := NewJWTVerifier(ctx, []string{allowedIssuer}, "")

	// Verify token should fail
	jwtClaims, err := verifier.Verify(ctx, tokenString)
	require.Error(t, err)
	require.Nil(t, jwtClaims)
	require.Contains(t, err.Error(), "not allowed")
}

func TestJWTVerifierAlgorithmConfusion(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	jwksResponse := map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "EC", "crv": "P-256",
			"x": x, "y": y,
			"kid": "test-key-id", "alg": "ES256", "use": "sig",
		}},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	issuer := server.URL
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "test-user",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	// Sign with HS256 using the raw public key bytes as HMAC secret (algorithm confusion attack)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = "test-key-id"
	tokenString, err := token.SignedString(privateKey.X.Bytes())
	require.NoError(t, err)

	ctx := context.Background()
	verifier := NewJWTVerifier(ctx, []string{issuer}, "")

	jwtClaims, err := verifier.Verify(ctx, tokenString)
	require.Error(t, err)
	require.Nil(t, jwtClaims)
	require.Contains(t, err.Error(), "signing method")
}

func TestJWTVerifierAudienceMismatch(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	jwksResponse := map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "EC", "crv": "P-256",
			"x": x, "y": y,
			"kid": "test-key-id", "alg": "ES256", "use": "sig",
		}},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	issuer := server.URL
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "test-user",
		Audience:  jwt.ClaimStrings{"wrong-audience"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-id"
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	verifier := NewJWTVerifier(ctx, []string{issuer}, "expected-audience")

	jwtClaims, err := verifier.Verify(ctx, tokenString)
	require.Error(t, err)
	require.Nil(t, jwtClaims)
	require.Contains(t, err.Error(), "audience mismatch")
}

func TestJWTVerifierAudienceNotConfigured(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	x := base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes())

	jwksResponse := map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "EC", "crv": "P-256",
			"x": x, "y": y,
			"kid": "test-key-id", "alg": "ES256", "use": "sig",
		}},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksResponse)
	}))
	defer server.Close()

	issuer := server.URL
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "test-user",
		Audience:  jwt.ClaimStrings{"any-audience"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = "test-key-id"
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	verifier := NewJWTVerifier(ctx, []string{issuer}, "")

	jwtClaims, err := verifier.Verify(ctx, tokenString)
	require.NoError(t, err)
	require.NotNil(t, jwtClaims)
	require.Equal(t, "any-audience", jwtClaims.Aud)
}
