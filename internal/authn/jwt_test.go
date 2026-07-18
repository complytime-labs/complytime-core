package authn_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/authn"
)

func TestJWTAuthenticator_Authenticate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Serve JWKS
	jwks := jwk.NewSet()
	key, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "test-key-1"))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, jwks.AddKey(key))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	auth, err := authn.NewJWTAuthenticator(context.Background(), []string{jwksServer.URL}, "complytime-gateway")
	require.NoError(t, err)

	// Build a valid JWT
	tok, err := jwt.NewBuilder().
		Issuer(jwksServer.URL).
		Subject("test-pub").
		Audience([]string{"complytime-gateway"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("admin", true).
		Build()
	require.NoError(t, err)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "test-key-1"))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(signed))

	principal, err := auth.Authenticate(req)
	require.NoError(t, err)
	assert.Equal(t, jwksServer.URL, principal.Issuer)
	assert.Equal(t, "test-pub", principal.Sub)
	assert.True(t, principal.Admin)
}

func TestJWTAuthenticator_RejectsMissingToken(t *testing.T) {
	auth, err := authn.NewJWTAuthenticator(context.Background(), []string{}, "aud")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	_, err = auth.Authenticate(req)
	require.Error(t, err)
}

func TestJWTAuthenticator_RejectsWrongAudience(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwks := jwk.NewSet()
	key, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "test-key-1"))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, jwks.AddKey(key))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	auth, err := authn.NewJWTAuthenticator(context.Background(), []string{jwksServer.URL}, "complytime-gateway")
	require.NoError(t, err)

	tok, err := jwt.NewBuilder().
		Issuer(jwksServer.URL).
		Subject("test-pub").
		Audience([]string{"wrong-audience"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "test-key-1"))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(signed))

	_, err = auth.Authenticate(req)
	require.Error(t, err)
}

func TestAuthMiddleware(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	jwks := jwk.NewSet()
	key, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, "test-key-1"))
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, jwks.AddKey(key))

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer jwksServer.Close()

	auth, err := authn.NewJWTAuthenticator(context.Background(), []string{jwksServer.URL}, "test-aud")
	require.NoError(t, err)

	tok, err := jwt.NewBuilder().
		Issuer(jwksServer.URL).
		Subject("svc").
		Audience([]string{"test-aud"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("admin", true).
		Build()
	require.NoError(t, err)
	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "test-key-1"))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)

	var captured *authn.Principal
	handler := authn.AuthMiddleware(auth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = authn.PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(signed))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, "svc", captured.Sub)
	assert.True(t, captured.Admin)
}

func TestAuthMiddleware_Rejects_NoToken(t *testing.T) {
	auth, _ := authn.NewJWTAuthenticator(context.Background(), []string{}, "aud")
	handler := authn.AuthMiddleware(auth)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestJWTAuthenticator_RejectsSpoofedIssuer(t *testing.T) {
	// Create two JWKS servers (two issuers)
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubB, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// JWKS for issuer A
	jwksA := jwk.NewSet()
	keyA, err := jwk.Import(pubA)
	require.NoError(t, err)
	require.NoError(t, keyA.Set(jwk.KeyIDKey, "key-a"))
	require.NoError(t, keyA.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, jwksA.AddKey(keyA))

	jwksServerA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksA)
	}))
	defer jwksServerA.Close()

	// JWKS for issuer B
	jwksB := jwk.NewSet()
	keyB, err := jwk.Import(pubB)
	require.NoError(t, err)
	require.NoError(t, keyB.Set(jwk.KeyIDKey, "key-b"))
	require.NoError(t, keyB.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, jwksB.AddKey(keyB))

	jwksServerB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksB)
	}))
	defer jwksServerB.Close()

	// Authenticator configured with both issuers
	auth, err := authn.NewJWTAuthenticator(
		context.Background(),
		[]string{jwksServerA.URL, jwksServerB.URL},
		"complytime-gateway",
	)
	require.NoError(t, err)

	// Build a token signed by issuer A but with iss claim = issuer B
	tok, err := jwt.NewBuilder().
		Issuer(jwksServerB.URL). // Claims to be from B
		Subject("attacker").
		Audience([]string{"complytime-gateway"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)

	privKeyA, err := jwk.Import(privA)
	require.NoError(t, err)
	require.NoError(t, privKeyA.Set(jwk.KeyIDKey, "key-a"))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKeyA))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+string(signed))

	// Should reject because iss claim doesn't match the expected issuer for keyset A
	_, err = auth.Authenticate(req)
	require.Error(t, err, "should reject token with spoofed issuer claim")

	// Verify that a properly signed token with correct issuer still works
	validTok, err := jwt.NewBuilder().
		Issuer(jwksServerA.URL). // Correct issuer
		Subject("valid-user").
		Audience([]string{"complytime-gateway"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)

	validSigned, err := jwt.Sign(validTok, jwt.WithKey(jwa.EdDSA(), privKeyA))
	require.NoError(t, err)

	validReq := httptest.NewRequest("GET", "/", nil)
	validReq.Header.Set("Authorization", "Bearer "+string(validSigned))

	principal, err := auth.Authenticate(validReq)
	require.NoError(t, err, "should accept token with correct issuer")
	assert.Equal(t, jwksServerA.URL, principal.Issuer)
	assert.Equal(t, "valid-user", principal.Sub)
}
