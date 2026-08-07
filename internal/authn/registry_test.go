package authn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/complytime-labs/complytime-core/internal/authn/publisher"
)

// mockIssuer is a test-only Issuer that returns a fixed Principal.
type mockIssuer struct {
	url       string
	principal *Principal
	authErr   error
}

func (m *mockIssuer) URL() string { return m.url }

func (m *mockIssuer) Authenticate(_ context.Context, _, _ string) (*Principal, error) {
	if m.authErr != nil {
		return nil, m.authErr
	}
	return m.principal, nil
}

func (m *mockIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub required")
	}
	return nil
}

// mockPublisherIssuer is a test-only PublisherIssuer that returns a fixed publisher.Principal.
type mockPublisherIssuer struct {
	url       string
	principal *publisher.Principal
	authErr   error
}

func (m *mockPublisherIssuer) URL() string { return m.url }

func (m *mockPublisherIssuer) Authenticate(_ context.Context, _, _ string) (*publisher.Principal, error) {
	if m.authErr != nil {
		return nil, m.authErr
	}
	return m.principal, nil
}

func (m *mockPublisherIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub required")
	}
	return nil
}

// newRegistryTestJWKSServer starts a test JWKS server and returns it with the private key.
func newRegistryTestJWKSServer(t *testing.T) (*httptest.Server, jwk.Key, jwk.Key) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "reg-test-key"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()))

	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(pubKey))

	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwks_uri": srvURL + "/protocol/openid-connect/certs",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "reg-test-key"))

	return srv, pubKey, privKey
}

// mintRegistryToken signs a JWT with standard claims and extra claim map.
func mintRegistryToken(t *testing.T, privKey jwk.Key, issuer, audience string, extra map[string]any) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer(issuer).
		Subject("test-subject").
		Audience([]string{audience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour))
	for k, v := range extra {
		b = b.Claim(k, v)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)
	return string(signed)
}

func makeHTTPRequest(t *testing.T, tokenStr string) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	return req
}

func TestRegistryOIDCIssuerScopeExtraction(t *testing.T) {
	srv, _, privKey := newRegistryTestJWKSServer(t)

	oidc, err := NewOIDCIssuer(context.Background(), OIDCIssuerConfig{
		URL: srv.URL,
	})
	require.NoError(t, err)

	registry := NewIssuerRegistry(oidc, nil, nil, nil, "complytime")

	tokenStr := mintRegistryToken(t, privKey, srv.URL, "complytime", map[string]any{
		"scope": "complytime:admin complytime:audit openid",
	})

	p, err := registry.Authenticate(makeHTTPRequest(t, tokenStr))
	require.NoError(t, err)
	assert.Equal(t, srv.URL, p.Issuer)
	assert.False(t, p.Publisher, "human IdP tokens must never set Publisher=true")
	assert.Contains(t, p.Scopes, "complytime:admin")
	assert.Contains(t, p.Scopes, "complytime:audit")
	assert.NotContains(t, p.Scopes, "openid", "unknown scopes must be filtered")
}

func TestRegistryTrustedPublisherIdentityOnly(t *testing.T) {
	primaryMock := &mockIssuer{
		url:       "https://primary.example.com",
		principal: &Principal{Issuer: "https://primary.example.com", Sub: "user"},
	}
	publisherMock := &mockPublisherIssuer{
		url:       "https://publisher.example.com",
		principal: &publisher.Principal{Issuer: "https://publisher.example.com", Sub: "scanner-bot"},
	}

	registry := NewIssuerRegistry(primaryMock, []publisher.PublisherIssuer{publisherMock}, nil, nil, "complytime")

	// Token from publisher issuer: registry must dispatch to publisherMock
	// We can't easily mint a real token here without a JWKS server, so we test
	// the dispatch via peekIssuer by using a real signed token with the publisher URL.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "pub-key"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "pub-key"))

	tok, err := jwt.NewBuilder().
		Issuer("https://publisher.example.com").
		Subject("scanner-bot").
		Audience([]string{"complytime"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)

	// The mock publisher issuer returns its principal; registry sets Publisher: true
	p, err := registry.Authenticate(makeHTTPRequest(t, string(signed)))
	require.NoError(t, err)
	assert.Equal(t, "https://publisher.example.com", p.Issuer)
	assert.Equal(t, "scanner-bot", p.Sub)
	assert.True(t, p.Publisher)
}

func TestRegistryUnknownIssuerRejected(t *testing.T) {
	primaryMock := &mockIssuer{
		url:       "https://primary.example.com",
		principal: &Principal{Issuer: "https://primary.example.com", Sub: "user"},
	}

	registry := NewIssuerRegistry(primaryMock, nil, nil, nil, "complytime")

	// Token from unknown issuer
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub
	privKey, err := jwk.Import(priv)
	require.NoError(t, err)

	tok, err := jwt.NewBuilder().
		Issuer("https://unknown.example.com").
		Subject("attacker").
		Audience([]string{"complytime"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)

	_, err = registry.Authenticate(makeHTTPRequest(t, string(signed)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a configured trusted publisher")
}

func TestRegistryStaticJWKFromStore(t *testing.T) {
	const scannerIssuer = "https://scanner.example.com"

	primaryMock := &mockIssuer{
		url:       "https://primary.example.com",
		principal: &Principal{Issuer: "https://primary.example.com", Sub: "user"},
	}

	// Build a static JWK for the scanner
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "scanner-key"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	storedJWK := json.RawMessage(raw)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "scanner-key"))

	jwkStore := publisher.JWKLookupFunc(func(_ context.Context, issuerID string) (*publisher.StoredJWK, error) {
		if issuerID == scannerIssuer {
			return &publisher.StoredJWK{JWK: storedJWK, NotAfter: time.Now().Add(24 * time.Hour)}, nil
		}
		return nil, nil
	})

	registry := NewIssuerRegistry(primaryMock, nil, jwkStore, nil, "complytime")

	tok, err := jwt.NewBuilder().
		Issuer(scannerIssuer).
		Subject(scannerIssuer).
		Audience([]string{"complytime"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		JwtID("unique-jti-registry-1").
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)

	p, err := registry.Authenticate(makeHTTPRequest(t, string(signed)))
	require.NoError(t, err)
	assert.Equal(t, scannerIssuer, p.Issuer)
}

func TestRegistryStaticJWKJTIReplay(t *testing.T) {
	const scannerIssuer = "https://scanner.example.com"

	primaryMock := &mockIssuer{
		url:       "https://primary.example.com",
		principal: &Principal{Issuer: "https://primary.example.com", Sub: "user"},
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "scanner-key-replay"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	storedJWK := json.RawMessage(raw)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "scanner-key-replay"))

	jwkStore := publisher.JWKLookupFunc(func(_ context.Context, issuerID string) (*publisher.StoredJWK, error) {
		if issuerID == scannerIssuer {
			return &publisher.StoredJWK{JWK: storedJWK, NotAfter: time.Now().Add(24 * time.Hour)}, nil
		}
		return nil, nil
	})

	jtiStore := &inMemJTIStore{seen: map[string]struct{}{}}
	registry := NewIssuerRegistry(primaryMock, nil, jwkStore, jtiStore, "complytime")

	tok, err := jwt.NewBuilder().
		Issuer(scannerIssuer).
		Subject(scannerIssuer).
		Audience([]string{"complytime"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		JwtID("registry-replay-jti").
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)
	tokenStr := string(signed)

	_, err = registry.Authenticate(makeHTTPRequest(t, tokenStr))
	require.NoError(t, err)

	_, err = registry.Authenticate(makeHTTPRequest(t, tokenStr))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jti replay")
}

func TestRegistryValidateTrustEntry(t *testing.T) {
	primaryMock := &mockIssuer{url: "https://primary.example.com"}
	publisherMock := &mockPublisherIssuer{url: "https://publisher.example.com"}

	registry := NewIssuerRegistry(primaryMock, []publisher.PublisherIssuer{publisherMock}, nil, nil, "complytime")

	require.NoError(t, registry.ValidateTrustEntry("https://primary.example.com", "any-user"))
	require.NoError(t, registry.ValidateTrustEntry("https://publisher.example.com", "some-sub"))
	require.Error(t, registry.ValidateTrustEntry("https://unknown.example.com", "some-sub"))
}

// inMemJTIStore is a test-only in-memory JTI store.
type inMemJTIStore struct {
	seen map[string]struct{}
}

func (s *inMemJTIStore) ClaimJTI(_ context.Context, jti string, _ time.Duration) error {
	if _, exists := s.seen[jti]; exists {
		return fmt.Errorf("jti replay: %q already seen", jti)
	}
	s.seen[jti] = struct{}{}
	return nil
}
