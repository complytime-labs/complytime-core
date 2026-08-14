package publisher

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeStaticJWKIssuer(t *testing.T) (*StaticJWKIssuer, jwk.Key) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-key-1"))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))

	raw, err := json.Marshal(set)
	require.NoError(t, err)
	msg := json.RawMessage(raw)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "test-key-1"))

	issuer := NewStaticJWKIssuer("https://scanner.example.com", &msg, time.Now().Add(24*time.Hour), nil)
	return issuer, privKey
}

func mintStaticToken(t *testing.T, privKey jwk.Key, issuer, audience string, lifetime time.Duration, jti string) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer(issuer).
		Subject(issuer).
		Audience([]string{audience}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(lifetime))
	if jti != "" {
		b = b.JwtID(jti)
	}
	tok, err := b.Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA(), privKey))
	require.NoError(t, err)
	return string(signed)
}

func TestStaticJWKAuthenticatesValidToken(t *testing.T) {
	sji, privKey := makeStaticJWKIssuer(t)
	tokenStr := mintStaticToken(t, privKey, sji.url, "complytime", 5*time.Minute, "unique-jti-1")

	p, err := sji.Authenticate(context.Background(), tokenStr, "complytime")
	require.NoError(t, err)
	assert.Equal(t, sji.url, p.Issuer)
	assert.Equal(t, sji.url, p.Sub)
}

func TestStaticJWKRejectsLongLifetime(t *testing.T) {
	sji, privKey := makeStaticJWKIssuer(t)
	tokenStr := mintStaticToken(t, privKey, sji.url, "complytime", 11*time.Minute, "unique-jti-2")

	_, err := sji.Authenticate(context.Background(), tokenStr, "complytime")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lifetime exceeds 10-minute maximum")
}

func TestStaticJWKRejectsExpiredJWK(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "expired-key-1"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	msg := json.RawMessage(raw)

	// JWK expired in the past
	sji := NewStaticJWKIssuer("https://scanner.example.com", &msg, time.Now().Add(-1*time.Hour), nil)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "expired-key-1"))
	tokenStr := mintStaticToken(t, privKey, sji.url, "complytime", 5*time.Minute, "unique-jti-3")

	_, err = sji.Authenticate(context.Background(), tokenStr, "complytime")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestStaticJWKRejectsMissingJTI(t *testing.T) {
	sji, privKey := makeStaticJWKIssuer(t)
	tokenStr := mintStaticToken(t, privKey, sji.url, "complytime", 5*time.Minute, "")

	_, err := sji.Authenticate(context.Background(), tokenStr, "complytime")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing jti claim")
}

func TestStaticJWKRejectsReplay(t *testing.T) {
	store := &inMemJTIStore{seen: map[string]struct{}{}}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pubKey, err := jwk.Import(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA()))
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "replay-key-1"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	msg := json.RawMessage(raw)

	sji := NewStaticJWKIssuer("https://scanner.example.com", &msg, time.Now().Add(24*time.Hour), store)

	privKey, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "replay-key-1"))
	tokenStr := mintStaticToken(t, privKey, sji.url, "complytime", 5*time.Minute, "replay-jti")

	ctx := context.Background()
	_, err = sji.Authenticate(ctx, tokenStr, "complytime")
	require.NoError(t, err)

	_, err = sji.Authenticate(ctx, tokenStr, "complytime")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jti replay")
}

func TestStaticJWKValidateTrustEntry(t *testing.T) {
	sji := &StaticJWKIssuer{url: "https://scanner.example.com"}

	require.NoError(t, sji.ValidateTrustEntry("https://scanner.example.com"))
	require.Error(t, sji.ValidateTrustEntry("https://other.example.com"))
	require.Error(t, sji.ValidateTrustEntry(""))
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
