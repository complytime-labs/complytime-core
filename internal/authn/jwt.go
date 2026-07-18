package authn

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type JWTAuthenticator struct {
	cache    *jwk.Cache
	jwksURLs []string
	audience string
}

func NewJWTAuthenticator(ctx context.Context, issuers []string, audience string) (*JWTAuthenticator, error) {
	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache: %w", err)
	}

	var urls []string
	for _, issuer := range issuers {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			continue
		}
		jwksURL := issuer + "/.well-known/jwks.json"
		if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(5*time.Minute)); err != nil {
			return nil, fmt.Errorf("registering JWKS %s: %w", jwksURL, err)
		}
		if _, err := cache.Refresh(ctx, jwksURL); err != nil {
			return nil, fmt.Errorf("fetching JWKS from %s: %w", jwksURL, err)
		}
		urls = append(urls, jwksURL)
	}

	return &JWTAuthenticator{cache: cache, jwksURLs: urls, audience: audience}, nil
}

func (a *JWTAuthenticator) Authenticate(r *http.Request) (*Principal, error) {
	tokenString, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, url := range a.jwksURLs {
		set, err := a.cache.Lookup(r.Context(), url)
		if err != nil {
			lastErr = fmt.Errorf("fetching keyset %s: %w", url, err)
			continue
		}
		tok, err := jwt.Parse([]byte(tokenString),
			jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
			jwt.WithAudience(a.audience),
			jwt.WithAcceptableSkew(30*time.Second),
		)
		if err != nil {
			lastErr = err
			continue
		}
		return principalFromToken(tok)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("authentication failed: %w", lastErr)
	}
	return nil, fmt.Errorf("no JWKS URLs configured")
}

func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	token, found := strings.CutPrefix(auth, "Bearer ")
	if !found || token == "" {
		return "", fmt.Errorf("missing or invalid Authorization header")
	}
	return token, nil
}

func principalFromToken(tok jwt.Token) (*Principal, error) {
	issuer, ok := tok.Issuer()
	if !ok || issuer == "" {
		return nil, fmt.Errorf("missing issuer claim")
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing subject claim")
	}

	p := &Principal{Issuer: issuer, Sub: sub}

	var admin bool
	if err := tok.Get("admin", &admin); err == nil {
		p.Admin = admin
	}

	var service bool
	if err := tok.Get("service", &service); err == nil {
		p.Service = service
	}

	return p, nil
}
