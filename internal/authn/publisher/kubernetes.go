package publisher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// kubernetesSubPattern matches Kubernetes service account tokens:
// system:serviceaccount:{namespace}:{name}
var kubernetesSubPattern = regexp.MustCompile(`^system:serviceaccount:[^:]+:[^:]+$`)

// KubernetesIssuer validates tokens from a Kubernetes cluster OIDC endpoint.
// Supports EKS, GKE, AKS, and any conformant cluster — the operator configures
// the cluster-specific issuer URL. JWKS location is resolved via OIDC discovery
// so clusters that serve JWKS at a non-standard path (GKE, AKS) are handled
// correctly.
type KubernetesIssuer struct {
	url     string
	jwksURL string
	cache   *jwk.Cache
}

// NewKubernetesIssuer creates an issuer for a Kubernetes cluster OIDC endpoint.
// issuerURL is the cluster-specific OIDC provider URL. The JWKS URI is resolved
// via OIDC discovery (issuerURL + /.well-known/openid-configuration).
func NewKubernetesIssuer(ctx context.Context, issuerURL string) (*KubernetesIssuer, error) {
	if issuerURL == "" {
		return nil, fmt.Errorf("issuerURL is required for Kubernetes (use the cluster OIDC provider URL)")
	}
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")

	jwksURL, err := discoverJWKSURI(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for Kubernetes issuer %s: %w", issuerURL, err)
	}

	httpClient := httprc.NewClient()
	cache, err := jwk.NewCache(ctx, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS cache for Kubernetes issuer: %w", err)
	}
	if err := cache.Register(ctx, jwksURL, jwk.WithMinInterval(1*time.Minute)); err != nil {
		return nil, fmt.Errorf("registering Kubernetes JWKS %s: %w", jwksURL, err)
	}
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("fetching Kubernetes JWKS from %s: %w", jwksURL, err)
	}

	return &KubernetesIssuer{url: issuerURL, jwksURL: jwksURL, cache: cache}, nil
}

// discoverJWKSURI fetches the OIDC discovery document and returns the jwks_uri.
func discoverJWKSURI(ctx context.Context, issuerURL string) (string, error) {
	discoveryURL := issuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("building discovery request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery endpoint %s returned %d", discoveryURL, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading discovery response: %w", err)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parsing discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document missing jwks_uri")
	}
	return doc.JWKSURI, nil
}

func (k *KubernetesIssuer) URL() string { return k.url }

func (k *KubernetesIssuer) Authenticate(ctx context.Context, tokenString, audience string) (*Principal, error) {
	set, err := k.cache.Lookup(ctx, k.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching Kubernetes JWKS: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenString),
		jwt.WithKeySet(set, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithIssuer(k.url),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("kubernetes token validation failed: %w", err)
	}
	if iss, ok := tok.Issuer(); !ok || iss != k.url {
		return nil, fmt.Errorf("issuer mismatch: got %q expected %q", iss, k.url)
	}
	sub, ok := tok.Subject()
	if !ok || sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	return &Principal{Issuer: k.url, Sub: sub}, nil
}

// ValidateTrustEntry validates that sub is a Kubernetes service account identity:
// system:serviceaccount:{namespace}:{name}
func (k *KubernetesIssuer) ValidateTrustEntry(sub string) error {
	if sub == "" {
		return fmt.Errorf("sub is required")
	}
	if !kubernetesSubPattern.MatchString(sub) {
		return fmt.Errorf("invalid Kubernetes sub %q: must match system:serviceaccount:{namespace}:{name}", sub)
	}
	return nil
}
