package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cedar-policy/cedar-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrincipalFromJWT(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		sub      string
		expected string
	}{
		{
			name:     "basic principal",
			issuer:   "https://auth.example.com",
			sub:      "user123",
			expected: `Publisher::"https://auth.example.com::user123"`,
		},
		{
			name:     "issuer with path",
			issuer:   "https://auth.example.com/realms/main",
			sub:      "service-account-id",
			expected: `Publisher::"https://auth.example.com/realms/main::service-account-id"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := PrincipalFromJWT(tt.issuer, tt.sub)
			assert.Equal(t, cedar.EntityType("Publisher"), principal.Type)
			assert.Equal(t, cedar.String(tt.issuer+"::"+tt.sub), principal.ID)
		})
	}
}

func TestActionForRoute(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantAction cedar.EntityUID
		wantOK     bool
	}{
		{
			name:       "POST /api/ingest maps to publish:artifact",
			method:     "POST",
			path:       "/api/ingest",
			wantAction: ActionPublishArtifact,
			wantOK:     true,
		},
		{
			name:       "POST /admin/subjects maps to admin:register-subject",
			method:     "POST",
			path:       "/admin/subjects",
			wantAction: ActionRegisterSubject,
			wantOK:     true,
		},
		{
			name:       "GET /api/evidence maps to read:evidence",
			method:     "GET",
			path:       "/api/evidence",
			wantAction: ActionReadEvidence,
			wantOK:     true,
		},
		{
			name:   "unmapped route returns false",
			method: "GET",
			path:   "/api/unknown",
			wantOK: false,
		},
		{
			name:   "wrong method returns false",
			method: "GET",
			path:   "/api/ingest",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, ok := ActionForRoute(tt.method, tt.path)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantAction, action)
			}
		})
	}
}

func TestSubjectResource(t *testing.T) {
	subject := SubjectResource("proj-123")
	assert.Equal(t, cedar.EntityType("Subject"), subject.Type)
	assert.Equal(t, cedar.String("proj-123"), subject.ID)
}

func TestLoadEmbeddedPolicies(t *testing.T) {
	ps, err := LoadEmbeddedPolicies()
	require.NoError(t, err)
	require.NotNil(t, ps)
}

func TestMiddleware(t *testing.T) {
	ps, err := LoadEmbeddedPolicies()
	require.NoError(t, err)

	tests := []struct {
		name           string
		method         string
		path           string
		issuer         string
		sub            string
		subjectID      string
		trustLookup    TrustLookupFunc
		wantStatusCode int
	}{
		{
			name:           "denies unmapped route",
			method:         "GET",
			path:           "/api/unknown",
			issuer:         "https://auth.example.com",
			sub:            "user123",
			subjectID:      "proj-1",
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return true, nil },
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:      "permits trusted publisher for ingest",
			method:    "POST",
			path:      "/api/ingest",
			issuer:    "https://auth.example.com",
			sub:       "user123",
			subjectID: "proj-1",
			trustLookup: func(ctx context.Context, subjectID, issuer, sub string) (bool, error) {
				return true, nil
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:      "denies untrusted publisher",
			method:    "POST",
			path:      "/api/ingest",
			issuer:    "https://auth.example.com",
			sub:       "user123",
			subjectID: "proj-1",
			trustLookup: func(ctx context.Context, subjectID, issuer, sub string) (bool, error) {
				return false, nil
			},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:      "trust lookup failure returns 403",
			method:    "POST",
			path:      "/api/ingest",
			issuer:    "https://auth.example.com",
			sub:       "user123",
			subjectID: "proj-1",
			trustLookup: func(ctx context.Context, subjectID, issuer, sub string) (bool, error) {
				return false, errors.New("trust store unavailable")
			},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:           "missing subject ID returns 403",
			method:         "POST",
			path:           "/api/ingest",
			issuer:         "https://auth.example.com",
			sub:            "user123",
			subjectID:      "", // Empty subject ID
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return true, nil },
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:           "missing publisher identity returns 401",
			method:         "POST",
			path:           "/api/ingest",
			issuer:         "", // Empty issuer
			sub:            "", // Empty sub
			subjectID:      "proj-1",
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return true, nil },
			wantStatusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := Middleware(ps, tt.trustLookup)
			wrapped := middleware(handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			ctx := req.Context()
			ctx = SetPublisherContext(ctx, tt.issuer, tt.sub)
			ctx = SetSubjectIDContext(ctx, tt.subjectID)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatusCode, rec.Code)
		})
	}
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	// Test publisher context
	ctx = SetPublisherContext(ctx, "https://auth.example.com", "user123")
	issuer, sub := GetPublisher(ctx)
	assert.Equal(t, "https://auth.example.com", issuer)
	assert.Equal(t, "user123", sub)

	// Test subject ID context
	ctx = SetSubjectIDContext(ctx, "proj-1")
	subjectID := GetSubjectID(ctx)
	assert.Equal(t, "proj-1", subjectID)

	// Test admin context
	ctx = SetAdminContext(ctx, true)
	// Admin is retrieved via ctx.Value in middleware, tested there

	// Test service context
	ctx = SetServiceContext(ctx, true)
	isService := GetService(ctx)
	assert.Equal(t, true, isService)

	// Test missing values
	emptyCtx := context.Background()
	issuer, sub = GetPublisher(emptyCtx)
	assert.Equal(t, "", issuer)
	assert.Equal(t, "", sub)

	subjectID = GetSubjectID(emptyCtx)
	assert.Equal(t, "", subjectID)

	isService = GetService(emptyCtx)
	assert.Equal(t, false, isService)
}
