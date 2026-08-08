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
			name:       "POST /admin/subjects maps to admin:request-registration",
			method:     "POST",
			path:       "/admin/subjects",
			wantAction: ActionRequestRegistration,
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
	ps, err := LoadEmbeddedPolicies("")
	require.NoError(t, err)
	require.NotNil(t, ps)
}

func TestMiddleware(t *testing.T) {
	ps, err := LoadEmbeddedPolicies("")
	require.NoError(t, err)

	tests := []struct {
		name           string
		method         string
		path           string
		issuer         string
		sub            string
		subjectID      string
		scopes         []string
		groups         []string
		isPublisher    bool
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
			scopes:         nil,
			groups:         nil,
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return true, nil },
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:        "permits trusted publisher for ingest",
			method:      "POST",
			path:        "/api/ingest",
			issuer:      "https://auth.example.com",
			sub:         "user123",
			subjectID:   "proj-1",
			scopes:      nil,
			groups:      nil,
			isPublisher: true,
			trustLookup: func(ctx context.Context, subjectID, issuer, sub string) (bool, error) {
				return true, nil
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:        "denies untrusted publisher",
			method:      "POST",
			path:        "/api/ingest",
			issuer:      "https://auth.example.com",
			sub:         "user123",
			subjectID:   "proj-1",
			scopes:      nil,
			groups:      nil,
			isPublisher: false,
			trustLookup: func(ctx context.Context, subjectID, issuer, sub string) (bool, error) {
				return false, nil
			},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:        "trust lookup failure returns 403",
			method:      "POST",
			path:        "/api/ingest",
			issuer:      "https://auth.example.com",
			sub:         "user123",
			subjectID:   "proj-1",
			scopes:      nil,
			groups:      nil,
			isPublisher: false,
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
			scopes:         nil,
			groups:         nil,
			isPublisher:    false,
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
			scopes:         nil,
			groups:         nil,
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return true, nil },
			wantStatusCode: http.StatusUnauthorized,
		},
		// Gateway admin request-* actions — complytime:admin scope required
		{
			name:           "permits admin request-registration",
			method:         "POST",
			path:           "/admin/subjects",
			issuer:         "https://auth.example.com",
			sub:            "admin-operator",
			subjectID:      "",
			scopes:         []string{"complytime:admin"},
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "denies non-admin request-registration",
			method:         "POST",
			path:           "/admin/subjects",
			issuer:         "https://auth.example.com",
			sub:            "random-user",
			subjectID:      "",
			scopes:         nil,
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusForbidden,
		},
		// query:evidence — requires complytime:audit or complytime:admin scope
		{
			name:           "auditor scope can query evidence",
			method:         "GET",
			path:           "/api/subjects",
			issuer:         "https://idp.example.com",
			sub:            "alice",
			subjectID:      "",
			scopes:         []string{"complytime:audit"},
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "admin scope can query evidence",
			method:         "GET",
			path:           "/api/subjects",
			issuer:         "https://idp.example.com",
			sub:            "alice",
			subjectID:      "",
			scopes:         []string{"complytime:admin"},
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "publisher flag flows into Cedar entity",
			method:         "GET",
			path:           "/api/subjects",
			issuer:         "https://idp.example.com",
			sub:            "publisher-1",
			subjectID:      "",
			scopes:         nil,
			groups:         nil,
			isPublisher:    true,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusForbidden,
		},
		// Group-based authorization tests
		{
			name:           "admin group grants admin access",
			method:         "POST",
			path:           "/admin/subjects",
			issuer:         "https://idp.example.com",
			sub:            "alice",
			subjectID:      "",
			scopes:         nil,
			groups:         []string{"complytime-admin"},
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "audit group grants query access",
			method:         "GET",
			path:           "/api/subjects",
			issuer:         "https://idp.example.com",
			sub:            "bob",
			subjectID:      "",
			scopes:         nil,
			groups:         []string{"complytime-auditor"},
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "no scopes no groups denies admin",
			method:         "POST",
			path:           "/admin/subjects",
			issuer:         "https://idp.example.com",
			sub:            "charlie",
			subjectID:      "",
			scopes:         nil,
			groups:         nil,
			isPublisher:    false,
			trustLookup:    func(ctx context.Context, subjectID, issuer, sub string) (bool, error) { return false, nil },
			wantStatusCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := Middleware(ps, tt.trustLookup, MiddlewareConfig{})
			wrapped := middleware(handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			ctx := req.Context()
			ctx = SetPublisherContext(ctx, tt.issuer, tt.sub)
			ctx = SetSubjectIDContext(ctx, tt.subjectID)
			ctx = SetScopesContext(ctx, tt.scopes)
			ctx = SetGroupsContext(ctx, tt.groups)
			ctx = SetPublisherFlagContext(ctx, tt.isPublisher)
			req = req.WithContext(ctx)

			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatusCode, rec.Code)
		})
	}
}

func TestMiddlewareCustomGroupNames(t *testing.T) {
	ps, err := LoadEmbeddedPolicies("")
	require.NoError(t, err)

	cfg := MiddlewareConfig{
		AdminGroup:   "ops-admin",
		AuditorGroup: "ops-auditor",
	}
	noTrust := func(ctx context.Context, subjectID, issuer, sub string) (bool, error) {
		return false, nil
	}

	tests := []struct {
		name           string
		method         string
		path           string
		groups         []string
		wantStatusCode int
	}{
		{
			name:           "custom admin group grants admin access",
			method:         "POST",
			path:           "/admin/subjects",
			groups:         []string{"ops-admin"},
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "custom auditor group grants query access",
			method:         "GET",
			path:           "/api/subjects",
			groups:         []string{"ops-auditor"},
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "default admin group name rejected when custom name configured",
			method:         "POST",
			path:           "/admin/subjects",
			groups:         []string{"complytime-admin"},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:           "default auditor group name rejected when custom name configured",
			method:         "GET",
			path:           "/api/subjects",
			groups:         []string{"complytime-auditor"},
			wantStatusCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			middleware := Middleware(ps, noTrust, cfg)
			wrapped := middleware(handler)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			ctx := req.Context()
			ctx = SetPublisherContext(ctx, "https://idp.example.com", "user")
			ctx = SetSubjectIDContext(ctx, "")
			ctx = SetScopesContext(ctx, nil)
			ctx = SetGroupsContext(ctx, tt.groups)
			ctx = SetPublisherFlagContext(ctx, false)
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

	// Test scopes context
	ctx = SetScopesContext(ctx, []string{"complytime:admin", "complytime:audit"})
	scopes := GetScopes(ctx)
	assert.Equal(t, []string{"complytime:admin", "complytime:audit"}, scopes)

	// Test publisher flag context
	ctx = SetPublisherFlagContext(ctx, true)
	isPublisher := GetPublisherFlag(ctx)
	assert.Equal(t, true, isPublisher)

	// Test groups context
	ctx = SetGroupsContext(ctx, []string{"complytime-admin", "complytime-publisher"})
	groups := GetGroups(ctx)
	assert.Equal(t, []string{"complytime-admin", "complytime-publisher"}, groups)

	// Test missing values
	emptyCtx := context.Background()
	issuer, sub = GetPublisher(emptyCtx)
	assert.Equal(t, "", issuer)
	assert.Equal(t, "", sub)

	subjectID = GetSubjectID(emptyCtx)
	assert.Equal(t, "", subjectID)

	assert.Nil(t, GetScopes(emptyCtx))

	isPublisher = GetPublisherFlag(emptyCtx)
	assert.Equal(t, false, isPublisher)

	assert.Nil(t, GetGroups(emptyCtx))
}
