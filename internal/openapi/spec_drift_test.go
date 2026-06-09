// SPDX-License-Identifier: Apache-2.0

package openapi_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/config"
	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/gemara"
	"github.com/complytime-labs/complytime-core/internal/store"
)

// specPath resolves the OpenAPI spec relative to this test file.
func specPath() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "docs", "api", "openapi.yaml")
}

// echoToSpec converts an Echo route path to OpenAPI path syntax.
// Echo uses :param and * wildcards; OpenAPI uses {param}.
func echoToSpec(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if strings.HasPrefix(seg, ":") {
			parts[i] = "{" + seg[1:] + "}"
		}
	}
	return strings.Join(parts, "/")
}

// routeKey is "METHOD /path" for comparison.
type routeKey struct {
	Method string
	Path   string
}

func (k routeKey) String() string { return k.Method + " " + k.Path }

// specRoutes parses the OpenAPI spec and returns all path+method pairs.
func specRoutes(t *testing.T) map[routeKey]bool {
	t.Helper()
	data, err := os.ReadFile(specPath())
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(data)
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	// Skip full validation — we only need paths and methods, not
	// response description completeness. Spec linting is a separate concern.
	_ = doc.Validate(loader.Context)

	routes := make(map[routeKey]bool)
	for path, item := range doc.Paths.Map() {
		for _, method := range []string{
			http.MethodGet, http.MethodPost, http.MethodPut,
			http.MethodPatch, http.MethodDelete,
		} {
			if item.GetOperation(method) != nil {
				routes[routeKey{Method: method, Path: path}] = true
			}
		}
	}
	return routes
}

// buildRouter constructs an Echo instance mirroring cmd/gateway/main.go route
// registration with stub stores. No server is started; we only inspect routes.
func buildRouter(t *testing.T) *echo.Echo {
	t.Helper()
	e := echo.New()

	authHandler := auth.NewHandler()
	authHandler.Register(e)

	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	apiGroup := e.Group("/api")

	s := store.Stores{
		Policies:            &nopPolicyStore{},
		Mappings:            &nopMappingStore{},
		Evidence:            &nopEvidenceStore{},
		AuditLogs:           &nopAuditLogStore{},
		DraftAuditLogs:      &nopDraftAuditLogStore{},
		Requirements:        &nopRequirementStore{},
		Controls:            &nopControlStore{},
		Guidance:            &nopGuidanceStore{},
		Threats:             &nopThreatStore{},
		Risks:               &nopRiskStore{},
		Catalogs:            &nopCatalogStore{},
		EvidenceAssessments: &nopEvidenceAssessmentStore{},
		Certifications:      &nopCertificationStore{},
		EventPublisher:      &nopEventPublisher{},
		HealthChecker:       &nopHealthChecker{},
		Inventory:           &nopInventoryStore{},
		Users:               &nopUserStore{},
		IngestTracker:       store.NewIngestTracker(),
		IngestPublisher:     &nopIngestPublisher{},
		TesseraAppender:     &nopTesseraAppender{},
		JWTVerifier:         &nopJWTVerifier{},
		Targets:             &nopTargetStore{},
		PolicyDimensions:    &nopPolicyDimensionStore{},
	}
	store.Register(apiGroup, s)

	authHandler.SetUserStore(&nopUserStore{})
	authHandler.RegisterUserAPI(apiGroup)
	config.Register(apiGroup, config.Options{Values: map[string]string{}})

	apiGroup.GET("/system-info", func(c echo.Context) error {
		return c.JSON(http.StatusOK, nil)
	})

	return e
}

// echoRoutes extracts all registered path+method pairs from the Echo router.
// Filters to only /api/* and /auth/* and /healthz paths. Skips the catch-all.
func echoRoutes(e *echo.Echo) map[routeKey]bool {
	routes := make(map[routeKey]bool)
	for _, r := range e.Routes() {
		path := r.Path
		if path == "/*" || path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/api/") &&
			!strings.HasPrefix(path, "/auth/") &&
			path != "/healthz" {
			continue
		}

		specPath := echoToSpec(path)
		routes[routeKey{Method: r.Method, Path: specPath}] = true
	}
	return routes
}

var wildcardMappings = map[string]string{}

func TestSpecDrift(t *testing.T) {
	t.Parallel()

	spec := specRoutes(t)
	router := buildRouter(t)
	code := echoRoutes(router)

	// Expand Echo wildcard Any routes to individual methods for comparison.
	// Echo's Any() registers GET, POST, PUT, PATCH, DELETE, etc.
	expandedCode := make(map[routeKey]bool)
	for k := range code {
		expandedCode[k] = true
	}

	// Build reverse wildcard map: spec path -> echo wildcard path
	wildcardSpecPaths := make(map[string]bool)
	for specPath := range wildcardMappings {
		wildcardSpecPaths[specPath] = true
	}

	var missing []string // in spec but not in code
	var undoced []string // in code but not in spec

	for k := range spec {
		if wildcardSpecPaths[k.Path] {
			echoPath := wildcardMappings[k.Path]
			echoKey := routeKey{Method: k.Method, Path: echoPath}
			if !expandedCode[echoKey] {
				missing = append(missing, k.String())
			}
			continue
		}
		if !expandedCode[k] {
			missing = append(missing, k.String())
		}
	}

	// Internal-only routes consumed by the workbench, not advertised in
	// OpenAPI (ADR 0039 Phase A — temporary proxy targets).
	for k := range expandedCode {
		switch k.Method {
		case http.MethodOptions, http.MethodHead, http.MethodConnect, http.MethodTrace:
			continue
		}
		if !spec[k] {
			undoced = append(undoced, k.String())
		}
	}

	sort.Strings(missing)
	sort.Strings(undoced)

	if len(missing) > 0 {
		t.Errorf("spec documents routes that do NOT exist in Echo (%d):\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(undoced) > 0 {
		t.Errorf("Echo registers routes NOT documented in OpenAPI spec (%d):\n  %s",
			len(undoced), strings.Join(undoced, "\n  "))
	}

	if len(missing) == 0 && len(undoced) == 0 {
		specCount := len(spec)
		codeCount := 0
		for k := range expandedCode {
			switch k.Method {
			case http.MethodOptions, http.MethodHead, http.MethodConnect, http.MethodTrace:
				continue
			}
			codeCount++
		}
		t.Logf("OK: %d spec routes, %d code routes — no drift detected", specCount, codeCount)
	}
}

// ---------------------------------------------------------------------------
// Stub implementations — satisfy interfaces for route registration only.
// None of these are called; handlers are never invoked.
// ---------------------------------------------------------------------------

type nopPolicyStore struct{}

func (*nopPolicyStore) InsertPolicy(context.Context, store.Policy) error         { panic("nop") }
func (*nopPolicyStore) ListPolicies(context.Context) ([]store.Policy, error)     { panic("nop") }
func (*nopPolicyStore) GetPolicy(context.Context, string) (*store.Policy, error) { panic("nop") }

type nopMappingStore struct{}

func (*nopMappingStore) InsertMapping(context.Context, store.MappingDocument) error { panic("nop") }
func (*nopMappingStore) ListMappings(context.Context, string) ([]store.MappingDocument, error) {
	panic("nop")
}
func (*nopMappingStore) ListAllMappings(context.Context) ([]store.MappingDocument, error) {
	panic("nop")
}
func (*nopMappingStore) QueryMappings(context.Context, string, string, int) ([]gemara.MappingEntry, error) {
	panic("nop")
}
func (*nopMappingStore) InsertMappingEntries(context.Context, []gemara.MappingEntry) error {
	panic("nop")
}
func (*nopMappingStore) DeleteMappingEntries(context.Context, string, string) error { panic("nop") }
func (*nopMappingStore) CountMappingEntries(context.Context, string) (int, error)   { panic("nop") }

type nopEvidenceStore struct{}

func (*nopEvidenceStore) InsertEvidence(context.Context, []store.EvidenceRecord) (int, error) {
	panic("nop")
}
func (*nopEvidenceStore) QueryEvidence(context.Context, store.EvidenceFilter) ([]store.EvidenceRecord, error) {
	panic("nop")
}

type nopAuditLogStore struct{}

func (*nopAuditLogStore) InsertAuditLog(context.Context, store.AuditLog) error { panic("nop") }
func (*nopAuditLogStore) ListAuditLogs(context.Context, string, time.Time, time.Time, int) ([]store.AuditLog, error) {
	panic("nop")
}
func (*nopAuditLogStore) GetAuditLog(context.Context, string) (*store.AuditLog, error) {
	panic("nop")
}

type nopDraftAuditLogStore struct{}

func (*nopDraftAuditLogStore) InsertDraftAuditLog(context.Context, store.DraftAuditLog) error {
	panic("nop")
}
func (*nopDraftAuditLogStore) ListDraftAuditLogs(context.Context, string, int) ([]store.DraftAuditLog, error) {
	panic("nop")
}
func (*nopDraftAuditLogStore) GetDraftAuditLog(context.Context, string) (*store.DraftAuditLog, error) {
	panic("nop")
}
func (*nopDraftAuditLogStore) UpdateDraftEdits(context.Context, string, string) error { panic("nop") }
func (*nopDraftAuditLogStore) PromoteDraftAuditLog(context.Context, string, string) error {
	panic("nop")
}

type nopRequirementStore struct{}

func (*nopRequirementStore) ListRequirementMatrix(context.Context, store.RequirementFilter) ([]store.RequirementRow, error) {
	panic("nop")
}
func (*nopRequirementStore) ListRequirementEvidence(context.Context, string, store.RequirementFilter) ([]store.RequirementEvidenceRow, error) {
	panic("nop")
}

type nopControlStore struct{}

func (*nopControlStore) InsertControls(context.Context, []gemara.ControlRow) error { panic("nop") }
func (*nopControlStore) InsertAssessmentRequirements(context.Context, []gemara.AssessmentRequirementRow) error {
	panic("nop")
}
func (*nopControlStore) InsertControlThreats(context.Context, []gemara.ControlThreatRow) error {
	panic("nop")
}
func (*nopControlStore) CountControls(context.Context, string) (int, error) { panic("nop") }

type nopThreatStore struct{}

func (*nopThreatStore) InsertThreats(context.Context, []gemara.ThreatRow) error { panic("nop") }
func (*nopThreatStore) CountThreats(context.Context, string) (int, error)       { panic("nop") }
func (*nopThreatStore) QueryThreats(context.Context, string, string, int) ([]gemara.ThreatRow, error) {
	panic("nop")
}
func (*nopThreatStore) QueryControlThreats(context.Context, string, string, int) ([]gemara.ControlThreatRow, error) {
	panic("nop")
}

type nopRiskStore struct{}

func (*nopRiskStore) InsertRisks(context.Context, []gemara.RiskRow) error             { panic("nop") }
func (*nopRiskStore) InsertRiskThreats(context.Context, []gemara.RiskThreatRow) error { panic("nop") }
func (*nopRiskStore) CountRisks(context.Context, string) (int, error)                 { panic("nop") }
func (*nopRiskStore) QueryRisks(context.Context, string, string, int) ([]gemara.RiskRow, error) {
	panic("nop")
}
func (*nopRiskStore) QueryRiskThreats(context.Context, string, string, int) ([]gemara.RiskThreatRow, error) {
	panic("nop")
}

type nopCatalogStore struct{}

func (*nopCatalogStore) InsertCatalog(context.Context, store.Catalog) error         { panic("nop") }
func (*nopCatalogStore) ListCatalogs(context.Context) ([]store.Catalog, error)      { panic("nop") }
func (*nopCatalogStore) GetCatalog(context.Context, string) (*store.Catalog, error) { panic("nop") }

type nopEvidenceAssessmentStore struct{}

func (*nopEvidenceAssessmentStore) InsertEvidenceAssessments(context.Context, []store.EvidenceAssessment) error {
	panic("nop")
}

type nopCertificationStore struct{}

func (*nopCertificationStore) InsertCertifications(context.Context, []store.CertificationRow) error {
	panic("nop")
}
func (*nopCertificationStore) UpdateEvidenceCertified(context.Context, string, bool) error {
	panic("nop")
}
func (*nopCertificationStore) QueryCertifications(context.Context, string) ([]store.CertificationRow, error) {
	panic("nop")
}
func (*nopCertificationStore) QueryRecentEvidence(context.Context, string, time.Time) ([]store.EvidenceRowLite, error) {
	panic("nop")
}

type nopEventPublisher struct{}

func (*nopEventPublisher) PublishEvidence(string, int)                    {}
func (*nopEventPublisher) PublishDraftAuditLog(string, string, string)    {}
func (*nopEventPublisher) PublishPolicyNew(uint64, string)                {}
func (*nopEventPublisher) PublishTargetRegistered(uint64, string, string) {}

type nopIngestPublisher struct{}

func (*nopIngestPublisher) PublishIngest(_ context.Context, _ events.IngestRef) error { return nil }

type nopHealthChecker struct{}

func (*nopHealthChecker) Ping(context.Context) error { return nil }

type nopGuidanceStore struct{}

func (*nopGuidanceStore) InsertGuidanceEntries(context.Context, []gemara.GuidanceEntryRow) error {
	panic("nop")
}

type nopInventoryStore struct{}

func (*nopInventoryStore) ListInventory(context.Context, store.InventoryFilter) ([]store.InventoryItem, error) {
	panic("nop")
}

type nopUserStore struct{}

func (*nopUserStore) UpsertUser(context.Context, string, string, string, string, string) error {
	return nil
}
func (*nopUserStore) GetUser(context.Context, string) (*auth.User, error) {
	return nil, fmt.Errorf("nop")
}
func (*nopUserStore) GetUserBySub(context.Context, string, string) (*auth.User, error) {
	return nil, fmt.Errorf("nop")
}
func (*nopUserStore) ListUsers(context.Context) ([]auth.User, error)             { return nil, nil }
func (*nopUserStore) SetRole(context.Context, string, string) (string, error)    { return "", nil }
func (*nopUserStore) CountUsers(context.Context) (int, error)                    { return 0, nil }
func (*nopUserStore) CountAdmins(context.Context) (int, error)                   { return 0, nil }
func (*nopUserStore) InsertRoleChange(context.Context, auth.RoleChange) error    { return nil }
func (*nopUserStore) ListRoleChanges(context.Context) ([]auth.RoleChange, error) { return nil, nil }
func (*nopUserStore) BootstrapAdmin(context.Context, string) (string, error)     { return "", nil }

type nopTargetStore struct{}

func (*nopTargetStore) InsertTarget(context.Context, store.TargetRow) error { panic("nop") }
func (*nopTargetStore) GetLatestTarget(context.Context, string, time.Time) (*store.TargetRow, error) {
	panic("nop")
}
func (*nopTargetStore) ListTargets(context.Context) ([]store.TargetRow, error) { panic("nop") }

type nopPolicyDimensionStore struct{}

func (*nopPolicyDimensionStore) QueryPoliciesByDimensions(context.Context, store.DimensionQuery) ([]store.PolicyWithDimensions, error) {
	panic("nop")
}

type nopTesseraAppender struct{}

func (*nopTesseraAppender) Add(context.Context, []byte) (uint64, error) { return 0, nil }

type nopJWTVerifier struct{}

func (*nopJWTVerifier) Verify(context.Context, string) (*auth.JWTClaims, error) {
	return &auth.JWTClaims{
		Iss: "https://example.com",
		Sub: "test-subject",
		Aud: "https://example.com",
		Exp: int64(time.Now().Add(time.Hour).Unix()),
		Iat: int64(time.Now().Unix()),
	}, nil
}
