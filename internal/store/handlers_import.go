// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"
	gemara "github.com/gemaraproj/go-gemara"
	gemarabundle "github.com/gemaraproj/go-gemara/bundle"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/attestation"
	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

const maxUnifiedImportBytes = 10 << 20

func registerImportRoute(g *echo.Group, s Stores) {
	g.POST("/import", importArtifactHandler(s))
}

// importArtifactHandler accepts OCI bundle references only.
// Raw artifact ingestion goes through POST /api/ingest (async via NATS).
// See ADR #0034 — Unified Ingest Pipeline.
func importArtifactHandler(s Stores) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		ctx := r.Context()

		token := extractBearerToken(r)
		if token == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": "missing or invalid Authorization header — expected 'Bearer <token>'",
			})
		}

		claims, err := s.JWTVerifier.Verify(ctx, token)
		if err != nil {
			slog.Warn("import jwt verification failed", "error", err)
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "JWT verification failed",
			})
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxUnifiedImportBytes))
		if err != nil {
			return jsonError(c, http.StatusBadRequest, "read body failed")
		}
		var probe struct {
			Reference string `json:"reference"`
		}
		if json.Unmarshal(body, &probe) != nil || strings.TrimSpace(probe.Reference) == "" {
			return jsonError(c, http.StatusBadRequest,
				"expected JSON body with \"reference\" field — "+
					"for raw YAML, use POST /api/ingest")
		}
		return ociImport(c, s, strings.TrimSpace(probe.Reference), claims)
	}
}

// ── OCI reference import ────────────────────────────────────────────────────

func ociImport(c echo.Context, s Stores, ref string, claims *auth.JWTClaims) error {
	if s.Registry == nil {
		return jsonError(c, http.StatusServiceUnavailable, "registry not configured")
	}

	repo, err := s.Registry.Repository(ref)
	if err != nil {
		return jsonError(c, http.StatusForbidden, err.Error())
	}

	ctx := c.Request().Context()
	bundle, err := gemarabundle.Unpack(ctx, repo, repo.Reference.Reference)
	if err != nil {
		slog.Error("oci import unpack failed", "reference", ref, "error", err)
		return jsonError(c, http.StatusBadGateway, "failed to pull bundle: "+err.Error())
	}

	bundleID := uuid.New().String()
	allFiles := append(bundle.Files, bundle.Imports...)

	if s.TesseraAppender == nil || s.IngestPublisher == nil {
		return jsonError(c, http.StatusServiceUnavailable, "tessera and NATS are required for import")
	}

	identity := bus.PublisherIdentity{
		Sub:      claims.Sub,
		Issuer:   claims.Iss,
		Type:     inferPublisherType(claims.Sub),
		Verified: true,
	}

	// Build Cedar principal from JWT claims and session groups
	importPrincipal := cedar.NewEntityUID("Identity", cedar.String(claims.Sub))
	var importPrincipalAttrs map[string]cedar.Value
	if sess, ok := auth.SessionFrom(ctx); ok && len(sess.Groups) > 0 {
		groupSet := make([]cedar.Value, len(sess.Groups))
		for i, g := range sess.Groups {
			groupSet[i] = cedar.String(g)
		}
		importPrincipalAttrs = map[string]cedar.Value{
			"groups": cedar.NewSet(groupSet...),
		}
	}

	var imported []requirements.OciImportedArtifact
	for _, f := range allFiles {
		detected, err := gemara.DetectType(f.Data)
		if err != nil {
			slog.Warn("skip unrecognized artifact", "name", f.Name, "error", err)
			continue
		}

		cedarAction, resourceAttrs, authErr := resolvePublishAction(ctx, f.Data, claims, s.TrustedPublishers)
		if authErr != nil {
			slog.Warn("import artifact authorization failed",
				"name", f.Name, "type", detected.String(), "error", authErr)
			continue
		}

		resource := cedar.NewEntityUID("Resource", "system")
		if targetID := evidence.DetectTargetID(f.Data); targetID != "" {
			resource = cedar.NewEntityUID("Target", cedar.String(targetID))
		}

		allowed, cedarErr := s.Authorizer.IsAuthorized(importPrincipal, importPrincipalAttrs, cedarAction, resource, resourceAttrs)
		if cedarErr != nil {
			slog.Error("import cedar authorization error", "name", f.Name, "error", cedarErr)
			continue
		}
		if !allowed {
			slog.Warn("import artifact authorization denied",
				"name", f.Name, "type", detected.String(),
				"principal", claims.Sub, "action", cedarAction.ID)
			continue
		}

		publisher := attestation.PublisherMeta{
			Issuer:  identity.Issuer,
			Subject: identity.Sub,
			Method:  "import",
		}
		artifactType := detected.String()
		wrappedEntry, wrapErr := attestation.WrapAsReceipt(f.Data, publisher, artifactType, "")
		if wrapErr != nil {
			slog.Error("attestation wrapping failed", "name", f.Name, "error", wrapErr)
			continue
		}

		logIndex, err := s.TesseraAppender.Add(ctx, wrappedEntry)
		if err != nil {
			slog.Error("tessera append failed", "name", f.Name, "error", err)
			continue
		}

		jobID := uuid.New().String()
		s.IngestTracker.Create(jobID)

		ingestRef := bus.IngestRef{
			JobID:             jobID,
			LogIndex:          logIndex,
			PublisherIdentity: identity,
			BundleID:          bundleID,
			OCIReference:      ref,
			Timestamp:         time.Now().UTC(),
		}
		if err := s.IngestPublisher.PublishIngest(ctx, ingestRef); err != nil {
			s.IngestTracker.Fail(jobID, fmt.Sprintf("publish failed: %v", err))
			slog.Error("jetstream publish failed", "name", f.Name, "error", err)
			continue
		}

		imported = append(imported, requirements.OciImportedArtifact{
			Type: detected.String(),
			Name: f.Name,
		})
	}

	return c.JSON(http.StatusAccepted, map[string]any{
		"bundle_id": bundleID,
		"status":    "processing",
		"digest":    bundle.Etag,
		"artifacts": len(imported),
	})
}
