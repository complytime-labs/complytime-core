// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/bus"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/httputil"
	"github.com/complytime-labs/complytime-core/internal/receipt"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func registerIngestRoutes(g *echo.Group, s Stores) {
	ingestHandler := httputil.RateLimit(s.IngestRateLimit)(
		IngestAsyncHandler(s.IngestPublisher, s.IngestTracker, s.TesseraAppender, s.JWTVerifier, s.TrustedPublishers, s.Authorizer),
	)
	g.POST("/ingest", echo.WrapHandler(ingestHandler))
	g.GET("/ingest/jobs/:job_id", IngestJobStatusHandler(s.IngestTracker))
}

// IngestPublisher publishes an IngestRef to JetStream for durable async processing.
type IngestPublisher interface {
	PublishIngest(ctx context.Context, ref bus.IngestRef) error
}

// IngestAsyncHandler returns an http.HandlerFunc implementing the 2-step ingest pipeline:
//  1. Channel access: JWT verification, artifact type detection, per-target publisher
//     authorization via Cedar publish:artifact
//  2. Tessera append: format detection, normalization to canonical JSON, receipt
//     wrapping (or DSSE pass-through), transparency log append
func IngestAsyncHandler(pub IngestPublisher, tracker *IngestTracker, appender TesseraAppender, verifier JWTVerifier, trustedPubs requirements.TrustedPublisherStore, authorizer auth.Authorizer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// ── Step 1: Channel access ──────────────────────────────────

		token := extractBearerToken(r)
		if token == "" {
			httputil.WriteJSON(w, http.StatusUnauthorized, map[string]any{
				"errors": []string{"missing or invalid Authorization header — expected 'Bearer <token>'"},
			})
			return
		}

		claims, err := verifier.Verify(ctx, token)
		if err != nil {
			slog.Warn("jwt verification failed", "error", err)
			httputil.WriteJSON(w, http.StatusForbidden, map[string]any{
				"errors": []string{"JWT verification failed"},
			})
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, consts.MaxSubmissionBody+1))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) == 0 {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"errors": []string{"request body is empty"},
			})
			return
		}
		if int64(len(body)) > consts.MaxSubmissionBody {
			httputil.WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"errors": []string{fmt.Sprintf("submission exceeds %d byte limit", consts.MaxSubmissionBody)},
			})
			return
		}

		format := receipt.DetectFormat(r.Header.Get("Content-Type"))

		// Reject TargetRegistration regardless of format
		if format == receipt.FormatDSSE {
			if payload, err := receipt.DecodeDSSEPayload(body); err == nil {
				if evidence.DetectArtifactTypeString(payload) == "TargetRegistration" {
					httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
						"errors": []string{"target registration must use POST /api/admin/targets"},
					})
					return
				}
			}
		} else {
			if evidence.DetectArtifactTypeString(body) == "TargetRegistration" {
				httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
					"errors": []string{"target registration must use POST /api/admin/targets"},
				})
				return
			}
		}

		cedarAction, resourceAttrs, targetID, err := resolvePublishAction(ctx, body, claims, trustedPubs, format)
		if err != nil {
			slog.Warn("publish authorization failed", "issuer", claims.Iss, "sub", claims.Sub, "error", err)
			httputil.WriteJSON(w, http.StatusForbidden, map[string]any{
				"errors": []string{err.Error()},
			})
			return
		}

		principal := cedar.NewEntityUID("Identity", cedar.String(claims.Sub))
		resource := cedar.NewEntityUID("Resource", "system")
		if targetID != "" {
			resource = cedar.NewEntityUID("Target", cedar.String(targetID))
		}

		allowed, err := authorizer.IsAuthorized(principal, nil, cedarAction, resource, resourceAttrs)
		if err != nil {
			slog.Error("cedar authorization error", "error", err)
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"errors": []string{"authorization error"},
			})
			return
		}
		if !allowed {
			slog.Warn("publish authorization denied",
				"principal", claims.Sub,
				"issuer", claims.Iss,
				"action", cedarAction.ID,
				"target", targetID,
				"decision", "deny",
			)
			msg := fmt.Sprintf(
				"publisher not authorized for the requested target — check issuer=%s subject=%s",
				claims.Iss, claims.Sub,
			)
			httputil.WriteJSON(w, http.StatusForbidden, map[string]any{
				"errors": []string{msg},
			})
			return
		}

		slog.Info("publish authorization permitted",
			"principal", claims.Sub,
			"action", cedarAction.ID,
			"decision", "allow",
		)

		// ── Step 2: Tessera append ──────────────────────────────────

		now := time.Now().UTC()
		var entryBytes []byte

		if format == receipt.FormatDSSE {
			if err := receipt.ValidateDSSE(body); err != nil {
				httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
					"errors": []string{err.Error()},
				})
				return
			}
			entryBytes = body
		} else {
			jsonBytes, err := normalizeArtifact(body)
			if err != nil {
				httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
					"errors": []string{err.Error()},
				})
				return
			}

			canonical, digest, err := receipt.Canonicalize(jsonBytes)
			if err != nil {
				httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
					"errors": []string{fmt.Sprintf("canonicalize: %v", err)},
				})
				return
			}

			artifactType := evidence.DetectArtifactTypeString(body)
			authorType := detectAuthorType(body)
			publisher := receipt.Publisher{
				Issuer:  claims.Iss,
				Subject: claims.Sub,
				Method:  "jwt-channel",
			}

			entryBytes, err = receipt.Wrap(canonical, digest, publisher, artifactType, authorType, now)
			if err != nil {
				slog.Error("receipt wrap failed", "error", err)
				httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
					"errors": []string{"internal error wrapping receipt"},
				})
				return
			}
		}

		logIndex, err := appender.Add(ctx, entryBytes)
		if err != nil {
			slog.Error("tessera append failed", "error", err)
			httputil.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
				"errors": []string{"evidence log unavailable — try again later"},
			})
			return
		}

		publisherType := inferPublisherType(claims.Sub)
		jobID := generateJobID()
		tracker.Create(jobID)

		ref := bus.IngestRef{
			JobID:    jobID,
			LogIndex: logIndex,
			PublisherIdentity: bus.PublisherIdentity{
				Sub:      claims.Sub,
				Issuer:   claims.Iss,
				Type:     publisherType,
				Verified: true,
			},
			Timestamp: now,
		}

		if err := pub.PublishIngest(ctx, ref); err != nil {
			tracker.Fail(jobID, fmt.Sprintf("publish failed: %v", err))
			slog.Error("async ingest publish failed", "job_id", jobID, "error", err)
			httputil.WriteJSON(w, http.StatusAccepted, map[string]any{
				"log_index": logIndex,
				"job_id":    jobID,
				"status":    "pending",
				"warning":   "async processing delayed — Tessera has the data",
			})
			return
		}

		httputil.WriteJSON(w, http.StatusAccepted, map[string]any{
			"job_id":    jobID,
			"log_index": logIndex,
			"status":    "pending",
		})
	}
}

// IngestJobStatusHandler returns an echo handler for polling async ingest jobs.
func IngestJobStatusHandler(tracker *IngestTracker) echo.HandlerFunc {
	return func(c echo.Context) error {
		jobID := c.Param("job_id")
		if jobID == "" {
			return jsonError(c, http.StatusBadRequest, "missing job_id")
		}
		status := tracker.Get(jobID)
		if status == nil {
			return jsonError(c, http.StatusNotFound, "job not found")
		}
		return c.JSON(http.StatusOK, status)
	}
}

func generateJobID() string {
	return uuid.New().String()
}

// extractBearerToken extracts the JWT token from the Authorization header.
// Returns empty string if the header is missing or malformed.
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}

// resolvePublishAction resolves Cedar action and publisher trust for all artifact types.
// All ingest submissions use publish:artifact with per-target publisher trust.
func resolvePublishAction(ctx context.Context, body []byte, claims *auth.JWTClaims, store requirements.TrustedPublisherStore, format receipt.Format) (cedar.EntityUID, map[string]cedar.Value, string, error) {
	targetID := resolveTargetID(body, format)
	if targetID == "" {
		return cedar.EntityUID{}, nil, "", fmt.Errorf("artifact missing target.id — all submissions must reference a target")
	}

	if store == nil {
		return cedar.EntityUID{}, nil, "", fmt.Errorf("publisher trust store unavailable")
	}

	trusted, err := isPublisherTrusted(ctx, claims, targetID, store)
	if err != nil {
		return cedar.EntityUID{}, nil, "", err
	}

	resourceAttrs := map[string]cedar.Value{
		"publisher_trusted": cedar.Boolean(trusted),
	}

	return cedar.NewEntityUID("Action", "publish:artifact"), resourceAttrs, targetID, nil
}

// isPublisherTrusted checks if the JWT claims match a trusted publisher for the target.
func isPublisherTrusted(ctx context.Context, claims *auth.JWTClaims, targetID string, store requirements.TrustedPublisherStore) (bool, error) {
	pubs, err := store.GetTrustedPublishers(ctx, targetID)
	if err != nil {
		return false, fmt.Errorf("publisher trust check unavailable — try again later")
	}

	if len(pubs) == 0 {
		return false, nil
	}

	for _, p := range pubs {
		if matchPublisher(claims.Iss, claims.Sub, p.Issuer, p.SubPattern) {
			return true, nil
		}
	}

	return false, nil
}

// matchPublisher checks if a JWT issuer/subject matches a trusted publisher
// entry. Supports exact match and glob-style prefix matching (trailing *).
func matchPublisher(issuer, sub, trustedIssuer, trustedPattern string) bool {
	if issuer != trustedIssuer {
		return false
	}
	if trustedPattern == sub {
		return true
	}
	if strings.HasSuffix(trustedPattern, "*") {
		return strings.HasPrefix(sub, trustedPattern[:len(trustedPattern)-1])
	}
	return false
}

// resolveTargetID extracts the target ID from the submission body.
// For DSSE envelopes, decodes the payload first.
func resolveTargetID(body []byte, format receipt.Format) string {
	if format == receipt.FormatDSSE {
		payload, err := receipt.DecodeDSSEPayload(body)
		if err != nil {
			return ""
		}
		return evidence.DetectTargetID(payload)
	}
	return evidence.DetectTargetID(body)
}

// inferPublisherType infers the publisher type from the JWT subject claim.
// GitHub Actions subjects start with "repo:", Kubernetes service accounts start with "system:".
func inferPublisherType(sub string) string {
	if strings.HasPrefix(sub, "repo:") {
		return "pipeline"
	}
	if strings.HasPrefix(sub, "system:") {
		return "service"
	}
	return "unknown"
}
