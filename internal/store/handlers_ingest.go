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

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/httputil"
)

func registerIngestRoutes(g *echo.Group, s Stores) {
	g.POST("/ingest", echo.WrapHandler(IngestAsyncHandler(s.IngestPublisher, s.IngestTracker, s.TesseraAppender, s.JWTVerifier)))
	g.GET("/ingest/jobs/:job_id", IngestJobStatusHandler(s.IngestTracker))
}

// IngestPublisher publishes an IngestRef to JetStream for durable async processing.
type IngestPublisher interface {
	PublishIngest(ctx context.Context, ref events.IngestRef) error
}

// IngestAsyncHandler returns an http.HandlerFunc that accepts raw Gemara
// YAML with a Bearer JWT token, verifies the JWT, appends to Tessera,
// assigns a job ID, publishes an IngestRef to JetStream, and returns
// 202 Accepted with the job ID and log_index for polling.
func IngestAsyncHandler(pub IngestPublisher, tracker *IngestTracker, appender TesseraAppender, verifier JWTVerifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

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

		body, err := io.ReadAll(io.LimitReader(r.Body, consts.MaxRequestBody))
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		if len(body) == 0 {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"errors": []string{"request body is empty — expected Gemara YAML"},
			})
			return
		}

		logIndex, err := appender.Add(ctx, body)
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

		ref := events.IngestRef{
			JobID: jobID,
			LogIndex: logIndex,
			PublisherIdentity: events.PublisherIdentity{
				Sub:      claims.Sub,
				Issuer:   claims.Iss,
				Type:     publisherType,
				Verified: true,
			},
			Timestamp: time.Now().UTC(),
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
