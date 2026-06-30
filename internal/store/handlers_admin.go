// SPDX-License-Identifier: Apache-2.0

package store

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/cedar-policy/cedar-go"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/auth"
	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/evidence"
	"github.com/complytime-labs/complytime-core/internal/httputil"
	"github.com/complytime-labs/complytime-core/internal/requirements"
)

func registerAdminRoutes(g *echo.Group, s Stores) {
	handler := AdminRegisterTargetHandler(
		s.TesseraAppender, s.JWTVerifier, s.Targets, s.TrustedPublishers, s.Authorizer, s.EventPublisher,
	)
	g.POST("/targets", echo.WrapHandler(handler))
}

// AdminRegisterTargetHandler handles POST /api/admin/targets.
// Parses and validates a TargetRegistration artifact, writes to NATS KV stores,
// and appends an audit entry to Tessera.
func AdminRegisterTargetHandler(appender TesseraAppender, verifier JWTVerifier, targets requirements.TargetStore, trustedPubs requirements.TrustedPublisherStore, authorizer auth.Authorizer, pub EventPublisher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token := extractBearerToken(r)
		if token == "" {
			httputil.WriteJSON(w, http.StatusUnauthorized, map[string]any{
				"errors": []string{"missing or invalid Authorization header"},
			})
			return
		}

		claims, err := verifier.Verify(ctx, token)
		if err != nil {
			slog.Warn("admin jwt verification failed", "error", err)
			httputil.WriteJSON(w, http.StatusForbidden, map[string]any{
				"errors": []string{"JWT verification failed"},
			})
			return
		}

		// Cedar authorization: admin:register-target
		principal := cedar.NewEntityUID("Identity", cedar.String(claims.Sub))
		action := cedar.NewEntityUID("Action", "admin:register-target")
		resource := cedar.NewEntityUID("Resource", "system")

		// Extract groups from middleware session (OAuth2 Proxy sets X-Forwarded-Groups)
		var principalAttrs map[string]cedar.Value
		if sess, ok := auth.SessionFrom(ctx); ok && len(sess.Groups) > 0 {
			groupSet := make([]cedar.Value, len(sess.Groups))
			for i, g := range sess.Groups {
				groupSet[i] = cedar.String(g)
			}
			principalAttrs = map[string]cedar.Value{
				"groups": cedar.NewSet(groupSet...),
			}
		}

		allowed, err := authorizer.IsAuthorized(principal, principalAttrs, action, resource, nil)
		if err != nil {
			slog.Error("cedar admin authorization error", "error", err)
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"errors": []string{"authorization error"},
			})
			return
		}
		if !allowed {
			slog.Warn("admin authorization denied", "principal", claims.Sub, "action", "admin:register-target")
			httputil.WriteJSON(w, http.StatusForbidden, map[string]any{
				"errors": []string{"admin access denied — requires admins group"},
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
				"errors": []string{"request body too large"},
			})
			return
		}

		reg, err := evidence.ParseTargetRegistration(body)
		if err != nil {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"errors": []string{err.Error()},
			})
			return
		}
		if err := evidence.ValidateTargetRegistration(reg); err != nil {
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"errors": []string{err.Error()},
			})
			return
		}

		// Append audit entry to Tessera
		logIndex, err := appender.Add(ctx, body)
		if err != nil {
			slog.Error("tessera append failed for admin registration", "error", err)
			httputil.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{
				"errors": []string{"evidence log unavailable — try again later"},
			})
			return
		}

		registeredAt, err := time.Parse(time.RFC3339, reg.Metadata.Date)
		if err != nil {
			registeredAt = time.Now().UTC()
		}

		// Write to NATS KV: targets-registry
		row := requirements.TargetRow{
			TargetID:        reg.Target.ID,
			TesseraLogIndex: logIndex,
			TargetName:      reg.Target.Name,
			TargetType:      reg.Target.Type,
			Technologies:    requirements.NormalizeSlice(reg.Dimensions.Technologies),
			Geopolitical:    requirements.NormalizeSlice(reg.Dimensions.Geopolitical),
			Sensitivity:     requirements.NormalizeSlice(reg.Dimensions.Sensitivity),
			Users:           requirements.NormalizeSlice(reg.Dimensions.Users),
			Groups:          requirements.NormalizeSlice(reg.Dimensions.Groups),
			RegisteredAt:    registeredAt,
			RegisteredBy:    claims.Sub,
		}
		if err := targets.InsertTarget(ctx, row); err != nil {
			slog.Error("admin target insert failed", "target_id", reg.Target.ID, "error", err)
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"errors": []string{"target registration failed"},
			})
			return
		}

		// Write to NATS KV: publisher-trust
		if len(reg.Target.TrustedPublishers) > 0 && trustedPubs != nil {
			logIdx := int64(logIndex) //nolint:gosec
			addedBy := claims.Sub
			pubRows := make([]requirements.TrustedPublisherRow, len(reg.Target.TrustedPublishers))
			for i, p := range reg.Target.TrustedPublishers {
				pubRows[i] = requirements.TrustedPublisherRow{
					TargetID:        reg.Target.ID,
					Issuer:          p.Issuer,
					SubPattern:      p.SubPattern,
					AddedAt:         registeredAt,
					AddedBy:         &addedBy,
					TesseraLogIndex: &logIdx,
				}
				if p.Environment != "" {
					env := p.Environment
					pubRows[i].Environment = &env
				}
			}
			if err := trustedPubs.InsertTrustedPublishers(ctx, pubRows); err != nil {
				slog.Error("admin trusted publishers insert failed", "target_id", reg.Target.ID, "error", err)
				httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
					"errors": []string{"trusted publisher registration failed"},
				})
				return
			}
		}

		if len(reg.Target.RemovePublishers) > 0 && trustedPubs != nil {
			keys := make([]requirements.TrustedPublisherKey, len(reg.Target.RemovePublishers))
			for i, p := range reg.Target.RemovePublishers {
				keys[i] = requirements.TrustedPublisherKey{
					Issuer:     p.Issuer,
					SubPattern: p.SubPattern,
				}
			}
			if err := trustedPubs.RemoveTrustedPublishers(ctx, reg.Target.ID, keys, logIndex); err != nil {
				slog.Error("admin trusted publishers remove failed", "target_id", reg.Target.ID, "error", err)
				httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
					"errors": []string{"trusted publisher removal failed"},
				})
				return
			}
		}

		if pub != nil {
			pub.PublishTargetRegistered(logIndex, reg.Target.ID, claims.Sub)
		}

		slog.Info("admin target registered",
			"target_id", reg.Target.ID,
			"log_index", logIndex,
			"registered_by", claims.Sub,
		)

		httputil.WriteJSON(w, http.StatusCreated, map[string]any{
			"target_id": reg.Target.ID,
			"log_index": logIndex,
			"status":    "registered",
		})
	}
}
