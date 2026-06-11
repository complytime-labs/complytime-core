// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/complytime-labs/complytime-core/internal/audit"
	"github.com/complytime-labs/complytime-core/internal/consts"
	gemarapkg "github.com/complytime-labs/complytime-core/internal/gemara"
	"github.com/complytime-labs/complytime-core/internal/httputil"
)

func registerAuditRoutes(g *echo.Group, s Stores) {
	g.GET("/audit-logs/:id", getAuditLogHandler(s.AuditLogs))
	g.GET("/audit-logs", listAuditLogsHandler(s.AuditLogs))
	g.POST("/audit-logs", createAuditLogHandler(s.AuditLogs))
}

func registerDraftAuditRoutes(g *echo.Group, s Stores) {
	if s.DraftAuditLogs == nil {
		return
	}
	g.GET("/draft-audit-logs", listDraftAuditLogsHandler(s.DraftAuditLogs))
	g.GET("/draft-audit-logs/:id", getDraftAuditLogHandler(s.DraftAuditLogs))
	g.PATCH("/draft-audit-logs/:id", updateDraftEditsHandler(s.DraftAuditLogs))
	g.POST("/draft-audit-logs", createDraftAuditLogHandler(s.DraftAuditLogs, s.EventPublisher))
	g.POST("/audit-logs/promote", promoteAuditLogHandler(s.DraftAuditLogs))
}

func getAuditLogHandler(s audit.AuditLogStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		id := c.Param("id")
		if id == "" {
			return jsonError(c, http.StatusBadRequest, "missing audit id")
		}
		a, err := s.GetAuditLog(c.Request().Context(), id)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return jsonError(c, http.StatusNotFound, "not found")
			}
			slog.Error("get audit log failed", "error", err, "id", id)
			return jsonError(c, http.StatusInternalServerError, "internal server error")
		}
		return c.JSON(http.StatusOK, a)
	}
}

func listAuditLogsHandler(s audit.AuditLogStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		policyID := c.QueryParam("policy_id")
		if policyID == "" {
			return jsonError(c, http.StatusBadRequest, "policy_id required")
		}
		var start, end time.Time
		if v := c.QueryParam("start"); v != "" {
			if t, err := time.Parse("2006-01-02", v); err == nil {
				start = t
			}
		}
		if v := c.QueryParam("end"); v != "" {
			if t, err := time.Parse("2006-01-02", v); err == nil {
				end = t
			}
		}
		limit := consts.ClampLimit(0)
		if v := c.QueryParam("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = consts.ClampLimit(n)
			}
		}

		logs, err := s.ListAuditLogs(c.Request().Context(), policyID, start, end, limit)
		if err != nil {
			slog.Error("list audit logs failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "query failed")
		}
		if logs == nil {
			logs = []audit.AuditLog{}
		}
		return c.JSON(http.StatusOK, logs)
	}
}

func createAuditLogHandler(s audit.AuditLogStore) echo.HandlerFunc {
	type createReq struct {
		PolicyID      string `json:"policy_id"`
		Content       string `json:"content"`
		Model         string `json:"model,omitempty"`
		PromptVersion string `json:"prompt_version,omitempty"`
	}
	return func(c echo.Context) error {
		var req createReq
		if err := c.Bind(&req); err != nil {
			return jsonError(c, http.StatusBadRequest, "invalid json")
		}
		if req.PolicyID == "" || req.Content == "" {
			return jsonError(c, http.StatusBadRequest, "policy_id and content required")
		}

		summary, parseErr := gemarapkg.ParseAuditLog(req.Content)
		if parseErr != nil {
			slog.Warn("audit log YAML parse failed", "policy_id", req.PolicyID, "error", parseErr)
			return jsonError(c, http.StatusBadRequest, fmt.Sprintf("invalid audit log content: %v", parseErr))
		}

		a := audit.AuditLog{
			PolicyID:   req.PolicyID,
			Content:    req.Content,
			AuditStart: summary.AuditStart,
			AuditEnd:   summary.AuditEnd,
			Framework:  summary.Framework,
			Summary: fmt.Sprintf(
				`{"strengths":%d,"findings":%d,"gaps":%d,"observations":%d}`,
				summary.Strengths, summary.Findings, summary.Gaps, summary.Observations,
			),
			Model:         req.Model,
			PromptVersion: req.PromptVersion,
		}

		if err := s.InsertAuditLog(c.Request().Context(), a); err != nil {
			slog.Error("insert audit log failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "insert failed")
		}
		return c.JSON(http.StatusCreated, map[string]string{"status": "stored", "audit_id": a.AuditID})
	}
}

// createDraftAuditLogHandler handles POST /api/draft-audit-logs.
func createDraftAuditLogHandler(s audit.DraftAuditLogStore, pub EventPublisher) echo.HandlerFunc {
	type createReq struct {
		PolicyID       string `json:"policy_id"`
		Content        string `json:"content"`
		AgentReasoning string `json:"agent_reasoning,omitempty"`
		Model          string `json:"model,omitempty"`
		PromptVersion  string `json:"prompt_version,omitempty"`
	}
	return func(c echo.Context) error {
		var req createReq
		if err := c.Bind(&req); err != nil {
			return jsonError(c, http.StatusBadRequest, "invalid json")
		}
		if req.PolicyID == "" || req.Content == "" {
			return jsonError(c, http.StatusBadRequest, "policy_id and content required")
		}

		summary, parseErr := gemarapkg.ParseAuditLog(req.Content)
		if parseErr != nil {
			slog.Warn("draft audit log YAML parse failed", "policy_id", req.PolicyID, "error", parseErr)
			return jsonError(c, http.StatusBadRequest, fmt.Sprintf("invalid audit log content: %v", parseErr))
		}

		d := audit.DraftAuditLog{
			DraftID:        uuid.New().String(),
			PolicyID:       req.PolicyID,
			Content:        req.Content,
			AuditStart:     summary.AuditStart,
			AuditEnd:       summary.AuditEnd,
			Framework:      summary.Framework,
			AgentReasoning: req.AgentReasoning,
			Summary: fmt.Sprintf(
				`{"strengths":%d,"findings":%d,"gaps":%d,"observations":%d}`,
				summary.Strengths, summary.Findings, summary.Gaps, summary.Observations,
			),
			Model:         req.Model,
			PromptVersion: req.PromptVersion,
		}

		if err := s.InsertDraftAuditLog(c.Request().Context(), d); err != nil {
			slog.Error("insert draft audit log failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "insert failed")
		}
		if pub != nil {
			pub.PublishDraftAuditLog(d.DraftID, d.PolicyID, d.Summary)
		}
		return c.JSON(http.StatusCreated, map[string]string{"status": "drafted", "draft_id": d.DraftID})
	}
}

func listDraftAuditLogsHandler(s audit.DraftAuditLogStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		status := c.QueryParam("status")
		limit := consts.ClampLimit(0)
		if v := c.QueryParam("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				limit = consts.ClampLimit(n)
			}
		}
		drafts, err := s.ListDraftAuditLogs(c.Request().Context(), status, limit)
		if err != nil {
			slog.Error("list draft audit logs failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "query failed")
		}
		if drafts == nil {
			drafts = []audit.DraftAuditLog{}
		}
		return c.JSON(http.StatusOK, drafts)
	}
}

func getDraftAuditLogHandler(s audit.DraftAuditLogStore) echo.HandlerFunc {
	return func(c echo.Context) error {
		draftID := c.Param("id")
		if draftID == "" {
			return jsonError(c, http.StatusBadRequest, "missing draft id")
		}
		draft, err := s.GetDraftAuditLog(c.Request().Context(), draftID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return jsonError(c, http.StatusNotFound, "draft not found")
			}
			slog.Error("get draft audit log failed", "error", err, "id", draftID)
			return jsonError(c, http.StatusInternalServerError, "internal server error")
		}
		return c.JSON(http.StatusOK, draft)
	}
}

// updateDraftEditsHandler handles PATCH /api/draft-audit-logs/{id}.
// Persists reviewer type overrides and notes. Truncates notes to 2000 chars.
func updateDraftEditsHandler(s audit.DraftAuditLogStore) echo.HandlerFunc {
	type editEntry struct {
		TypeOverride string `json:"type_override,omitempty"`
		Note         string `json:"note,omitempty"`
	}
	type patchReq struct {
		ReviewerEdits map[string]editEntry `json:"reviewer_edits"`
	}
	return func(c echo.Context) error {
		draftID := c.Param("id")
		if draftID == "" {
			return jsonError(c, http.StatusBadRequest, "missing draft id")
		}

		var req patchReq
		if err := c.Bind(&req); err != nil {
			return jsonError(c, http.StatusBadRequest, "invalid json")
		}

		for k, v := range req.ReviewerEdits {
			if len(v.Note) > 2000 {
				v.Note = v.Note[:2000]
				req.ReviewerEdits[k] = v
			}
		}

		editsJSON, err := json.Marshal(req.ReviewerEdits)
		if err != nil {
			return jsonError(c, http.StatusInternalServerError, "failed to serialize edits")
		}

		if err := s.UpdateDraftEdits(c.Request().Context(), draftID, string(editsJSON)); err != nil {
			if errors.Is(err, audit.ErrDraftAlreadyPromoted) {
				return jsonError(c, http.StatusConflict, "draft already promoted")
			}
			if errors.Is(err, audit.ErrDraftNotFound) {
				return jsonError(c, http.StatusNotFound, "draft not found")
			}
			slog.Error("update draft edits failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "update failed")
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "saved"})
	}
}

// promoteAuditLogHandler handles POST /api/audit-logs/promote.
// Requires an authenticated admin session. The promoting user's identity
// becomes created_by on the official AuditLog.
func promoteAuditLogHandler(s audit.DraftAuditLogStore) echo.HandlerFunc {
	type promoteReq struct {
		DraftID string `json:"draft_id"`
	}
	return func(c echo.Context) error {
		var req promoteReq
		if err := c.Bind(&req); err != nil {
			return jsonError(c, http.StatusBadRequest, "invalid json")
		}
		if req.DraftID == "" {
			return jsonError(c, http.StatusBadRequest, "draft_id required")
		}

		reviewedBy := authSessionEmail(c.Request().Context())

		if err := s.PromoteDraftAuditLog(c.Request().Context(), req.DraftID, reviewedBy); err != nil {
			if errors.Is(err, audit.ErrDraftAlreadyPromoted) {
				return jsonError(c, http.StatusConflict, "draft already promoted")
			}
			slog.Error("promote draft failed", "error", err)
			return jsonError(c, http.StatusInternalServerError, "promote failed")
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "promoted", "draft_id": req.DraftID})
	}
}

func authSessionEmail(ctx context.Context) string {
	if id, ok := httputil.IdentityFrom(ctx); ok {
		return id
	}
	return "unknown"
}
