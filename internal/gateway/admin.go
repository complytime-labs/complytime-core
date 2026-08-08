package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/complytime-labs/complytime-core/internal/admin"
	"github.com/complytime-labs/complytime-core/internal/authz"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
	"github.com/complytime-labs/complytime-core/internal/subjects"
	"github.com/complytime-labs/complytime-core/internal/trust"
)

const adminRequestTimeout = 10 * time.Second

// RegisterSubject handles POST /admin/subjects.
func (h *GatewayHandler) RegisterSubject(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		SubjectID         string             `json:"subjectId"`
		TrustedPublishers []trust.TrustEntry `json:"trustedPublishers"`
		ScannerJWK        *struct {
			JWK      json.RawMessage `json:"jwk"`
			NotAfter time.Time       `json:"not_after"`
		} `json:"scannerJwk"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.SubjectID == "" {
		http.Error(w, "subjectId is required", http.StatusBadRequest)
		return
	}
	if err := subjects.ValidateSubjectID(body.SubjectID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.TrustedPublishers) == 0 {
		http.Error(w, "at least one trusted publisher required", http.StatusBadRequest)
		return
	}

	// Pre-validate scanner JWK before any writes.
	var scannerIssuerID string
	var scannerParsedKey jwk.Key
	if body.ScannerJWK != nil {
		for _, tp := range body.TrustedPublishers {
			if tp.Issuer == tp.Sub {
				scannerIssuerID = tp.Issuer
				break
			}
		}
		if scannerIssuerID == "" {
			http.Error(w, "scannerJwk requires a trusted publisher with issuer == sub (scanner identity convention)", http.StatusBadRequest)
			return
		}
		pk, err := jwk.ParseKey(body.ScannerJWK.JWK)
		if err != nil {
			http.Error(w, "invalid scanner JWK: cannot parse key", http.StatusBadRequest)
			return
		}
		var dParam []byte
		if err := pk.Get("d", &dParam); err == nil {
			http.Error(w, "invalid scanner JWK: must be a public key (contains private key material)", http.StatusBadRequest)
			return
		}
		scannerParsedKey = pk
	}
	_ = scannerParsedKey // parsed and validated above; JWK bytes used for storage

	// Validate all trusted publisher identities before any writes.
	if h.registry != nil {
		for _, tp := range body.TrustedPublishers {
			if err := h.registry.ValidateTrustEntry(tp.Issuer, tp.Sub); err != nil {
				http.Error(w, fmt.Sprintf("invalid trusted publisher {issuer: %q, sub: %q}: %v", tp.Issuer, tp.Sub, err), http.StatusBadRequest)
				return
			}
		}
	}

	issuer, sub := authz.GetPublisher(ctx)

	natsCtx, cancel := context.WithTimeout(ctx, adminRequestTimeout)
	defer cancel()

	natReq := admin.RegisterRequest{
		SubjectID:        body.SubjectID,
		RegistrantIssuer: issuer,
		RegistrantSub:    sub,
	}
	payload, err := json.Marshal(natReq)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	msg, err := h.nc.RequestWithContext(natsCtx, natsinfra.SubjectAdminRegisterSubject, payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("locker request failed: %v", err), http.StatusInternalServerError)
		return
	}
	var natResp admin.RegisterResponse
	if err := json.Unmarshal(msg.Data, &natResp); err != nil || natResp.Error != "" {
		errMsg := natResp.Error
		if errMsg == "" {
			errMsg = err.Error()
		}
		http.Error(w, fmt.Sprintf("registration failed: %s", errMsg), http.StatusInternalServerError)
		return
	}

	logSubjectID := strings.ReplaceAll(strings.ReplaceAll(body.SubjectID, "\n", ""), "\r", "")
	if err := h.trustStore.SetPublisherTrust(ctx, body.SubjectID, body.TrustedPublishers); err != nil {
		slog.Error("registration partial failure: trust write failed after ledger creation",
			"subjectId", logSubjectID, "error", err)
		http.Error(w, "failed to set publisher trust", http.StatusInternalServerError)
		return
	}
	if err := h.trustStore.RegisterSubject(ctx, body.SubjectID); err != nil {
		slog.Error("registration partial failure: registry write failed after trust set",
			"subjectId", logSubjectID, "error", err)
		http.Error(w, "failed to register subject", http.StatusInternalServerError)
		return
	}

	if body.ScannerJWK != nil {
		logIssuerID := strings.ReplaceAll(strings.ReplaceAll(scannerIssuerID, "\n", ""), "\r", "")
		if err := h.trustStore.StoreJWK(ctx, scannerIssuerID, body.ScannerJWK.JWK, body.ScannerJWK.NotAfter); err != nil {
			logErr := strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\n", ""), "\r", "")
			slog.Error("failed to store scanner JWK",
				"subjectId", logSubjectID, "issuerID", logIssuerID, "error", logErr)
			http.Error(w, "failed to store scanner JWK", http.StatusInternalServerError)
			return
		}
		slog.Info("stored scanner JWK", "subjectId", logSubjectID, "issuerID", logIssuerID,
			"notAfter", body.ScannerJWK.NotAfter)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"subjectId": body.SubjectID})
}

// ModifyTrust handles PUT /admin/subjects/{subjectId}/trust.
func (h *GatewayHandler) ModifyTrust(w http.ResponseWriter, r *http.Request, subjectID string) {
	ctx := r.Context()

	if err := subjects.ValidateSubjectID(subjectID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	logSubjectID := strings.ReplaceAll(strings.ReplaceAll(subjectID, "\n", ""), "\r", "")

	exists, err := h.trustStore.SubjectExists(ctx, subjectID)
	if err != nil {
		http.Error(w, "failed to check subject existence", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, fmt.Sprintf("subject %s not found", subjectID), http.StatusNotFound)
		return
	}

	var body struct {
		TrustedPublishers []trust.TrustEntry `json:"trustedPublishers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate all trusted publisher identities before any writes.
	if h.registry != nil {
		for _, tp := range body.TrustedPublishers {
			if err := h.registry.ValidateTrustEntry(tp.Issuer, tp.Sub); err != nil {
				http.Error(w, fmt.Sprintf("invalid trusted publisher: %v", err), http.StatusBadRequest)
				return
			}
		}
	}

	if err := h.trustStore.SetPublisherTrust(ctx, subjectID, body.TrustedPublishers); err != nil {
		http.Error(w, "failed to update trust", http.StatusInternalServerError)
		return
	}

	issuer, sub := authz.GetPublisher(ctx)
	sealReq := admin.SealTrustRequest{
		SubjectID:         subjectID,
		TrustedPublishers: body.TrustedPublishers,
		OperatorIssuer:    issuer,
		OperatorSub:       sub,
	}
	sealPayload, err := json.Marshal(sealReq)
	if err != nil {
		slog.Error("failed to marshal trust seal request", "subjectId", logSubjectID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sealCtx, sealCancel := context.WithTimeout(ctx, adminRequestTimeout)
	defer sealCancel()
	sealMsg, err := h.nc.RequestWithContext(sealCtx, natsinfra.SubjectAdminSealTrust, sealPayload)
	if err != nil {
		slog.Warn("failed to seal trust modification receipt",
			"subjectId", logSubjectID, "error", err)
	} else {
		var sealResp admin.SealTrustResponse
		if err := json.Unmarshal(sealMsg.Data, &sealResp); err != nil || sealResp.Error != "" {
			slog.Warn("trust modification receipt seal error",
				"subjectId", logSubjectID, "error", sealResp.Error)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"subjectId": subjectID})
}
