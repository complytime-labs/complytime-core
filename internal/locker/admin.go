package locker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	natsgo "github.com/nats-io/nats.go"

	"github.com/complytime-labs/complytime-core/internal/admin"
	eventspkg "github.com/complytime-labs/complytime-core/internal/events"
	"github.com/complytime-labs/complytime-core/internal/gateway/receipt"
	natsinfra "github.com/complytime-labs/complytime-core/internal/nats"
)

// AdminSubscriber handles NATS request-reply for locker admin operations.
type AdminSubscriber struct {
	nc     *natsgo.Conn
	locker *Locker
	events *eventspkg.EventPublisher
}

// NewAdminSubscriber creates a new AdminSubscriber.
func NewAdminSubscriber(nc *natsgo.Conn, locker *Locker, events *eventspkg.EventPublisher) *AdminSubscriber {
	return &AdminSubscriber{nc: nc, locker: locker, events: events}
}

// Start subscribes to admin subjects and blocks until ctx is cancelled.
func (s *AdminSubscriber) Start(ctx context.Context) error {
	regSub, err := s.nc.Subscribe(natsinfra.SubjectAdminRegisterSubject, s.handleRegister)
	if err != nil {
		return fmt.Errorf("subscribing to admin register: %w", err)
	}
	trustSub, err := s.nc.Subscribe(natsinfra.SubjectAdminSealTrust, s.handleSealTrust)
	if err != nil {
		return fmt.Errorf("subscribing to admin seal-trust: %w", err)
	}
	slog.Info("admin subscriber started",
		"registerSubject", natsinfra.SubjectAdminRegisterSubject,
		"sealTrustSubject", natsinfra.SubjectAdminSealTrust)
	<-ctx.Done()
	_ = regSub.Drain()
	return trustSub.Drain()
}

func (s *AdminSubscriber) handleRegister(msg *natsgo.Msg) {
	var req admin.RegisterRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.respond(msg, admin.RegisterResponse{Error: "invalid request payload"})
		return
	}

	ledger, err := s.locker.CreateLedger(context.Background(), req.SubjectID)
	if err != nil {
		s.respond(msg, admin.RegisterResponse{Error: fmt.Sprintf("creating ledger: %v", err)})
		return
	}

	regData, _ := json.Marshal(map[string]string{
		"subjectId":        req.SubjectID,
		"registrantIssuer": req.RegistrantIssuer,
		"registrantSub":    req.RegistrantSub,
	})
	publisher := receipt.Publisher{
		Issuer: req.RegistrantIssuer,
		Sub:    req.RegistrantSub,
	}
	receiptBytes, err := receipt.Wrap(regData, publisher, req.SubjectID, "subject-registration")
	if err != nil {
		s.respond(msg, admin.RegisterResponse{Error: fmt.Sprintf("wrapping receipt: %v", err)})
		return
	}
	if _, err := ledger.Seal(context.Background(), receiptBytes); err != nil {
		s.respond(msg, admin.RegisterResponse{Error: fmt.Sprintf("sealing receipt: %v", err)})
		return
	}

	if err := s.events.PublishSubjectRegistered(context.Background(), req.SubjectID); err != nil {
		slog.Warn("failed to publish subject.registered event", "error", err, "subjectId", SanitizeLogValue(req.SubjectID))
	}

	slog.Info("subject registered via admin subscriber", "subjectId", SanitizeLogValue(req.SubjectID))
	s.respond(msg, admin.RegisterResponse{VerifierKey: ledger.VerifierKey()})
}

func (s *AdminSubscriber) handleSealTrust(msg *natsgo.Msg) {
	var req admin.SealTrustRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.respond(msg, admin.SealTrustResponse{Error: "invalid request payload"})
		return
	}

	ledger, ok := s.locker.GetLedger(req.SubjectID)
	if !ok {
		s.respond(msg, admin.SealTrustResponse{Error: fmt.Sprintf("ledger not found for %s", req.SubjectID)})
		return
	}

	trustData, _ := json.Marshal(map[string]any{
		"subjectId":         req.SubjectID,
		"trustedPublishers": req.TrustedPublishers,
		"operatorIssuer":    req.OperatorIssuer,
		"operatorSub":       req.OperatorSub,
	})
	publisher := receipt.Publisher{
		Issuer: req.OperatorIssuer,
		Sub:    req.OperatorSub,
	}
	receiptBytes, err := receipt.Wrap(trustData, publisher, req.SubjectID, "trust-modification")
	if err != nil {
		s.respond(msg, admin.SealTrustResponse{Error: fmt.Sprintf("wrapping receipt: %v", err)})
		return
	}
	logIndex, err := ledger.Seal(context.Background(), receiptBytes)
	if err != nil {
		s.respond(msg, admin.SealTrustResponse{Error: fmt.Sprintf("sealing receipt: %v", err)})
		return
	}

	slog.Info("trust modification sealed", "subjectId", SanitizeLogValue(req.SubjectID), "logIndex", logIndex)
	s.respond(msg, admin.SealTrustResponse{LogIndex: logIndex})
}

func (s *AdminSubscriber) respond(msg *natsgo.Msg, resp any) {
	data, _ := json.Marshal(resp)
	if err := msg.Respond(data); err != nil {
		slog.Warn("failed to send admin reply", "error", err)
	}
}
