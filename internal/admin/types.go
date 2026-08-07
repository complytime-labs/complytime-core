package admin

import "github.com/complytime-labs/complytime-core/internal/trust"

// RegisterRequest is the NATS request payload for subject registration.
type RegisterRequest struct {
	SubjectID        string `json:"subjectId"`
	RegistrantIssuer string `json:"registrantIssuer"`
	RegistrantSub    string `json:"registrantSub"`
}

// RegisterResponse is the NATS response payload for subject registration.
type RegisterResponse struct {
	VerifierKey string `json:"verifierKey,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SealTrustRequest is the NATS request payload for sealing a trust modification receipt.
type SealTrustRequest struct {
	SubjectID         string             `json:"subjectId"`
	TrustedPublishers []trust.TrustEntry `json:"trustedPublishers"`
	OperatorIssuer    string             `json:"operatorIssuer"`
	OperatorSub       string             `json:"operatorSub"`
}

// SealTrustResponse is the NATS response payload for sealing a trust modification receipt.
type SealTrustResponse struct {
	LogIndex uint64 `json:"logIndex,omitempty"`
	Error    string `json:"error,omitempty"`
}
