package gateway

import (
	"net/http"

	"github.com/complytime-labs/complytime-core/internal/authz"
	"github.com/complytime-labs/complytime-core/internal/locker"
)

// SubjectIDExtractor is Chi middleware that reads X-Subject-ID from the
// request header and sets it in context for the Cedar authorization
// middleware. Required for POST /api/ingest so Cedar can evaluate
// publisher trust for the specific subject before the handler runs.
//
// Routes that don't need a subject ID (admin, job status, healthz)
// are handled by the Cedar middleware's own fallback logic.
func SubjectIDExtractor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subjectID := r.Header.Get(HeaderSubjectID)
		if subjectID != "" {
			if err := locker.ValidateSubjectID(subjectID); err != nil {
				http.Error(w, "Invalid X-Subject-ID", http.StatusBadRequest)
				return
			}
			ctx := authz.SetSubjectIDContext(r.Context(), subjectID)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}
