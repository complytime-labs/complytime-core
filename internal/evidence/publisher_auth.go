// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"strings"

	"github.com/complytime-labs/complytime-core/internal/requirements"
)

// IsPublisherAuthorized checks whether a publisher identity (issuer + sub)
// matches any of the trusted publisher entries for a target.
//
// Matching rules:
//   - Issuer must match exactly.
//   - SubPattern supports a trailing '*' wildcard (prefix match);
//     otherwise exact match is required.
//
// Returns true if any trusted publisher matches.
func IsPublisherAuthorized(publisherIssuer, publisherSub string, trustedPublishers []requirements.TrustedPublisherRow) bool {
	for _, tp := range trustedPublishers {
		if tp.Issuer != publisherIssuer {
			continue
		}
		if matchSubPattern(tp.SubPattern, publisherSub) {
			return true
		}
	}
	return false
}

// matchSubPattern matches a subject against a pattern.
// If the pattern ends with '*', it performs a prefix match on the
// portion before the '*'. Otherwise it requires an exact match.
func matchSubPattern(pattern, subject string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(subject, prefix)
	}
	return pattern == subject
}
