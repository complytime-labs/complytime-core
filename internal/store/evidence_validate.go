// SPDX-License-Identifier: Apache-2.0

package store

import "github.com/complytime-labs/complytime-core/internal/evidence"

func validateEvidenceRecordEnums(rec EvidenceRecord, row int) []string {
	return evidence.ValidateEvidenceRecordEnums(rec, row)
}
