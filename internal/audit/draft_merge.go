// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type reviewerEdit struct {
	TypeOverride string `json:"type_override,omitempty"`
	Note         string `json:"note,omitempty"`
}

var typePattern = regexp.MustCompile(`(?m)^(\s+type:\s*)(.+)$`)

// MergeReviewerEdits applies reviewer type overrides and notes to audit log YAML content.
// Returns the merged content or the original if editsJSON is empty/unparseable.
func MergeReviewerEdits(content string, editsJSON string) (string, error) {
	if editsJSON == "" || editsJSON == "{}" {
		return content, nil
	}

	var edits map[string]reviewerEdit
	if err := json.Unmarshal([]byte(editsJSON), &edits); err != nil {
		return content, fmt.Errorf("parse reviewer_edits: %w", err)
	}
	if len(edits) == 0 {
		return content, nil
	}

	blocks := strings.Split(content, "\n  - id: ")
	if len(blocks) < 2 {
		return content, nil
	}

	for i := 1; i < len(blocks); i++ {
		lines := strings.SplitN(blocks[i], "\n", 2)
		resultID := strings.TrimSpace(lines[0])
		edit, ok := edits[resultID]
		if !ok {
			continue
		}

		block := blocks[i]
		if edit.TypeOverride != "" {
			block = typePattern.ReplaceAllStringFunc(block, func(match string) string {
				sub := typePattern.FindStringSubmatch(match)
				if len(sub) == 3 {
					return sub[1] + edit.TypeOverride
				}
				return match
			})
		}

		if edit.Note != "" {
			if !strings.Contains(block, "reviewer-note:") {
				insertIdx := strings.Index(block, "\n  - id:")
				if insertIdx < 0 {
					block = block + "\n    reviewer-note: >-\n      " + edit.Note
				} else {
					block = block[:insertIdx] + "\n    reviewer-note: >-\n      " + edit.Note + block[insertIdx:]
				}
			}
		}

		blocks[i] = block
	}

	return blocks[0] + "\n  - id: " + strings.Join(blocks[1:], "\n  - id: "), nil
}
