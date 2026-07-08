// SPDX-License-Identifier: Apache-2.0

package requirements

// NormalizeSlice returns an empty slice if the input is nil.
func NormalizeSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
