package authn

import "strings"

// ExtractClaimByPath walks a dot-separated path into a claims map and returns
// the leaf value as a string slice. Non-string array elements are skipped.
// Returns nil if the path is empty, missing, or the leaf is not an array.
func ExtractClaimByPath(claims map[string]any, dotPath string) []string {
	if dotPath == "" {
		return nil
	}

	segments := strings.Split(dotPath, ".")
	var current any = claims

	for _, seg := range segments {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[seg]
		if !ok {
			return nil
		}
	}

	arr, ok := current.([]any)
	if !ok {
		return nil
	}

	var out []string
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
