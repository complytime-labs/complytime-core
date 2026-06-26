// SPDX-License-Identifier: Apache-2.0

package targetid

import (
	"fmt"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

const purlPrefix = "pkg:"

func IsPURL(id string) bool {
	return strings.HasPrefix(id, purlPrefix)
}

func Validate(id string) error {
	if IsPURL(id) {
		return validatePURL(id)
	}
	return nil
}

func Normalize(id string) string {
	if IsPURL(id) {
		return normalizePURL(id)
	}
	return id
}

func validatePURL(id string) error {
	p, err := packageurl.FromString(id)
	if err != nil {
		return fmt.Errorf("invalid PURL %q: %w", id, err)
	}
	if err := p.Normalize(); err != nil {
		return fmt.Errorf("invalid PURL %q: %w", id, err)
	}
	return nil
}

func normalizePURL(id string) string {
	p, err := packageurl.FromString(id)
	if err != nil {
		return id
	}
	_ = p.Normalize()
	return p.ToString()
}
