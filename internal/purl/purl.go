// SPDX-License-Identifier: Apache-2.0

package purl

import (
	"fmt"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

const prefix = "pkg:"

func IsPURL(id string) bool {
	return strings.HasPrefix(id, prefix)
}

func Validate(id string) error {
	if !IsPURL(id) {
		return nil
	}
	p, err := packageurl.FromString(id)
	if err != nil {
		return fmt.Errorf("invalid PURL %q: %w", id, err)
	}
	if err := p.Normalize(); err != nil {
		return fmt.Errorf("invalid PURL %q: %w", id, err)
	}
	return nil
}

func Normalize(id string) string {
	if !IsPURL(id) {
		return id
	}
	p, err := packageurl.FromString(id)
	if err != nil {
		return id
	}
	_ = p.Normalize()
	return p.ToString()
}
