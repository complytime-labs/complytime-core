// SPDX-License-Identifier: Apache-2.0

package targetid

import (
	"fmt"
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	packageurl "github.com/package-url/packageurl-go"
)

const (
	purlPrefix = "pkg:"
	cpePrefix  = "cpe:"
)

func IsPURL(id string) bool {
	return strings.HasPrefix(id, purlPrefix)
}

func IsCPE(id string) bool {
	return strings.HasPrefix(id, cpePrefix)
}

func Validate(id string) error {
	switch {
	case IsPURL(id):
		return validatePURL(id)
	case IsCPE(id):
		return validateCPE(id)
	default:
		return nil
	}
}

func Normalize(id string) string {
	switch {
	case IsPURL(id):
		return normalizePURL(id)
	case IsCPE(id):
		return normalizeCPE(id)
	default:
		return id
	}
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

func validateCPE(id string) error {
	_, err := naming.UnbindFS(id)
	if err != nil {
		return fmt.Errorf("invalid CPE %q: %w", id, err)
	}
	return nil
}

func normalizeCPE(id string) string {
	wfn, err := naming.UnbindFS(id)
	if err != nil {
		return id
	}
	return naming.BindToFS(wfn)
}
