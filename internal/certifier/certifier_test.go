// SPDX-License-Identifier: Apache-2.0

package certifier_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/certifier"
	"github.com/stretchr/testify/assert"
)

func TestTrustSignal_Valid(t *testing.T) {
	signal := certifier.TrustSignal{
		Layer:     "quality",
		CheckName: "schema",
		Result:    certifier.ResultPass,
		Reason:    "all required fields present",
	}

	assert.Equal(t, "quality", signal.Layer)
	assert.Equal(t, "schema", signal.CheckName)
	assert.Equal(t, certifier.ResultPass, signal.Result)
	assert.Equal(t, "all required fields present", signal.Reason)
}

func TestResult_Constants(t *testing.T) {
	assert.Equal(t, certifier.Result("pass"), certifier.ResultPass)
	assert.Equal(t, certifier.Result("fail"), certifier.ResultFail)
	assert.Equal(t, certifier.Result("skip"), certifier.ResultSkip)
	assert.Equal(t, certifier.Result("error"), certifier.ResultError)
}

func TestResult_ToVerdict(t *testing.T) {
	assert.Equal(t, certifier.VerdictPass, certifier.ResultPass.ToVerdict())
	assert.Equal(t, certifier.VerdictFail, certifier.ResultFail.ToVerdict())
	assert.Equal(t, certifier.VerdictSkip, certifier.ResultSkip.ToVerdict())
	assert.Equal(t, certifier.VerdictError, certifier.ResultError.ToVerdict())

	// Test unknown result maps to VerdictError
	unknownResult := certifier.Result("unknown")
	assert.Equal(t, certifier.VerdictError, unknownResult.ToVerdict())
}
