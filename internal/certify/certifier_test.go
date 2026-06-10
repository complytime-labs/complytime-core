// SPDX-License-Identifier: Apache-2.0

package certify_test

import (
	"testing"

	"github.com/complytime-labs/complytime-core/internal/certify"
	"github.com/stretchr/testify/assert"
)

func TestTrustSignal_Valid(t *testing.T) {
	signal := certify.TrustSignal{
		Layer:     "quality",
		CheckName: "schema",
		Result:    certify.ResultPass,
		Reason:    "all required fields present",
	}

	assert.Equal(t, "quality", signal.Layer)
	assert.Equal(t, "schema", signal.CheckName)
	assert.Equal(t, certify.ResultPass, signal.Result)
	assert.Equal(t, "all required fields present", signal.Reason)
}

func TestResult_Constants(t *testing.T) {
	assert.Equal(t, certify.Result("pass"), certify.ResultPass)
	assert.Equal(t, certify.Result("fail"), certify.ResultFail)
	assert.Equal(t, certify.Result("skip"), certify.ResultSkip)
	assert.Equal(t, certify.Result("error"), certify.ResultError)
}

func TestResult_ToVerdict(t *testing.T) {
	assert.Equal(t, certify.VerdictPass, certify.ResultPass.ToVerdict())
	assert.Equal(t, certify.VerdictFail, certify.ResultFail.ToVerdict())
	assert.Equal(t, certify.VerdictSkip, certify.ResultSkip.ToVerdict())
	assert.Equal(t, certify.VerdictError, certify.ResultError.ToVerdict())

	// Test unknown result maps to VerdictError
	unknownResult := certify.Result("unknown")
	assert.Equal(t, certify.VerdictError, unknownResult.ToVerdict())
}
