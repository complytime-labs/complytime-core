// SPDX-License-Identifier: Apache-2.0

package auth

import "expvar"

var (
	authRequestTotal    = expvar.NewMap("auth_request_total")
	authUserUpsertTotal = expvar.NewInt("auth_user_upsert_total")
)
