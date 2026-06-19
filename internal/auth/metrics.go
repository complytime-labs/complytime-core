// SPDX-License-Identifier: Apache-2.0

package auth

import "expvar"

var authRequestTotal = expvar.NewMap("auth_request_total")
