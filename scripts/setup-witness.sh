#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate witness and log key material for local development.
# Outputs to deploy/compose/witness-config/

set -euo pipefail

OUTDIR="${1:-deploy/compose/witness-config}"
mkdir -p "$OUTDIR"

if [[ -f "$OUTDIR/witness-signer.key" ]]; then
    echo "Witness keys already exist in $OUTDIR — skipping generation."
    echo "Delete $OUTDIR and run 'docker compose down -v' to regenerate."
    exit 0
fi

# Build a small key generator
TMPGEN=$(mktemp -d)
trap 'rm -rf "$TMPGEN"' EXIT

cat > "$TMPGEN/main.go" << 'GENEOF'
package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/mod/sumdb/note"
)

func main() {
	name := os.Args[1]
	skey, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(skey)
	fmt.Println(vkey)
}
GENEOF

cat > "$TMPGEN/go.mod" << 'MODEOF'
module keygen
go 1.23
require golang.org/x/mod v0.37.0
MODEOF

cd "$TMPGEN" && go mod tidy && cd - > /dev/null

# Generate witness key pair
echo "Generating witness key pair..."
WITKEYS=$(cd "$TMPGEN" && go run main.go "complytime-witness")
WIT_SKEY=$(echo "$WITKEYS" | head -1)
WIT_VKEY=$(echo "$WITKEYS" | tail -1)

echo "$WIT_SKEY" > "$OUTDIR/witness-signer.key"
echo "$WIT_VKEY" > "$OUTDIR/witness-verifier.key"
chmod 644 "$OUTDIR/witness-signer.key"

# Generate log signer key pair (pre-generate so witness can be provisioned)
echo "Generating log signer key pair..."
LOGKEYS=$(cd "$TMPGEN" && go run main.go "tessera-log")
LOG_SKEY=$(echo "$LOGKEYS" | head -1)
LOG_VKEY=$(echo "$LOGKEYS" | tail -1)

mkdir -p "$OUTDIR/log-signer"
echo "$LOG_SKEY" > "$OUTDIR/log-signer/.signer.key"
echo "$LOG_VKEY" >> "$OUTDIR/log-signer/.signer.key"
chmod 644 "$OUTDIR/log-signer/.signer.key"

# Write witness policy for the gateway (Sigsum format)
cat > "$OUTDIR/witness-policy" << POLICYEOF
witness complytime-witness ${WIT_VKEY} http://witness:8080/
group devgroup all complytime-witness
quorum devgroup
POLICYEOF

# Write additional logs config for the omniwitness
cat > "$OUTDIR/additional-logs.yaml" << LOGSEOF
Logs:
  - Origin: tessera-log
    URL: http://ingest:8081
    PublicKey: ${LOG_VKEY}
    Feeder: tiles
LOGSEOF

echo ""
echo "Generated in $OUTDIR:"
echo "  witness-signer.key    — witness private key"
echo "  witness-verifier.key  — witness public key"
echo "  witness-policy        — Sigsum policy for gateway"
echo "  log-signer/.signer.key — log signer key pair"
echo "  additional-logs.yaml  — log config for omniwitness"
echo ""
echo "Log verifier key: $LOG_VKEY"
