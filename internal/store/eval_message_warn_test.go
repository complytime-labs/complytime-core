// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/complytime-labs/complytime-core/internal/consts"
	"github.com/complytime-labs/complytime-core/internal/evidence"
)

func TestWarnEvalMessageIfLarge_EmitsWhenOverThreshold(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })

	msg := strings.Repeat("a", consts.EvalMessageWarnBytes+1)
	warnEvalMessageIfLarge(evidence.EvidenceRecord{
		PolicyID:    "pol",
		EvidenceID:  "ev",
		EvalMessage: msg,
	})

	out := buf.String()
	if !strings.Contains(out, "evidence eval_message exceeds recommended summary size") {
		t.Fatalf("expected warn log, got: %s", out)
	}
	var fields map[string]any
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	if int(fields["bytes"].(float64)) != len(msg) {
		t.Fatalf("bytes field: %v", fields["bytes"])
	}
}

func TestWarnEvalMessageIfLarge_SilentUnderThreshold(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })

	warnEvalMessageIfLarge(evidence.EvidenceRecord{
		PolicyID:    "pol",
		EvidenceID:  "ev",
		EvalMessage: strings.Repeat("b", consts.EvalMessageWarnBytes),
	})
	if buf.Len() != 0 {
		t.Fatalf("unexpected log: %s", buf.String())
	}
}
