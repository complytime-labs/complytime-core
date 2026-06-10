// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"testing"
)

func TestNilBus_PublishEvidence_NoPanic(t *testing.T) {
	var b *Bus
	b.PublishEvidence("policy-1", 5)
}

func TestNilBus_PublishDraftAuditLog_NoPanic(t *testing.T) {
	var b *Bus
	b.PublishDraftAuditLog("draft-1", "policy-1", "summary")
}

func TestNilBus_SubscribeEvidence_NoPanic(t *testing.T) {
	var b *Bus
	sub, err := b.SubscribeEvidence(func(_ EvidenceEvent) {})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if sub != nil {
		t.Fatalf("expected nil subscription, got %v", sub)
	}
}

func TestNilBus_Close_NoPanic(t *testing.T) {
	var b *Bus
	b.Close()
}

func TestZeroValueBus_Close_NoPanic(t *testing.T) {
	b := &Bus{}
	b.Close()
}

func TestEvidenceSubjectNaming(t *testing.T) {
	want := "core.evidence"
	if SubjectEvidence != want {
		t.Fatalf("SubjectEvidence = %q, want %q", SubjectEvidence, want)
	}
	if SubjectPrefix != SubjectEvidence {
		t.Fatalf("SubjectPrefix = %q, want = SubjectEvidence = %q", SubjectPrefix, SubjectEvidence)
	}
}

func TestDraftSubjectNaming(t *testing.T) {
	want := "core.draft"
	if SubjectDraft != want {
		t.Fatalf("SubjectDraft = %q, want %q", SubjectDraft, want)
	}
}
