package store

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestManagedCustodyPairComparisonRunsBeforeSigningAndInput(t *testing.T) {
	f := newManagedAuditFixture(t)
	audit, serve := f.open(t), f.serve.open(t)
	pair, err := NewManagedCustodyAuditServePair(audit, serve)
	if err != nil {
		t.Fatal(err)
	}
	before := testCoordination(t, f.serve.archive.f.coordinator)
	left, right := newManagedServeStream(t, f.serve.challenge), newManagedServeStream(t, f.serve.challenge)
	injected := errors.New("reviewed local scope changed")
	called := false
	_, err = pair.exchange(t.Context(), f.intent.ReplicaPeerID, f.serve.config.AuditorPeerID, left, right, func() error {
		called = true
		return injected
	})
	if !called || !errors.Is(err, injected) {
		t.Fatal("comparison was not enforced", err)
	}
	assertManagedPairNoInput(t, left, right)
	entries, err := os.ReadDir(f.config.ArtifactsPath)
	if err != nil || len(entries) != 1 || entries[0].Name() != "custody.lock" {
		t.Fatal("failed comparison signed or published a challenge", entries, err)
	}
	if state, err := f.journal.State(); err != nil || state.Sequence != 0 {
		t.Fatal("failed comparison committed an audit", state.Sequence, err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, f.serve.archive.f.coordinator)) {
		t.Fatal("failed comparison changed authority")
	}
}
