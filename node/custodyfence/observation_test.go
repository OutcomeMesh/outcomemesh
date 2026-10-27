package custodyfence

import (
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestIndependentObservationCannotForgetHistoricalPendingPin(t *testing.T) {
	s := testScope()
	before := initial(s)
	path := filepath.Join(t.TempDir(), "witness")
	w, err := Create(path, s, before.Position.HeadID, testKey(3))
	if err != nil {
		t.Fatal(err)
	}
	claim := signed(t, s, before.Position, Claim, types.Hash{}, types.Hash{})
	if _, err := w.Vote(claim); err != nil {
		t.Fatal(err)
	}
	_, retained, err := w.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	cert := certificate(t, claim, 3, 4, 5)
	if err := w.CommitAt(retained, cert); err != nil {
		t.Fatal(err)
	}
	bad := retained
	bad.PendingID = testHash(101)
	if err := w.CommitAt(bad, cert); err == nil {
		t.Fatal("exact extension ignored a contradictory retained pending pin")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if recovered, err := RecoverCommit(path, s, before.Position.HeadID, testKey(3), bad, cert); err == nil {
		_ = recovered.Close()
		t.Fatal("cold recovery ignored contradictory pending history")
	}
	recovered, err := RecoverCommit(path, s, before.Position.HeadID, testKey(3), retained, cert)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	id, _ := claim.ID()
	x, _, err := recovered.Snapshot()
	if err != nil || x.Position.Sequence != 1 || x.Position.HeadID != id || !x.ObligationHeld {
		t.Fatal(x, err)
	}
}
