//go:build linux || darwin

package prunefence_test

import (
	"path/filepath"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyguard"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

func TestPruneServiceRevocationAtOriginalGuardSurvivesRestart(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "guard")
	g, err := custodyguard.Create(root, custodyguard.Config{Subjects: [][32]byte{f.Public(90)}, Limit: 4, Revoker: f.Public(93)})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	v := servicePolicy(t)
	v.Service.Guard = g.Identity().PublicKey
	e, err := v.Service.Sign(f.Key(91))
	if err != nil {
		t.Fatal(err)
	}
	v.Service = &e
	_, permit := servicePermit(t, v, g)
	id := g.Identity()
	r, err := (guardwire.Revocation{GuardID: id.ID(), Subject: f.Public(90), Authority: f.Public(93), ReasonID: f.Hash("revocation")}).Sign(f.Key(93))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Revoke(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	enrollment, _ := e.ID()
	if err := permit.ConsumeProtected(binding().OperationID, binding().StoragePairID, enrollment); err == nil {
		t.Fatal("revoked after witness claim, before storage consumption")
	}
	position, err := g.Position()
	if err != nil {
		t.Fatal(err)
	}
	if position.Sequence != 1 {
		t.Fatal("refusal appended a choice")
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	cold, err := custodyguard.Open(root, id, position, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	_, copied := servicePermit(t, v, cold)
	if err := copied.ConsumeProtected(binding().OperationID, binding().StoragePairID, enrollment); err == nil {
		t.Fatal("copied key bypassed cold revocation")
	}
	if _, err := copied.Seal(f.Hash("effect")); err == nil {
		t.Fatal("refusal sealed effect")
	}
}
