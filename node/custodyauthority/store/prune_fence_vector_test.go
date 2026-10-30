package store

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func fixedFencedPrunePlan(t testing.TB) ScheduledPrunePlan {
	t.Helper()
	old, err := DecodeScheduledPrunePlan(fixedScheduledPrunePlan(t).Plan)
	if err != nil {
		t.Fatal(err)
	}
	p, err := old.WithFence(pruneFencePolicy())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPruneFencePlanAndRequestVersions(t *testing.T) {
	if PrunePrepared != 1 || PruneAdmitted != 2 || PruneStarted != 3 || PruneSucceeded != 4 || PruneCancelled != 5 {
		t.Fatal("legacy persisted stage numbers changed")
	}
	p := fixedFencedPrunePlan(t)
	raw, _ := p.CanonicalBytes()
	r, _ := p.Request.CanonicalBytes()
	if raw[9] != 1 || r[9] != 3 {
		t.Fatal("wrong protocol versions")
	}
	if _, err := DecodeScheduledPrunePlan(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodePruneRequest(r); err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{raw, r} {
		bad := bytes.Clone(input)
		bad[9]--
		if input[9] == 1 {
			if _, err := DecodeScheduledPrunePlan(bad); err == nil {
				t.Fatal("downgraded fenced plan")
			}
		} else {
			if _, err := DecodePruneRequest(bad); err == nil {
				t.Fatal("downgraded fenced request")
			}
		}
	}
	bad := p
	bad.Request.FencePolicyID[0] ^= 1
	if _, err := bad.ID(); err == nil {
		t.Fatal("substituted policy ID")
	}
	bad = p
	bad.FencePolicy = nil
	if _, err := bad.ID(); err == nil {
		t.Fatal("stripped required policy")
	}
	for _, key := range [][32]byte{p.Replicas[0].Assignment.ReplicaPublicKey, p.OriginalPolicy.TrustedAttestors[0]} {
		bad = p
		policy := *p.FencePolicy
		policy.Witnesses = append([][32]byte(nil), policy.Witnesses...)
		policy.Guard = key
		bad.FencePolicy = &policy
		bad.Request.FencePolicyID, _ = policy.ID()
		if _, err := bad.ID(); err == nil {
			t.Fatal("participant became independent guard")
		}
	}
	id, _ := p.ID()
	rid, _ := p.Request.ID()
	if id.String() != "10edb968af695e29333e04e3f91645e37cfdefeb018245b8d214d1f0a9bf5c68" || len(raw) != 8284 || fmt.Sprintf("%x", sha256.Sum256(raw)) != "1c363b2acac29c0809c81a266e9294ff0f56c43855ad8d624a0e296da3e998ba" {
		t.Fatal("fenced plan vector changed")
	}
	if rid.String() != "e0096185e0660af653b3fb6f79ed2661dff866f3bb71a65e4570c6d24be4b070" || len(r) != 514 || fmt.Sprintf("%x", sha256.Sum256(r)) != "7b696b055b2f599c54cebef307793d370120f3c6f4288b8bf8fab1bfc6c7af34" {
		t.Fatal("fenced request vector changed")
	}
}
