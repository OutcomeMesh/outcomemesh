//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	fixture "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func assertUnavailableEvidence(t *testing.T, x *protectedFixture) {
	t.Helper()
	for _, v := range []struct {
		o    *Owner
		d    wire.Descriptor
		kind uint8
	}{{x.a, x.ad, v2.ProtectedReadAcceptance}, {x.a, x.ad, v2.ProtectedReadServe}, {x.b, x.bd, v2.ProtectedReadServe}, {x.b, x.bd, v2.ProtectedReadAcceptance}, {x.a, x.ad, v2.ProtectedReadResult}} {
		before, _ := v.o.Position()
		if _, _, _, e := protectedCall(t, v.o, v.d, v2.ProtectedCommand{Kind: v.kind, Admission: x.binding, Now: 1}, fmt.Sprint("absent", v.kind)); e == nil {
			t.Fatal("absent/wrong role read succeeded")
		}
		after, _ := v.o.Position()
		if before != after {
			t.Fatal("refusal consumed position")
		}
	}
}
func assertRecoveredEvidence(t *testing.T, x *protectedFixture, b v2.Bundle, accepted, aServe, bServe []byte) {
	t.Helper()
	result, _ := b.Result.CanonicalBytes()
	account := x.state.Snapshot()
	for i, side := range []struct {
		o     **Owner
		root  string
		d     wire.Descriptor
		want  [][]byte
		kinds []uint8
	}{{&x.a, x.aroot, x.ad, [][]byte{accepted, aServe}, []uint8{v2.ProtectedReadAcceptance, v2.ProtectedReadServe}}, {&x.b, x.broot, x.bd, [][]byte{result, bServe}, []uint8{v2.ProtectedReadResult, v2.ProtectedReadServe}}} {
		before, e := (*side.o).currentExecutionSource()
		fixture.Require(t, e)
		// Cold restart, no live execution session or current approval window.
		pos, pending := (*side.o).Position()
		if pending {
			t.Fatal("unexpected pending runtime")
		}
		fixture.Require(t, (*side.o).Close())
		id, _ := side.d.ID()
		*side.o, e = Open(side.root, id, pos, nil)
		fixture.Require(t, e)
		(*side.o).SetGuard(x.guard)
		(*side.o).clock = func() uint64 { return b.Result.Entry.Record.Proof.RespondedAt + 100000 }
		for j, kind := range side.kinds {
			got := mustProtected(t, *side.o, side.d, v2.ProtectedCommand{Kind: kind, Admission: x.binding, Now: 1}, fmt.Sprintf("recover-%d-%d", i, j))
			if !bytes.Equal(got, side.want[j]) {
				t.Fatal("historical receipt changed", kind)
			}
			got = mustProtected(t, *side.o, side.d, v2.ProtectedCommand{Kind: kind, Admission: x.binding, Now: 1}, fmt.Sprintf("recover-again-%d-%d", i, j))
			if !bytes.Equal(got, side.want[j]) {
				t.Fatal("second read changed receipt")
			}
		}
		after, e := (*side.o).currentExecutionSource()
		fixture.Require(t, e)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("reading changed source")
		}
		kind := uint8(v2.ProtectedAccept)
		if i == 1 {
			kind = v2.ProtectedPrepare
		}
		if _, _, _, e := protectedCall(t, *side.o, side.d, v2.ProtectedCommand{Kind: kind, Admission: x.binding, Now: 1}, "closed-write"); e == nil {
			t.Fatal("read reopened Serve")
		}
	}
	if !reflect.DeepEqual(account, x.state.Snapshot()) {
		t.Fatal("reading changed admission obligations")
	}
}
