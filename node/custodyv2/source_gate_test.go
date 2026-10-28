package custodyv2

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func injectSourceHandoff(t testing.TB, path string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(path, "source-handoff.omcsh"), []byte("unconfirmed source version transition"), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestRequiredSourceGateStopsOpenedTargetAndRemainsPoisoned(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	target := x.createTarget(t)
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	injectSourceHandoff(t, x.s.Journal)
	if _, e := target.Prepare(); !errors.Is(e, workarchive.ErrCustodySourceHandedOff) {
		t.Fatal(e)
	}
	os.Remove(filepath.Join(x.s.Journal, "source-handoff.omcsh"))
	if _, e := target.Execute(t.Context(), f.Certificate(candidate.Claim, 70, 71, 72), x.c.Plan.Challenge.IssuedAt); e == nil {
		t.Fatal("poisoned owner revived")
	}
	if _, e := os.Stat(filepath.Join(x.targetPath, "consumed")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("consumed after exclusion", e)
	}
}
func TestRequiredSourceGateChecksBeforeFirstObjectRead(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	target := x.createTarget(t)
	candidate, e := target.Prepare()
	if e != nil {
		t.Fatal(e)
	}
	target.r.hook = func(at string) error {
		if at == "before-effect" {
			injectSourceHandoff(t, x.s.Journal)
		}
		return nil
	}
	if _, e := target.Execute(t.Context(), f.Certificate(candidate.Claim, 70, 71, 72), x.c.Plan.Challenge.IssuedAt); !errors.Is(e, workarchive.ErrCustodySourceHandedOff) {
		t.Fatal(e)
	}
	if target.r.objects != nil {
		t.Fatal("archive opened after version refusal")
	}
	if _, e := os.Stat(filepath.Join(x.targetPath, "consumed")); e != nil {
		t.Fatal("lost consumed intent", e)
	}
	if _, e := os.Stat(filepath.Join(x.targetPath, "result")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("published forbidden result", e)
	}
}
func TestRequiredSourceGateStopsAcceptanceReceiptAfterSourceAppend(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	target := x.createTarget(t)
	b := x.bundle(t, target)
	acceptor := x.createAcceptor(t)
	acceptor.r.hook = func(at string) error {
		if at == "source-accepted-before-receipt" {
			injectSourceHandoff(t, x.ajournal)
		}
		return nil
	}
	if _, e := acceptor.Accept(t.Context(), b, x.c.Plan.Challenge.IssuedAt); !errors.Is(e, workarchive.ErrCustodySourceHandedOff) {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(x.acceptorPath, "pending")); e != nil {
		t.Fatal("lost exact acceptance attempt", e)
	}
	if _, e := os.Stat(filepath.Join(x.acceptorPath, "accepted")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("published forbidden receipt", e)
	}
}
func TestRequiredSourceGateStopsInboxAcknowledgementAndCachedReceipt(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-signing", true: "cached-receipt"}[cached], func(t *testing.T) {
			z := newAdmissionDeliveryFixture(t)
			inbox := z.inbox(t)
			if cached {
				if _, e := inbox.Receive(t.Context(), z.delivery); e != nil {
					t.Fatal(e)
				}
				injectSourceHandoff(t, z.s.Journal)
			} else {
				inbox.s.hook = func(at string) error {
					if at == "delivery-durable" {
						injectSourceHandoff(t, z.s.Journal)
					}
					return nil
				}
			}
			if _, e := inbox.Receive(t.Context(), z.delivery); !errors.Is(e, workarchive.ErrCustodySourceHandedOff) {
				t.Fatal("acknowledged after source exclusion", e)
			}
			if !cached {
				if _, e := os.Stat(filepath.Join(z.path, "receipt")); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("created forbidden receipt", e)
				}
			}
			if _, e := inbox.ReadReceipt(); e == nil {
				t.Fatal("cached receipt bypassed live gate")
			}
		})
	}
}
