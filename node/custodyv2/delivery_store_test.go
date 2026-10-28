package custodyv2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	libcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/transport"
)

type admissionDeliveryFixture struct {
	requiredRuntimeFixture
	path, outbox string
	enrollment   AdmissionDeliveryEnrollment
	delivery     AdmissionDelivery
}

func admissionDeliveryTestRoute(t testing.TB, seed byte, port string) string {
	t.Helper()
	public := f.Public(seed)
	key, e := libcrypto.UnmarshalEd25519PublicKey(public[:])
	if e != nil {
		t.Fatal(e)
	}
	id, e := peer.IDFromPublicKey(key)
	if e != nil {
		t.Fatal(e)
	}
	return "/ip4/127.0.0.1/udp/" + port + "/quic-v1/p2p/" + id.String()
}

func newAdmissionDeliveryFixture(t testing.TB) admissionDeliveryFixture {
	t.Helper()
	x := newRequiredRuntimeFixture(t)
	z := admissionDeliveryFixture{requiredRuntimeFixture: x, path: filepath.Join(x.root, "admission-inbox"), outbox: filepath.Join(x.root, "admission-outbox")}
	peer, e := transport.PeerIDFromPublicKey(x.c.Assignment.Base.RemoteTransportPublicKey[:])
	if e != nil {
		t.Fatal(e)
	}
	bid, _ := x.binding.ID()
	z.enrollment, e = CreateAdmissionInbox(z.path, x.c, x.pin, bid, AdmissionDeliveryTarget, x.s, peer)
	if e != nil {
		t.Fatal(e)
	}
	z.delivery = AdmissionDelivery{Version: Version2, Enrollment: z.enrollment, Context: x.c, Binding: x.binding}
	if e := z.delivery.Validate(); e != nil {
		t.Fatal(e)
	}
	return z
}
func (z admissionDeliveryFixture) inbox(t testing.TB) *AdmissionInbox {
	t.Helper()
	i, e := OpenAdmissionInbox(z.path, z.c, z.pin, z.s, z.enrollment, f.Key(14))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = i.Close() })
	return i
}
func (z admissionDeliveryFixture) createOutbox(t testing.TB) *AdmissionOutbox {
	t.Helper()
	if e := CreateAdmissionOutbox(z.outbox, z.delivery, admissionDeliveryTestRoute(t, 15, "40123")); e != nil {
		t.Fatal(e)
	}
	return z.openOutbox(t)
}
func (z admissionDeliveryFixture) openOutbox(t testing.TB) *AdmissionOutbox {
	t.Helper()
	o, e := OpenAdmissionOutbox(z.outbox, z.delivery, admissionDeliveryTestRoute(t, 15, "40123"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func TestAdmissionDeliveryStoresRetainOnlyProofAndExactReceipt(t *testing.T) {
	z := newAdmissionDeliveryFixture(t)
	// Intake does not read or hash current object chunks. A missing chunk must
	// not turn proof delivery into an archive effect or a new custody response.
	if e := os.Remove(filepath.Join(z.s.Objects, "chunk-"+z.c.Manifest.Chunks[0].ID.String()+".omwc")); e != nil {
		t.Fatal(e)
	}
	i, o := z.inbox(t), z.createOutbox(t)
	if _, e := i.Delivery(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("new intake discovered a proof", e)
	}
	if _, e := o.ReadReceipt(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("new outbox was prematurely acknowledged", e)
	}
	r, e := i.Receive(t.Context(), o.Delivery())
	if e != nil {
		t.Fatal(e)
	}
	if e := r.Verify(z.delivery); e != nil {
		t.Fatal(e)
	}
	if e := o.Confirm(t.Context(), r); e != nil {
		t.Fatal(e)
	}
	before, _ := r.CanonicalBytes()
	for j := 0; j < 3; j++ {
		again, e := i.Receive(t.Context(), z.delivery)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := again.CanonicalBytes()
		if !bytes.Equal(raw, before) {
			t.Fatal("delivery retry changed historical receipt")
		}
	}
	state, e := i.decision.State()
	if e != nil || state.Sequence != 0 {
		t.Fatal("intake advanced original source", state, e)
	}
	for _, p := range []string{z.targetPath, z.acceptorPath} {
		if _, e := os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("proof delivery created a runtime owner", p, e)
		}
	}
	if e := i.Close(); e != nil {
		t.Fatal(e)
	}
	if e := o.Close(); e != nil {
		t.Fatal(e)
	}
	i, o = z.inbox(t), z.openOutbox(t)
	for _, read := range []func() (AdmissionDeliveryReceipt, error){i.ReadReceipt, o.ReadReceipt} {
		got, e := read()
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := got.CanonicalBytes()
		if !bytes.Equal(raw, before) {
			t.Fatal("cold receipt changed")
		}
	}
}

func TestAdmissionDeliveryInboxFaultsRequireExplicitExactRecovery(t *testing.T) {
	for _, stage := range []string{"delivery-before-sync", "delivery-durable", "receipt-before-sync", "receipt-durable"} {
		t.Run(stage, func(t *testing.T) {
			z := newAdmissionDeliveryFixture(t)
			i := z.inbox(t)
			i.s.hook = func(name string) error {
				if name == stage {
					return errors.New("injected intake write failure")
				}
				return nil
			}
			if _, e := i.Receive(t.Context(), z.delivery); !errors.Is(e, ErrUncertain) {
				t.Fatal("failed persistence returned success", e)
			}
			if _, e := i.ReadReceipt(); !errors.Is(e, ErrUncertain) {
				t.Fatal("uncertain live handle remained usable", e)
			}
			_ = i.Close()
			i = z.inbox(t)
			if _, e := i.Delivery(); e != nil {
				t.Fatal("cold open lost exact complete delivery", e)
			}
			_, e := i.ReadReceipt()
			if stage[:8] == "delivery" && !errors.Is(e, os.ErrNotExist) {
				t.Fatal("cold Open fabricated missing acknowledgement", e)
			}
			r, e := i.Receive(t.Context(), z.delivery)
			if e != nil {
				t.Fatal("explicit exact recovery failed", e)
			}
			expected, e := (AdmissionDeliveryReceipt{}).Sign(z.delivery, f.Key(14))
			if e != nil || r != expected {
				t.Fatal("recovery changed receipt", r, expected, e)
			}
			state, e := i.decision.State()
			if e != nil || state.Sequence != 0 {
				t.Fatal("intake recovery advanced source", state, e)
			}
		})
	}
}

func TestAdmissionDeliveryOutboxReceiptFaultsRecoverWithoutDispatch(t *testing.T) {
	for _, stage := range []string{"receipt-before-sync", "receipt-durable"} {
		t.Run(stage, func(t *testing.T) {
			z := newAdmissionDeliveryFixture(t)
			i, o := z.inbox(t), z.createOutbox(t)
			r, e := i.Receive(t.Context(), z.delivery)
			if e != nil {
				t.Fatal(e)
			}
			o.s.hook = func(name string) error {
				if name == stage {
					return errors.New("injected outbox confirmation failure")
				}
				return nil
			}
			if e := o.Confirm(t.Context(), r); !errors.Is(e, ErrUncertain) {
				t.Fatal("failed outbox persistence returned success", e)
			}
			if e := o.Check(); !errors.Is(e, ErrUncertain) {
				t.Fatal("failed outbox stayed live", e)
			}
			_ = o.Close()
			o = z.openOutbox(t)
			got, e := o.ReadReceipt()
			if e != nil || got != r {
				t.Fatal("cold exact receipt recovery failed", got, e)
			}
			if e := o.Confirm(t.Context(), r); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestAdmissionDeliveryCachedReceiptIsHistoricalButPendingProofCannotAcknowledgeAdvancedSource(t *testing.T) {
	for _, acknowledged := range []bool{false, true} {
		t.Run(map[bool]string{false: "pending", true: "acknowledged"}[acknowledged], func(t *testing.T) {
			z := newAdmissionDeliveryFixture(t)
			i := z.inbox(t)
			if !acknowledged {
				i.s.hook = func(name string) error {
					if name == "delivery-durable" {
						return errors.New("stop before receipt")
					}
					return nil
				}
			}
			_, e := i.Receive(t.Context(), z.delivery)
			if acknowledged && e != nil || !acknowledged && !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			_ = i.Close()
			target := z.createTarget(t)
			z.bundle(t, target)
			_ = target.Close()
			i = z.inbox(t)
			state, e := i.decision.State()
			if e != nil || state.Sequence != 1 {
				t.Fatal("fixture source did not advance", state, e)
			}
			_, e = i.Receive(t.Context(), z.delivery)
			if acknowledged && e != nil || !acknowledged && e == nil {
				t.Fatal("advanced source was not distinguished from historical ACK", e)
			}
			if !acknowledged {
				if _, e := i.ReadReceipt(); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("advanced source received a new acknowledgement", e)
				}
			}
		})
	}
}

func TestAdmissionDeliveryOriginalPlacementAndIndependentSelectors(t *testing.T) {
	for _, kind := range []string{"inbox-copy", "inbox-move", "inbox-replaced-lock", "inbox-replaced-source", "inbox-ready", "inbox-unexpected", "inbox-key", "inbox-enrollment", "outbox-copy", "outbox-move", "outbox-route", "outbox-delivery", "outbox-receipt"} {
		t.Run(kind, func(t *testing.T) {
			z := newAdmissionDeliveryFixture(t)
			o := z.createOutbox(t)
			_ = o.Close()
			ip, op, enrollment := z.path, z.outbox, z.enrollment
			key := f.Key(14)
			route := admissionDeliveryTestRoute(t, 15, "40123")
			delivery := z.delivery
			switch kind {
			case "inbox-copy":
				ip = filepath.Join(z.root, "inbox-copy")
				copyAdmissionWitnessRoot(t, z.path, ip)
			case "inbox-move":
				ip = filepath.Join(z.root, "inbox-moved")
				if e := os.Rename(z.path, ip); e != nil {
					t.Fatal(e)
				}
			case "inbox-replaced-lock":
				if e := os.Rename(filepath.Join(z.path, "owner.lock"), filepath.Join(z.root, "old-owner-lock")); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(z.path, "owner.lock"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "inbox-replaced-source":
				old := z.s.Objects + "-old"
				if e := os.Rename(z.s.Objects, old); e != nil {
					t.Fatal(e)
				}
				if e := os.Mkdir(z.s.Objects, 0700); e != nil {
					t.Fatal(e)
				}
			case "inbox-ready":
				if e := os.Remove(filepath.Join(z.path, "ready")); e != nil {
					t.Fatal(e)
				}
			case "inbox-unexpected":
				if e := os.WriteFile(filepath.Join(z.path, "invented"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "inbox-key":
				key = f.Key(1)
			case "inbox-enrollment":
				enrollment.Nonce[0] ^= 1
			case "outbox-copy":
				op = filepath.Join(z.root, "outbox-copy")
				copyAdmissionWitnessRoot(t, z.outbox, op)
			case "outbox-move":
				op = filepath.Join(z.root, "outbox-moved")
				if e := os.Rename(z.outbox, op); e != nil {
					t.Fatal(e)
				}
			case "outbox-route":
				route = admissionDeliveryTestRoute(t, 15, "40124")
			case "outbox-delivery":
				delivery.Enrollment.Nonce[0] ^= 1
			case "outbox-receipt":
				if e := os.WriteFile(filepath.Join(z.outbox, "receipt"), make([]byte, AdmissionDeliveryReceiptBytes), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if kind[:5] == "inbox" {
				if i, e := OpenAdmissionInbox(ip, z.c, z.pin, z.s, enrollment, key); e == nil {
					_ = i.Close()
					t.Fatal("substituted inbox was accepted")
				}
			} else if o, e := OpenAdmissionOutbox(op, delivery, route); e == nil {
				_ = o.Close()
				t.Fatal("substituted outbox was accepted")
			}
		})
	}
}

func TestAdmissionDeliveryCancellationCopiesAndConcurrentReceivers(t *testing.T) {
	z := newAdmissionDeliveryFixture(t)
	i := z.inbox(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := i.Receive(ctx, z.delivery); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := i.Delivery(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("cancelled delivery left proof", e)
	}
	if _, e := OpenAdmissionInbox(z.path, z.c, z.pin, z.s, z.enrollment, f.Key(14)); e == nil {
		t.Fatal("concurrent owner acquired intake")
	}
	if e := CreateRequiredTarget(z.targetPath, z.c, z.pin, z.s, z.binding); e == nil {
		t.Fatal("runtime acquired source while intake retained decision")
	}
	var wg sync.WaitGroup
	results := make(chan AdmissionDeliveryReceipt, 4)
	errorsCh := make(chan error, 4)
	for j := 0; j < 4; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := i.Receive(t.Context(), z.delivery)
			results <- r
			errorsCh <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errorsCh)
	for e := range errorsCh {
		if e != nil {
			t.Fatal(e)
		}
	}
	var first AdmissionDeliveryReceipt
	for r := range results {
		if first.Version == 0 {
			first = r
		} else if r != first {
			t.Fatal("concurrent retries produced divergent receipt")
		}
	}
	_ = i.Close()
	if e := CreateRequiredTarget(z.targetPath, z.c, z.pin, z.s, z.binding); e != nil {
		t.Fatal("explicit runtime creation failed after intake close", e)
	}
}

func TestAdmissionDeliveryEnrollmentRecoveryIsReadOnlyAndSelectorBound(t *testing.T) {
	z := newAdmissionDeliveryFixture(t)
	before, e := os.ReadDir(z.path)
	if e != nil {
		t.Fatal(e)
	}
	bid, _ := z.binding.ID()
	got, e := ReadAdmissionInboxEnrollment(z.path, z.c, z.pin, bid, AdmissionDeliveryTarget, z.s, z.enrollment.RecipientPeerID)
	if e != nil || got != z.enrollment {
		t.Fatal("exact public enrollment recovery failed", got, e)
	}
	after, e := os.ReadDir(z.path)
	if e != nil || len(before) != len(after) {
		t.Fatal("descriptor recovery created state", before, after, e)
	}
	if _, e := ReadAdmissionInboxEnrollment(z.path, z.c, z.pin, types.DomainHash("foreign-binding"), AdmissionDeliveryTarget, z.s, z.enrollment.RecipientPeerID); e == nil {
		t.Fatal("foreign binding adopted saved descriptor")
	}
	if _, e := ReadAdmissionInboxEnrollment(z.path, z.c, z.pin, bid, AdmissionDeliveryAuthority, Sources{Journal: z.ajournal}, z.enrollment.RecipientPeerID); e == nil {
		t.Fatal("foreign role/source adopted saved descriptor")
	}
	if e := os.Remove(filepath.Join(z.path, "ready")); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadAdmissionInboxEnrollment(z.path, z.c, z.pin, bid, AdmissionDeliveryTarget, z.s, z.enrollment.RecipientPeerID); e == nil {
		t.Fatal("partial initialization was silently completed")
	}
}

func TestAdmissionDeliveryAuthorityIntakeUsesItsOriginalSourceAndRole(t *testing.T) {
	x := newRequiredRuntimeFixture(t)
	bid, _ := x.binding.ID()
	public := f.Public(47)
	peer, e := transport.PeerIDFromPublicKey(public[:])
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(x.root, "authority-inbox")
	sources := Sources{Journal: x.ajournal}
	enrollment, e := CreateAdmissionInbox(path, x.c, x.pin, bid, AdmissionDeliveryAuthority, sources, peer)
	if e != nil {
		t.Fatal(e)
	}
	if enrollment.ReceiptPublicKey != x.c.Assignment.Base.AuthorityPublicKey {
		t.Fatal("authority intake substituted receipt role")
	}
	i, e := OpenAdmissionInbox(path, x.c, x.pin, sources, enrollment, f.Key(1))
	if e != nil {
		t.Fatal(e)
	}
	defer i.Close()
	d := AdmissionDelivery{Version: Version2, Enrollment: enrollment, Context: x.c, Binding: x.binding}
	r, e := i.Receive(t.Context(), d)
	if e != nil || r.Verify(d) != nil {
		t.Fatal("authority could not retain exact proof", e)
	}
	state, e := i.decision.State()
	if e != nil || state.Sequence != 0 {
		t.Fatal("authority delivery advanced source", state, e)
	}
}

func TestAdmissionDeliveryCancellationAfterProofDurabilityNeedsExplicitRetry(t *testing.T) {
	z := newAdmissionDeliveryFixture(t)
	i := z.inbox(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	i.s.hook = func(stage string) error {
		if stage == "delivery-durable" {
			cancel()
		}
		return nil
	}
	if _, e := i.Receive(ctx, z.delivery); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled intake returned acknowledgement", e)
	}
	if _, e := i.ReadReceipt(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("cancellation fabricated ACK", e)
	}
	_ = i.Close()
	i = z.inbox(t)
	if _, e := i.ReadReceipt(); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("cold open completed cancelled delivery", e)
	}
	if _, e := i.Receive(t.Context(), z.delivery); e != nil {
		t.Fatal("explicit retry did not resume exact retained proof", e)
	}
}

func TestAdmissionDeliveryPartialRetainedFilesAreNeverReconstructed(t *testing.T) {
	for _, name := range []string{"delivery", "receipt"} {
		t.Run(name, func(t *testing.T) {
			z := newAdmissionDeliveryFixture(t)
			i := z.inbox(t)
			if _, e := i.Receive(t.Context(), z.delivery); e != nil {
				t.Fatal(e)
			}
			_ = i.Close()
			if e := os.Truncate(filepath.Join(z.path, name), 20); e != nil {
				t.Fatal(e)
			}
			if i, e := OpenAdmissionInbox(z.path, z.c, z.pin, z.s, z.enrollment, f.Key(14)); e == nil {
				_ = i.Close()
				t.Fatal("partial evidence was silently reconstructed")
			}
		})
	}
}

func TestAdmissionDeliveryInvalidRoutesNeverCreateAnOutbox(t *testing.T) {
	z := newAdmissionDeliveryFixture(t)
	valid := admissionDeliveryTestRoute(t, 15, "40123")
	for j, route := range []string{"", "/ip4/127.0.0.1/udp/40123/quic-v1", admissionDeliveryTestRoute(t, 46, "40123"), "/ip4/127.0.0.1/tcp/40123" + valid[len("/ip4/127.0.0.1/udp/40123/quic-v1"):], valid + "/p2p-circuit"} {
		path := filepath.Join(z.root, "invalid-route-"+string(rune('0'+j)))
		if e := CreateAdmissionOutbox(path, z.delivery, route); e == nil {
			t.Fatal("invalid or foreign route persisted", route)
		}
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			t.Fatal("invalid route created a root", route, e)
		}
	}
}
