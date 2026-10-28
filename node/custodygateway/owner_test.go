//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
)

func testKey(v byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{v}, 32)) }
func testHash(s string) types.Hash      { return types.DomainHash("gateway-owner-test", []byte(s)) }
func testRoot(t testing.TB) string {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return root
}

// This fixture tests owner durability/placement independently of imported proof
// verification. The CLI campaign constructs the full real source/enrollment.
func testOwner(t testing.TB) *Owner {
	t.Helper()
	root := filepath.Join(testRoot(t), "owner")
	id, e := CreateIdentity(root)
	if e != nil {
		t.Fatal(e)
	}
	lock, e := lockExisting(filepath.Join(root, "owner.lock"))
	if e != nil {
		t.Fatal(e)
	}
	d := wire.Descriptor{RootID: id.RootID, SourceID: testHash("source"), GenesisID: testHash("g"), GenesisDescriptorID: testHash("gd"), EnrollmentID: testHash("e"), Gateway: id.PublicKey, OwnerUID: uint32(os.Geteuid()), ParticipantUID: 65534, EventLimit: 8}
	if d.OwnerUID == d.ParticipantUID {
		d.ParticipantUID = 65533
	}
	copy(d.Issuer[:], testKey(1).Public().(ed25519.PublicKey))
	var actor [32]byte
	copy(actor[:], testKey(3).Public().(ed25519.PublicKey))
	d.Clients = [][32]byte{actor}
	d, e = d.Sign(testKey(1))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(Config{})
	hash := types.DomainHash(wire.Domain+"config/id", raw)
	if e = os.Mkdir(filepath.Join(root, "events"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = publish(filepath.Join(root, "config"), raw); e != nil {
		t.Fatal(e)
	}
	if e = publish(filepath.Join(root, "configured"), hash[:]); e != nil {
		t.Fatal(e)
	}
	key, e := privateRead(filepath.Join(root, "key"), 64)
	if e != nil {
		t.Fatal(e)
	}
	o := &Owner{root: root, identity: id, descriptor: d, configHash: hash, key: key, lock: lock}
	t.Cleanup(func() { o.Close() })
	return o
}
func testRevoke(t testing.TB, o *Owner) wire.Request {
	t.Helper()
	id, _ := o.descriptor.ID()
	q, e := (wire.Request{DescriptorID: id, Before: o.position, Nonce: testHash("revoke"), Kind: wire.Revoke}).Sign(testKey(1))
	if e != nil {
		t.Fatal(e)
	}
	return q
}
func TestGatewayIdentityExclusiveAndIncomplete(t *testing.T) {
	root := filepath.Join(testRoot(t), "owner")
	id, e := CreateIdentity(root)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = CreateIdentity(root); e == nil {
		t.Fatal("recreated identity")
	}
	got, e := ReadIdentity(root)
	if e != nil || got != id {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(root, "identity")); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadIdentity(root); e == nil {
		t.Fatal("missing ready")
	}
	if _, e = CreateIdentity(root); e == nil {
		t.Fatal("partial root reused")
	}
}
func TestGatewayOwnerRejectsPlacementKeyAndLogChanges(t *testing.T) {
	cases := map[string]func(*testing.T, *Owner){
		"public-root": func(t *testing.T, o *Owner) {
			if e := os.Chmod(o.root, 0755); e != nil {
				t.Fatal(e)
			}
		},
		"key-bytes": func(t *testing.T, o *Owner) {
			if e := os.WriteFile(filepath.Join(o.root, "key"), bytes.Repeat([]byte{0}, 64), 0600); e != nil {
				t.Fatal(e)
			}
		},
		"key-mode": func(t *testing.T, o *Owner) {
			if e := os.Chmod(filepath.Join(o.root, "key"), 0644); e != nil {
				t.Fatal(e)
			}
		},
		"lock-replaced": func(t *testing.T, o *Owner) {
			p := filepath.Join(o.root, "owner.lock")
			if e := os.Rename(p, p+".old"); e != nil {
				t.Fatal(e)
			}
			if e := publish(p, nil); e != nil {
				t.Fatal(e)
			}
		},
		"config": func(t *testing.T, o *Owner) {
			if e := os.WriteFile(filepath.Join(o.root, "config"), []byte("changed"), 0600); e != nil {
				t.Fatal(e)
			}
		},
		"configured": func(t *testing.T, o *Owner) {
			if e := os.Remove(filepath.Join(o.root, "configured")); e != nil {
				t.Fatal(e)
			}
		},
		"unexpected-event": func(t *testing.T, o *Owner) {
			if e := publish(filepath.Join(o.root, "events", "unknown"), nil); e != nil {
				t.Fatal(e)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			o := testOwner(t)
			q := testRevoke(t, o)
			change(t, o)
			if _, e := o.Execute(t.Context(), q); e == nil {
				t.Fatal("changed owner used")
			}
			if p, _ := o.Position(); p.Sequence != 0 {
				t.Fatal("advanced")
			}
		})
	}
}
func TestGatewayCommitFailurePoisonsUntilColdRecovery(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			o := testOwner(t)
			q := testRevoke(t, o)
			failure := errors.New("injected commit fault")
			if after {
				o.afterCommit = func() error { return failure }
			} else {
				o.beforeCommit = func() error { return failure }
			}
			raw, e := o.Execute(t.Context(), q)
			if !errors.Is(e, failure) || len(raw) != 0 {
				t.Fatal("exposed non-durable/unknown reply", e)
			}
			if after {
				if _, e = o.Execute(t.Context(), q); e == nil {
					t.Fatal("poison ignored")
				}
				raw, e = privateRead(filepath.Join(o.root, "events", eventName(1)), wire.MaximumResponseBytes)
				if e != nil {
					t.Fatal(e)
				}
				r, e := wire.DecodeResponse(raw)
				if e != nil || r.Verify(o.descriptor, q) != nil {
					t.Fatal("lost durable evidence", e)
				}
			} else {
				o.beforeCommit = nil
				if _, e = o.Execute(t.Context(), q); e != nil {
					t.Fatal("known before-write failure unusable", e)
				}
			}
		})
	}
}
func TestGatewayRevocationSerializesWithInFlightAction(t *testing.T) {
	o := testOwner(t)
	q := testRevoke(t, o)
	entered := make(chan struct{})
	release := make(chan struct{})
	o.beforeCommit = func() error { close(entered); <-release; return nil }
	first := make(chan error, 1)
	go func() { _, e := o.Execute(t.Context(), q); first <- e }()
	<-entered
	second := make(chan error, 1)
	go func() { _, e := o.Execute(t.Context(), q); second <- e }()
	select {
	case e := <-second:
		t.Fatal("second action bypassed held effect", e)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if e := <-first; e != nil {
		t.Fatal(e)
	}
	if e := <-second; e != nil {
		t.Fatal("exact retained revoke retry", e)
	}
	p, revoked := o.Position()
	if p.Sequence != 1 || !revoked {
		t.Fatal(p, revoked)
	}
}
func TestGatewayFinalSlotReservedForIssuerRevocation(t *testing.T) {
	o := testOwner(t)
	for n := uint64(1); n < uint64(o.descriptor.EventLimit); n++ {
		id, _ := o.descriptor.ID()
		q, _ := (wire.Request{DescriptorID: id, Before: o.position, Nonce: testHash(string(rune(n))), Kind: wire.Inspect}).Sign(testKey(3))
		r, e := (wire.Response{Request: q, SourceID: o.descriptor.SourceID, Data: []byte("historical source")}).Sign(o.descriptor, o.key)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := r.CanonicalBytes()
		if e = publish(filepath.Join(o.root, "events", eventName(n)), raw); e != nil {
			t.Fatal(e)
		}
		o.position, _ = r.Position()
		o.tip = raw
		o.journalBytes += len(raw)
	}
	id, _ := o.descriptor.ID()
	q, _ := (wire.Request{DescriptorID: id, Before: o.position, Nonce: testHash("limit"), Kind: wire.Inspect}).Sign(testKey(3))
	if _, e := o.Execute(t.Context(), q); !errors.Is(e, wire.ErrAccess) {
		t.Fatal("read consumed reserved slot", e)
	}
	if _, e := o.Execute(t.Context(), testRevoke(t, o)); e != nil {
		t.Fatal("revoke unavailable", e)
	}
}

func TestGatewayTamperedTipAndReleasedKeyRefuse(t *testing.T) {
	o := testOwner(t)
	q := testRevoke(t, o)
	if _, e := o.Execute(t.Context(), q); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(o.root, "events", eventName(1))
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	raw[len(raw)-1] ^= 1
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = o.Execute(t.Context(), q); e == nil {
		t.Fatal("tampered retained reply")
	}
	if e = o.Close(); e != nil {
		t.Fatal(e)
	}
	for _, v := range o.key {
		if v != 0 {
			t.Fatal("closed owner retained private key")
		}
	}
	if _, e = o.Execute(t.Context(), q); e == nil {
		t.Fatal("closed owner used")
	}
}
func TestGatewaySymlinkAndWritableAncestorRefuse(t *testing.T) {
	root := testRoot(t)
	private := filepath.Join(root, "private")
	if _, e := CreateIdentity(private); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "link")
	if e := os.Symlink(private, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadIdentity(link); e == nil {
		t.Fatal("symlink alias")
	}
	if e := os.Chmod(root, 0777); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadIdentity(private); e == nil {
		t.Fatal("replaceable ancestor")
	}
}
