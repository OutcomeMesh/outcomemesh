package store

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestRemoteNegativeCaptureRetainsUnknownAndExactSource(t *testing.T) {
	for _, branch := range []string{"unseen", "unknown", "retained"} {
		t.Run(branch, func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := f.auditConfig(t)
			var now atomic.Uint64
			now.Store(f.base.serve.now)
			config.Audit.SessionConfig.Now = now.Load
			a, b, address := openRemoteTerminalPair(t, f, config)
			if branch == "unknown" {
				a.hooks.at = func(stage string) error {
					if stage == "remote-audit-start-confirmed" {
						return errors.New("stop before data")
					}
					return nil
				}
			}
			if branch == "retained" {
				b.hooks.at = func(stage string) error {
					if stage == "remote-data-admitted" {
						now.Store(f.base.serve.now + f.scope.CustodyPolicy.MaximumProofAge + 1000)
					}
					return nil
				}
			}
			if branch != "unseen" {
				if _, err := a.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err == nil {
					t.Fatal("negative branch accepted data")
				}
			}
			response, err := a.SealQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), address)
			if err != nil {
				t.Fatal(err)
			}
			before := testCoordination(t, a.life.owner)
			source, err := a.journal.State()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "negative")
			n, err := a.CaptureNegativeToFile(t.Context(), response, nil, path)
			if err != nil {
				t.Fatal(err)
			}
			want := RemoteCustodyUnseen
			if branch == "unknown" {
				want = RemoteCustodyUnknown
			}
			if branch == "retained" {
				want = RemoteCustodyUnverifiedResult
			}
			if n.Kind != want {
				t.Fatal("misclassified branch", n.Kind)
			}
			id, _ := n.ID()
			loaded, err := LoadRemoteCustodyNegative(path, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.VerifyNegative(t.Context(), loaded); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.CaptureNegativeToFile(t.Context(), response, nil, path); err != nil {
				t.Fatal("lost-output retry", err)
			}
			if branch == "retained" {
				r, _ := b.Review(t.Context())
				out := filepath.Join(t.TempDir(), "result")
				rid, err := r.ID()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := b.ExportResultReviewed(t.Context(), out, rid); err != nil {
					t.Fatal(err)
				}
				body, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				entry, err := workarchive.DecodeCustodyJournalEntry(body)
				if err != nil {
					t.Fatal(err)
				}
				next, err := a.CaptureNegativeToFile(t.Context(), response, &entry, filepath.Join(t.TempDir(), "verified"))
				if err != nil || next.Kind != RemoteCustodyUnacceptedResult {
					t.Fatal("historical evidence not verified", err)
				}
				if _, err := a.CaptureNegativeToFile(t.Context(), response, &entry, path); err == nil {
					t.Fatal("enrichment overwrote original observation")
				}
				if _, err := a.CaptureTerminal(t.Context(), response); err == nil {
					t.Fatal("negative evidence became successful custody")
				}
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, original) {
				t.Fatal("observation changed")
			}
			if !reflect.DeepEqual(before, testCoordination(t, a.life.owner)) {
				t.Fatal("capture changed authority")
			}
			after, err := a.journal.State()
			if err != nil || !reflect.DeepEqual(source, after) || before.Authority.Pending != 2 || before.Authority.Remote != nil {
				t.Fatal("capture released obligations or changed source", err)
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			a, err = OpenRemoteCustodyAuditRuntime(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if err := a.VerifyNegative(t.Context(), n); err != nil {
				t.Fatal("retained observation lost across restart", err)
			}
			if branch == "retained" {
				entry, exists, err := b.journal.Head()
				if err != nil || !exists {
					t.Fatal(err)
				}
				if _, appended, err := a.journal.Append(entry.Record); err != nil || !appended {
					t.Fatal("source-advance fixture", err)
				}
				if err := a.VerifyNegative(t.Context(), n); err == nil {
					t.Fatal("old absence observation survived a later source advance")
				}
			}
		})
	}
}

func TestRemoteNegativeCannotDenyAcceptedResultOrUnconfirmedDrain(t *testing.T) {
	f := newRemoteExecutionFixture(t)
	a, _, address := openRemoteTerminalPair(t, f, f.auditConfig(t))
	path := filepath.Join(t.TempDir(), "negative")
	if _, err := a.CaptureNegativeToFile(t.Context(), remotewire.Response{}, nil, path); err == nil {
		t.Fatal("no confirmed drain accepted")
	}
	if _, err := a.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), address); err != nil {
		t.Fatal(err)
	}
	response, err := a.SealQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), address)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CaptureNegativeToFile(t.Context(), response, nil, path); err == nil {
		t.Fatal("accepted source presented as absent")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed capture published evidence", err)
	}
}

func remoteNegativeVector(t testing.TB, full bool) RemoteCustodyNegative {
	t.Helper()
	v := remoteTerminalCodecVector(t)
	n := RemoteCustodyNegative{Kind: RemoteCustodyUnverifiedResult, PlanID: v.PlanID, BeginID: v.BeginID, AuditAdmission: v.AuditAdmission, Intent: v.Intent, Seal: v.Seal, Drained: v.Drained, SourceSequence: v.Intent.PriorSequence, SourceHeadID: v.Intent.PriorHeadID, SourceReceiptID: v.Intent.PriorReceiptID}
	if full {
		n.Kind = RemoteCustodyUnacceptedResult
		n.RemoteEntry = &v.Entry
	}
	b, err := n.unsignedBytes()
	if err != nil {
		t.Fatal(err)
	}
	id := types.DomainHash("OMESH/custody-authority/remote-negative/signature/v0", b)
	copy(n.Signature[:], ed25519.Sign(testKey(1), id[:]))
	return n
}

func TestRemoteNegativeCodecSeparatesEvidenceAndRejectsSubstitution(t *testing.T) {
	for _, full := range []bool{false, true} {
		n := remoteNegativeVector(t, full)
		b, err := n.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := n.ID()
		wantSize, wantID := 1391, "4e9c7faf416cfe9b4b8c0732b6625f0a3be849eb40dfd100ec8d9c4c613f12cd"
		if full {
			wantSize, wantID = 3946, "d7eeae45600305da37d5f2e85128ccd4040faf41b5e959d2b52215287fb7a100"
		}
		if len(b) != wantSize || id.String() != wantID {
			t.Fatalf("negative golden changed: bytes=%d id=%s", len(b), id)
		}
		decoded, err := DecodeRemoteCustodyNegative(b)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := decoded.CanonicalBytes()
		if !bytes.Equal(b, got) {
			t.Fatal("round trip changed bytes")
		}
		if _, err := DecodeRemoteCustodyTerminal(b); err == nil {
			t.Fatal("negative became positive terminal")
		}
		for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte{}, b...), 0)} {
			if _, err := DecodeRemoteCustodyNegative(bad); err == nil {
				t.Fatal("noncanonical envelope")
			}
		}
		for _, offset := range []int{0, 8, 10, 80, len(b) - 1} {
			bad := append([]byte{}, b...)
			bad[offset] ^= 1
			if _, err := DecodeRemoteCustodyNegative(bad); err == nil {
				t.Fatal("substitution accepted", offset)
			}
		}
	}
}

func FuzzDecodeRemoteCustodyNegative(f *testing.F) {
	for _, full := range []bool{false, true} {
		n := remoteNegativeVector(f, full)
		b, err := n.CanonicalBytes()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("OMCRNEG0"))
	f.Fuzz(func(t *testing.T, b []byte) {
		n, err := DecodeRemoteCustodyNegative(b)
		if err != nil {
			return
		}
		got, err := n.CanonicalBytes()
		if err != nil || !bytes.Equal(b, got) {
			t.Fatal("noncanonical accepted", err)
		}
	})
}
