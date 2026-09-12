package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/admissionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func testAdmissionIntent(t testing.TB) AdmissionIntent {
	t.Helper()
	history, _ := testHistory(t)
	c := history[0].Command
	c.Purpose = custodyauthority.Prune
	c, err := c.Sign(testKey(4))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(c, testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return AdmissionIntent{ClientPeerID: testHash(45), ServerPeerID: testHash(46), Entry: entry}
}

func newTestAdmissionOutbox(t testing.TB, intent AdmissionIntent) (*AdmissionOutbox, string, types.Hash) {
	t.Helper()
	id, err := intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "outbox")
	outbox, err := CreateAdmissionOutbox(path, testAssignment(), intent, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	return outbox, path, id
}

func openTestAdmissionOutbox(t testing.TB, path string, id types.Hash) *AdmissionOutbox {
	t.Helper()
	outbox, err := OpenAdmissionOutbox(path, testAssignment(), id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	return outbox
}

func testAdmissionOutboxSnapshot(t testing.TB, outbox *AdmissionOutbox) AdmissionDelivery {
	t.Helper()
	result, err := outbox.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testAdmissionOutboxAck(intent AdmissionIntent) admissionwire.Acknowledgement {
	id, _ := intent.Entry.ID()
	return admissionwire.Acknowledgement{Nonce: testHash(47), EntryID: id}
}

func TestAdmissionIntentCanonicalRecords(t *testing.T) {
	intent := testAdmissionIntent(t)
	encoded, _ := intent.CanonicalBytes()
	id, _ := intent.ID()
	ack := testAdmissionOutboxAck(intent)
	receipt, _ := admissionReceipt(id, ack)
	if len(encoded) != 456 || len(receipt) != 148 {
		t.Fatal("changed fixed envelopes")
	}
	if id.String() != "91879e16d38c955bead8c305d40ca051e26e7fe008c03404717f3000eef68366" ||
		types.DomainHash("test/admission-receipt", receipt).String() != "c1db870727fc619cf8b2d3d480315bdb3af6ba4a7471983ccf379d2f3bacd085" {
		t.Fatalf("admission outbox canonical vectors changed: id=%s receipt=%s", id, types.DomainHash("test/admission-receipt", receipt))
	}
	if got, err := DecodeAdmissionIntent(encoded); err != nil || got != intent {
		t.Fatal(got, err)
	}
	if got, err := decodeAdmissionReceipt(receipt, intent); err != nil || got != ack {
		t.Fatal(got, err)
	}
	for i := range len(encoded) {
		if _, err := DecodeAdmissionIntent(encoded[:i]); err == nil {
			t.Fatal("intent truncation", i)
		}
	}
	for i := range len(receipt) {
		if _, err := decodeAdmissionReceipt(receipt[:i], intent); err == nil {
			t.Fatal("receipt truncation", i)
		}
	}
	for _, offset := range []int{0, 8, 9, 74, len(encoded) - 1} {
		bad := bytes.Clone(encoded)
		bad[offset] ^= 1
		if _, err := DecodeAdmissionIntent(bad); err == nil {
			t.Fatal("invalid intent", offset)
		}
	}
	for i := range receipt {
		bad := bytes.Clone(receipt)
		bad[i] ^= 1
		if _, err := decodeAdmissionReceipt(bad, intent); err == nil {
			t.Fatal("changed receipt", i)
		}
	}
	if _, err := DecodeAdmissionIntent(append(encoded, 0)); err == nil {
		t.Fatal("intent trailing byte")
	}
	if _, err := decodeAdmissionReceipt(append(receipt, 0), intent); err == nil {
		t.Fatal("receipt trailing byte")
	}
	for _, mutate := range []func(*AdmissionIntent){
		func(i *AdmissionIntent) { i.ClientPeerID = types.Hash{} },
		func(i *AdmissionIntent) { i.ServerPeerID = types.Hash{} },
		func(i *AdmissionIntent) { i.ClientPeerID = i.ServerPeerID },
		func(i *AdmissionIntent) { h, _ := testHistory(t); i.Entry = h[0] },
		func(i *AdmissionIntent) { h, _ := testHistory(t); i.Entry = h[2] },
		func(i *AdmissionIntent) { h, _ := testHistory(t); i.Entry = h[3] },
		func(i *AdmissionIntent) { h, _ := testHistory(t); i.Entry = h[5] },
	} {
		bad := intent
		mutate(&bad)
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("invalid intent encoded")
		}
	}
	wrong := intent
	wrong.ServerPeerID = testHash(99)
	if _, err := decodeAdmissionReceipt(receipt, wrong); err == nil {
		t.Fatal("receipt changed route pin")
	}
	badAck := ack
	badAck.EntryID = testHash(99)
	badReceipt, _ := admissionReceipt(id, badAck)
	if _, err := decodeAdmissionReceipt(badReceipt, intent); err == nil {
		t.Fatal("checksummed wrong entry accepted")
	}
}

func TestAdmissionOutboxBootstrapAndExactRecovery(t *testing.T) {
	intent := testAdmissionIntent(t)
	outbox, path, id := newTestAdmissionOutbox(t, intent)
	if opened, err := OpenAdmissionOutbox(path, testAssignment(), id); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("missing lifetime lock", err)
	}
	if _, err := CreateAdmissionOutbox(path, testAssignment(), intent, id); !errors.Is(err, os.ErrExist) {
		t.Fatal("recreated journal", err)
	}
	s := testAdmissionOutboxSnapshot(t, outbox)
	if s.IntentID != id || s.Intent != intent || s.Acknowledgement != nil {
		t.Fatal(s)
	}
	s.Intent.Entry.Signature[0] ^= 1
	if testAdmissionOutboxSnapshot(t, outbox).Intent != intent {
		t.Fatal("snapshot aliases intent")
	}
	_ = outbox.Close()
	outbox = openTestAdmissionOutbox(t, path, id)
	if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("open fabricated delivery")
	}
	ack := testAdmissionOutboxAck(intent)
	if err := outbox.record(ack); err != nil {
		t.Fatal(err)
	}
	s = testAdmissionOutboxSnapshot(t, outbox)
	s.Acknowledgement.Nonce[0] ^= 1
	if *testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != ack {
		t.Fatal("snapshot aliases acknowledgement")
	}
	_ = outbox.Close()
	outbox = openTestAdmissionOutbox(t, path, id)
	if *testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != ack {
		t.Fatal("lost durable acknowledgement")
	}
	_ = outbox.Close()
	if _, err := OpenAdmissionOutbox(path, testAssignment(), testHash(99)); err == nil {
		t.Fatal("wrong intent pin accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenAdmissionOutbox(missing, testAssignment(), id); err == nil {
		t.Fatal("open initialized missing root")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("open created root")
	}
	if _, err := CreateAdmissionOutbox(missing, testAssignment(), intent, testHash(99)); err == nil {
		t.Fatal("bad pin created root")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad pin wrote files")
	}
}

func TestAdmissionOutboxInitializationFailures(t *testing.T) {
	for _, stage := range []string{"admission-outbox-before-ready", "admission-outbox-ready-file-synced", "admission-outbox-ready-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			intent := testAdmissionIntent(t)
			id, _ := intent.ID()
			path := filepath.Join(t.TempDir(), "outbox")
			injected := errors.New("initialization fault")
			outbox, err := createAdmissionOutbox(path, testAssignment(), intent, id, storeHooks{at: func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) || outbox != nil {
				t.Fatal(outbox, err)
			}
			if _, err := CreateAdmissionOutbox(path, testAssignment(), intent, id); !errors.Is(err, os.ErrExist) {
				t.Fatal("partial root rebuilt", err)
			}
			outbox, err = OpenAdmissionOutbox(path, testAssignment(), id)
			if outbox != nil {
				defer outbox.Close()
			}
			if stage == "admission-outbox-before-ready" {
				if err == nil || errors.Is(err, ErrBusy) {
					t.Fatal("partial init usable or lock retained", err)
				}
			} else if err != nil || testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
				t.Fatal("ready recovery", err)
			}
		})
	}
}

func admissionOutboxWriteStages() []string {
	return []string{"admission-outbox-before-write", "admission-outbox-before-file-sync", "admission-outbox-file-synced", "admission-outbox-before-publish", "admission-outbox-after-publish", "admission-outbox-directory-synced", "admission-outbox-after-apply"}
}

func admissionOutboxHasReceipt(stage string) bool {
	return stage == "admission-outbox-after-publish" || stage == "admission-outbox-directory-synced" || stage == "admission-outbox-after-apply"
}

func TestAdmissionOutboxReceiptPublicationFaults(t *testing.T) {
	for _, stage := range admissionOutboxWriteStages() {
		t.Run(stage, func(t *testing.T) {
			intent := testAdmissionIntent(t)
			ack := testAdmissionOutboxAck(intent)
			outbox, path, id := newTestAdmissionOutbox(t, intent)
			injected := errors.New("receipt publication failed")
			outbox.hooks.at = func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}
			if err := outbox.record(ack); !errors.Is(err, injected) || !errors.Is(err, ErrUncertain) {
				t.Fatal(err)
			}
			if _, err := outbox.Snapshot(); !errors.Is(err, ErrUncertain) {
				t.Fatal("failed writer stayed usable", err)
			}
			_ = outbox.Close()
			for range 2 {
				outbox = openTestAdmissionOutbox(t, path, id)
				s := testAdmissionOutboxSnapshot(t, outbox)
				if s.Intent != intent || (s.Acknowledgement != nil) != admissionOutboxHasReceipt(stage) {
					t.Fatal("recovery promoted or discarded receipt", s)
				}
				_ = outbox.Close()
			}
			outbox = openTestAdmissionOutbox(t, path, id)
			if !admissionOutboxHasReceipt(stage) {
				if err := outbox.record(ack); err != nil {
					t.Fatal("explicit publication retry", err)
				}
			}
			if *testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != ack {
				t.Fatal("wrong recovered receipt")
			}
		})
	}
}

func TestAdmissionOutboxRejectsMalformedOrReplacedEvidence(t *testing.T) {
	for _, mutation := range []string{"unknown-root", "missing-intent", "missing-ready", "missing-assignment", "wrong-pin", "bad-signature", "truncated-receipt", "bad-checksum", "extra-receipt", "unknown-pending", "oversized-pending", "pending-directory", "lock-content"} {
		t.Run(mutation, func(t *testing.T) {
			intent := testAdmissionIntent(t)
			outbox, path, id := newTestAdmissionOutbox(t, intent)
			ack := testAdmissionOutboxAck(intent)
			if err := outbox.record(ack); err != nil {
				t.Fatal(err)
			}
			_ = outbox.Close()
			switch mutation {
			case "unknown-root":
				writeTestFile(t, filepath.Join(path, "unknown"), nil)
			case "missing-intent", "missing-ready", "missing-assignment":
				name := map[string]string{"missing-intent": admissionIntentName, "missing-ready": admissionReadyName, "missing-assignment": assignmentName}[mutation]
				if err := os.Remove(filepath.Join(path, name)); err != nil {
					t.Fatal(err)
				}
			case "wrong-pin", "bad-signature":
				encoded, _ := intent.CanonicalBytes()
				if mutation == "wrong-pin" {
					encoded[42] ^= 1
				} else {
					encoded[len(encoded)-1] ^= 1
				}
				writeTestFile(t, filepath.Join(path, admissionIntentName), encoded)
			case "truncated-receipt", "bad-checksum":
				encoded, _ := admissionReceipt(id, ack)
				if mutation == "truncated-receipt" {
					encoded = encoded[:len(encoded)-1]
				} else {
					encoded[len(encoded)-1] ^= 1
				}
				writeTestFile(t, filepath.Join(path, admissionReceivedName, admissionReceiptName), encoded)
			case "extra-receipt":
				writeTestFile(t, filepath.Join(path, admissionReceivedName, "extra"), nil)
			case "unknown-pending":
				writeTestFile(t, filepath.Join(path, pendingName, "unknown"), nil)
			case "oversized-pending":
				writeTestFile(t, filepath.Join(path, pendingName, "entry-1"), make([]byte, admissionReceiptBytes+1))
			case "pending-directory":
				if err := os.Mkdir(filepath.Join(path, pendingName, "entry-1"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "lock-content":
				writeTestFile(t, filepath.Join(path, admissionLockName), []byte{1})
			}
			if reopened, err := OpenAdmissionOutbox(path, testAssignment(), id); err == nil {
				_ = reopened.Close()
				t.Fatal("malformed outbox accepted")
			}
		})
	}
	for _, name := range []string{"", admissionLockName, admissionReadyName, admissionIntentName, assignmentName, admissionReceivedName, pendingName, filepath.Join(admissionReceivedName, admissionReceiptName)} {
		t.Run("symlink/"+name, func(t *testing.T) {
			intent := testAdmissionIntent(t)
			outbox, path, id := newTestAdmissionOutbox(t, intent)
			if err := outbox.record(testAdmissionOutboxAck(intent)); err != nil {
				t.Fatal(err)
			}
			_ = outbox.Close()
			original := filepath.Join(path, name)
			moved := filepath.Join(t.TempDir(), "original")
			if err := os.Rename(original, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, original); err != nil {
				t.Fatal(err)
			}
			if reopened, err := OpenAdmissionOutbox(path, testAssignment(), id); err == nil {
				_ = reopened.Close()
				t.Fatal("symlink accepted")
			}
		})
	}
	t.Run("same-size-live-change", func(t *testing.T) {
		intent := testAdmissionIntent(t)
		outbox, path, _ := newTestAdmissionOutbox(t, intent)
		encoded, _ := intent.CanonicalBytes()
		encoded[42] ^= 1
		writeTestFile(t, filepath.Join(path, admissionIntentName), encoded)
		if _, err := outbox.Snapshot(); !errors.Is(err, ErrUncertain) {
			t.Fatal("live intent edit accepted", err)
		}
	})
}

// Prepare only the server's lifecycle. The client retains the ORIGINAL command,
// including after Stop/Complete/Retire; it cannot sign a replacement.
func prepareAdmissionOutboxPhase(t testing.TB, f *pruneFixture, phase string) {
	t.Helper()
	f.admission = pruneAdmissionEntry(t, f)
	if phase == "initial" {
		return
	}
	if _, err := f.executor.Admit(context.Background(), f.coordinator, f.admission); err != nil {
		t.Fatal(err)
	}
	switch phase {
	case "admitted":
	case "stopping":
		f.stop(t)
	case "retired":
		if _, err := f.executor.CancelBeforeStart(context.Background(), f.coordinator); err != nil {
			t.Fatal(err)
		}
		if _, err := f.executor.Complete(context.Background(), f.coordinator, pruneCompletionEntry(t, f)); err != nil {
			t.Fatal(err)
		}
		stop := f.stop(t)
		appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
	default:
		t.Fatal("unknown admission phase", phase)
	}
}

func assertAdmissionOutboxPhase(t testing.TB, f *pruneFixture, phase string) {
	t.Helper()
	if phase == "initial" || phase == "admitted" {
		assertPruneAdmissionConfirmed(t, f)
		return
	}
	sequence, pending, authorityPhase, stage := uint64(2), uint16(1), custodyauthority.Stopping, PruneAdmitted
	if phase == "retired" {
		sequence, pending, authorityPhase, stage = 4, 0, custodyauthority.Retired, PruneCancelled
	}
	c, s := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
	if c.Pending != nil || c.Confirmed.Sequence != sequence || c.Authority.Sequence != sequence ||
		c.Authority.Pending != pending || c.Authority.Phase != authorityPhase ||
		s.Stage != stage || s.Admission == nil || *s.Admission != f.admission ||
		s.Protection.Pending != nil || s.Protection.Confirmed.Stage != stage {
		t.Fatal("historical admission changed lifecycle", c, s)
	}
	ticket, _ := f.admission.ID()
	if _, found, err := f.chain.CanonicalPruneEffect(ticket); err != nil || found {
		t.Fatal("admission executed effect", err)
	}
}

func TestAdmissionOutboxQUICLostReplyAndDurableHistoricalRetry(t *testing.T) {
	for _, phase := range []string{"initial", "admitted", "stopping", "retired"} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/partial-%v", phase, partial), func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				prepareAdmissionOutboxPhase(t, f, phase)
				server, client := completionHosts(t)
				intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: f.admission}
				outbox, path, id := newTestAdmissionOutbox(t, intent)
				results := installAdmissionServer(t, f, server, client, func(s network.Stream) admissionwire.Stream { return lostCompletionReply{s, partial} })
				if ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second); !errors.Is(err, admissionwire.ErrUnconfirmed) || ack != (admissionwire.Acknowledgement{}) {
					t.Fatal("lost reply became success", err)
				}
				_ = awaitCompletionServe(t, results)
				if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
					t.Fatal("unreceived acknowledgement recorded")
				}
				assertAdmissionOutboxPhase(t, f, phase)
				before, executor := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
				_ = outbox.Close()
				f.reopen(t)
				outbox = openTestAdmissionOutbox(t, path, id)
				results = installAdmissionServer(t, f, server, client, nil)
				ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
				if err != nil || *testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != ack {
					t.Fatal("delivery not durable", err)
				}
				if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
					t.Fatal("retry re-appended admission", r.err)
				}
				_ = outbox.Close()
				_ = server.Close()
				outbox = openTestAdmissionOutbox(t, path, id)
				if cached, err := outbox.Deliver(t.Context(), client, "not-an-address", 2*time.Second); err != nil || cached != ack {
					t.Fatal("historical delivery dialed again", err)
				}
				if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(executor, pruneSnapshot(t, f.executor)) {
					t.Fatal("historical delivery changed server")
				}
				assertAdmissionOutboxPhase(t, f, phase)
			})
		}
	}
}

func TestAdmissionOutboxQUICRecordsCheckedReplyDespiteCancellation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	prepareAdmissionOutboxPhase(t, f, "initial")
	server, client := completionHosts(t)
	intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: f.admission}
	outbox, path, id := newTestAdmissionOutbox(t, intent)
	results := installAdmissionServer(t, f, server, client, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	outbox.hooks.at = func(stage string) error {
		if stage == "admission-outbox-reply-verified" {
			cancel()
		}
		return nil
	}
	ack, err := outbox.Deliver(ctx, client, server.Addresses()[0], 2*time.Second)
	if err != nil || ctx.Err() == nil {
		t.Fatal("checked reply not retained", err)
	}
	_ = awaitCompletionServe(t, results)
	_ = outbox.Close()
	outbox = openTestAdmissionOutbox(t, path, id)
	if *testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != ack {
		t.Fatal("checked reply lost on reopen")
	}
}

func TestAdmissionOutboxMissingReceiptIsUnresolvedNotPermissionToRepeatEffect(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	prepareAdmissionOutboxPhase(t, f, "initial")
	server, client := completionHosts(t)
	intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: f.admission}
	outbox, path, id := newTestAdmissionOutbox(t, intent)
	results := installAdmissionServer(t, f, server, client, nil)
	original, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || !r.commit.Appended {
		t.Fatal(r.err)
	}
	if _, err := f.executor.CancelBeforeStart(t.Context(), f.coordinator); err != nil {
		t.Fatal(err)
	}
	if _, err := f.executor.Complete(t.Context(), f.coordinator, pruneCompletionEntry(t, f)); err != nil {
		t.Fatal(err)
	}
	stop := f.stop(t)
	appendCoordinated(t, f.coordinator, testEntry(t, testCoordination(t, f.coordinator).Authority, custodyauthority.Retire, types.Hash{}, types.Hash{}, stop))
	before, executor := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
	// The cached ACK remains historical even when the authority is now retired.
	if cached, err := outbox.Deliver(t.Context(), client, "no-network", time.Second); err != nil || cached != original {
		t.Fatal(err)
	}
	_ = outbox.Close()
	// ACK-only loss has no independent receipt-position pin. Keep the lost
	// evidence aside and recover as unresolved, without claiming rollback detection.
	if err := os.Rename(filepath.Join(path, admissionReceivedName, admissionReceiptName), filepath.Join(t.TempDir(), "old-ack")); err != nil {
		t.Fatal(err)
	}
	outbox = openTestAdmissionOutbox(t, path, id)
	if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("missing ACK invented delivery")
	}
	retry, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
	if err != nil || retry.EntryID != original.EntryID || retry.Nonce == original.Nonce {
		t.Fatal("lost ACK retry changed command or reused nonce", err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
		t.Fatal("ACK loss repeated authority admission", r.err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(executor, pruneSnapshot(t, f.executor)) {
		t.Fatal("ACK loss changed server")
	}
	if _, err := f.executor.Execute(t.Context(), f.coordinator, f.chain, func() (uint64, error) { t.Error("ACK granted execution"); return 200, nil }); !errors.Is(err, ErrPruneCancelled) {
		t.Fatal(err)
	}
	assertAdmissionOutboxPhase(t, f, "retired")
}

func TestAdmissionOutboxQUICRejectsWrongClientBeforeSending(t *testing.T) {
	server, client := completionHosts(t)
	intent := testAdmissionIntent(t)
	intent.ServerPeerID = server.ID()
	intent.ClientPeerID = testHash(99)
	outbox, _, _ := newTestAdmissionOutbox(t, intent)
	if _, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second); !errors.Is(err, ErrAdmissionIntent) {
		t.Fatal(err)
	}
	if _, err := outbox.Deliver(nil, client, "", time.Second); !errors.Is(err, ErrAdmissionIntent) {
		t.Fatal(err)
	}
	if _, err := outbox.Deliver(t.Context(), nil, "", time.Second); !errors.Is(err, ErrAdmissionIntent) {
		t.Fatal(err)
	}
	if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("bad client acknowledged")
	}
}

func TestAdmissionOutboxPendingLimitPreventsNetworkUse(t *testing.T) {
	server, client := completionHosts(t)
	intent := testAdmissionIntent(t)
	intent.ServerPeerID = server.ID()
	intent.ClientPeerID = client.ID()
	outbox, path, _ := newTestAdmissionOutbox(t, intent)
	for i := range MaximumPendingFiles {
		writeTestFile(t, filepath.Join(path, pendingName, fmt.Sprintf("entry-%d", i)), nil)
	}
	called := false
	outbox.hooks.at = func(string) error { called = true; return nil }
	if _, err := outbox.Deliver(t.Context(), client, "not-an-address", time.Second); !errors.Is(err, custodyauthority.ErrLimit) || called {
		t.Fatal("capacity checked after send", err)
	}
}

func TestAdmissionOutboxQUICSerializesDeliveryAndClose(t *testing.T) {
	for _, mode := range []string{"duplicate", "close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			prepareAdmissionOutboxPhase(t, f, "initial")
			server, client := completionHosts(t)
			intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: f.admission}
			outbox, path, id := newTestAdmissionOutbox(t, intent)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			setCoordinatorHooks(f.coordinator, storeHooks{at: func(stage string) error {
				if stage == "confirm-before-publish" {
					close(entered)
					<-release
				}
				return nil
			}})
			results := installAdmissionServer(t, f, server, client, nil)
			type reply struct {
				ack admissionwire.Acknowledgement
				err error
			}
			deliver := func(ctx context.Context) <-chan reply {
				done := make(chan reply, 1)
				go func() {
					ack, err := outbox.Deliver(ctx, client, server.Addresses()[0], 2*time.Second)
					done <- reply{ack, err}
				}()
				return done
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			first := deliver(ctx)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("server did not reach confirmation")
			}
			if outbox.mu.TryLock() {
				outbox.mu.Unlock()
				t.Fatal("network exchange lost journal guard")
			}
			switch mode {
			case "duplicate":
				second := deliver(t.Context())
				unblock()
				a, b := <-first, <-second
				if a.err != nil || b.err != nil || a.ack != b.ack {
					t.Fatal("duplicate delivery not serialized", a.err, b.err)
				}
			case "close":
				closed := make(chan error, 1)
				go func() { closed <- outbox.Close() }()
				select {
				case <-closed:
					t.Fatal("close escaped in-flight ownership")
				case <-time.After(20 * time.Millisecond):
				}
				unblock()
				if r := <-first; r.err != nil {
					t.Fatal(r.err)
				}
				if err := <-closed; err != nil {
					t.Fatal(err)
				}
				outbox = openTestAdmissionOutbox(t, path, id)
			case "cancel":
				cancel()
				r := <-first
				if !errors.Is(r.err, context.Canceled) || !errors.Is(r.err, admissionwire.ErrUnconfirmed) || r.ack != (admissionwire.Acknowledgement{}) {
					t.Fatal("cancelled exchange became success", r.err)
				}
				if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
					t.Fatal("cancellation fabricated delivery")
				}
				unblock()
			}
			_ = awaitCompletionServe(t, results)
			setCoordinatorHooks(f.coordinator, storeHooks{})
			if mode == "cancel" {
				_ = outbox.Close()
				outbox = openTestAdmissionOutbox(t, path, id)
				if _, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second); err != nil {
					t.Fatal(err)
				}
				if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
					t.Fatal("cancelled client's retry changed decision", r.err)
				}
			}
			if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement == nil {
				t.Fatal("successful delivery unrecorded")
			}
			select {
			case <-results:
				t.Fatal("duplicate network exchange")
			default:
			}
		})
	}
}

func TestAdmissionOutboxQUICLocalSyncFailureReturnsNoAcknowledgement(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	prepareAdmissionOutboxPhase(t, f, "initial")
	server, client := completionHosts(t)
	intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: f.admission}
	outbox, path, id := newTestAdmissionOutbox(t, intent)
	results := installAdmissionServer(t, f, server, client, nil)
	failure := errors.New("receipt directory sync failed")
	outbox.hooks.syncEntriesDirectory = func(string) error { return failure }
	ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
	if !errors.Is(err, failure) || !errors.Is(err, ErrUncertain) || !errors.Is(err, admissionwire.ErrUnconfirmed) || ack != (admissionwire.Acknowledgement{}) {
		t.Fatal("failed local durability reported success", err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || !r.commit.Appended {
		t.Fatal(r.err)
	}
	if _, err := outbox.Snapshot(); !errors.Is(err, ErrUncertain) {
		t.Fatal("uncertain writer stayed usable", err)
	}
	_ = outbox.Close()
	_ = server.Close()
	outbox = openTestAdmissionOutbox(t, path, id)
	if s := testAdmissionOutboxSnapshot(t, outbox); s.Acknowledgement == nil {
		t.Fatal("recovery discarded exact visible receipt")
	}
	if _, err := outbox.Deliver(t.Context(), client, "no-network", time.Second); err != nil {
		t.Fatal("re-synced receipt required network", err)
	}
}

func TestAdmissionOutboxAssignmentBindingAndUnknownServer(t *testing.T) {
	intent := testAdmissionIntent(t)
	for _, mode := range []string{"authority", "assignment", "actor", "purpose", "sequence"} {
		t.Run(mode, func(t *testing.T) {
			a := testAssignment()
			bad := intent
			switch mode {
			case "authority":
				bad.Entry, _ = custodyauthority.SignEntry(bad.Entry.Command, testKey(5))
			case "assignment":
				a.NetworkID++
			case "actor":
				c := bad.Entry.Command
				c.ActorPublicKey = [32]byte{}
				c, _ = c.Sign(testKey(5))
				bad.Entry, _ = custodyauthority.SignEntry(c, testKey(1))
			case "purpose":
				a.Consumers[0].Purposes = custodyauthority.Audit | custodyauthority.Serve
				a.Consumers = append(a.Consumers, custodyauthority.Consumer{PublicKey: testPublic(5), Purposes: custodyauthority.Prune})
				if bytes.Compare(a.Consumers[0].PublicKey[:], a.Consumers[1].PublicKey[:]) > 0 {
					a.Consumers[0], a.Consumers[1] = a.Consumers[1], a.Consumers[0]
				}
				c := bad.Entry.Command
				c.AssignmentID, _ = a.ID()
				c, _ = c.Sign(testKey(4))
				bad.Entry, _ = custodyauthority.SignEntry(c, testKey(1))
			case "sequence":
				c := bad.Entry.Command
				c.ExpectedSequence = 2*(uint64(a.MaximumOperations)-1) + 1
				c, _ = c.Sign(testKey(4))
				bad.Entry, _ = custodyauthority.SignEntry(c, testKey(1))
			}
			id, err := bad.ID()
			if err != nil {
				t.Fatal("test fixture must be canonically signed", err)
			}
			path := t.TempDir() + "/outbox"
			if outbox, err := CreateAdmissionOutbox(path, a, bad, id); err == nil {
				_ = outbox.Close()
				t.Fatal("unbound intent retained")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid scope wrote files")
			}
		})
	}
	f := newPruneFixtureWithStorageID(t, testHash(91))
	prepareAdmissionOutboxPhase(t, f, "initial")
	server, client := completionHosts(t)
	// Use a working concrete endpoint and a command it would accept. Disabled
	// negotiation or an invalid admission must not mask a missing server pin.
	results := installAdmissionServer(t, f, server, client, nil)
	intent = AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: testHash(99), Entry: f.admission}
	before := testCoordination(t, f.coordinator)
	outbox, _, _ := newTestAdmissionOutbox(t, intent)
	if ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], time.Second); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) || ack != (admissionwire.Acknowledgement{}) {
		t.Fatal("untrusted server acknowledged", err)
	}
	if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("failed pin created receipt")
	}
	if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) {
		t.Fatal("wrong server pin changed authority")
	}
	select {
	case <-results:
		t.Fatal("wrong pin reached admission handler")
	default:
	}
}

func TestAdmissionOutboxSequenceBounds(t *testing.T) {
	for _, maximum := range []uint32{1, 4, custodyauthority.MaximumOperations} {
		for _, sequence := range []uint64{0, 2 * (uint64(maximum) - 1), 2*(uint64(maximum)-1) + 1, ^uint64(0) - 1} {
			t.Run(fmt.Sprintf("%d/%d", maximum, sequence), func(t *testing.T) {
				a := testAssignment()
				a.MaximumOperations, a.MaximumPending = maximum, 1
				intent := testAdmissionIntent(t)
				c := intent.Entry.Command
				var err error
				c.AssignmentID, err = a.ID()
				if err != nil {
					t.Fatal(err)
				}
				c.ExpectedSequence = sequence
				c, err = c.Sign(testKey(4))
				if err != nil {
					t.Fatal(err)
				}
				intent.Entry, err = custodyauthority.SignEntry(c, testKey(1))
				if err != nil {
					t.Fatal(err)
				}
				id, err := intent.ID()
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(t.TempDir(), "outbox")
				outbox, err := CreateAdmissionOutbox(path, a, intent, id)
				if sequence > 2*(uint64(maximum)-1) {
					if outbox != nil {
						_ = outbox.Close()
						t.Fatal("impossible admission retained")
					}
					if !errors.Is(err, ErrAdmissionIntent) {
						t.Fatal(err)
					}
					if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("invalid bound wrote root", err)
					}
				} else {
					if err != nil {
						t.Fatal("static bound rejected", err)
					}
					_ = outbox.Close()
					outbox, err = OpenAdmissionOutbox(path, a, id)
					if err != nil {
						t.Fatal(err)
					}
					defer outbox.Close()
					if testAdmissionOutboxSnapshot(t, outbox).Acknowledgement != nil {
						t.Fatal("static validation invented current acceptance")
					}
				}
			})
		}
	}
}

func TestAdmissionOutboxRecordsAreNotCompletionEvidence(t *testing.T) {
	admit, complete := testAdmissionIntent(t), testCompletionIntent(t)
	admitID, _ := admit.ID()
	completeID, _ := complete.ID()
	a, _ := admit.CanonicalBytes()
	c, _ := complete.CanonicalBytes()
	ar, _ := admissionReceipt(admitID, testAdmissionOutboxAck(admit))
	cr, _ := completionReceipt(completeID, testOutboxAck(complete))
	if _, err := DecodeAdmissionIntent(c); err == nil {
		t.Fatal("completion intent is admission")
	}
	if _, err := DecodeCompletionIntent(a); err == nil {
		t.Fatal("admission intent is completion")
	}
	if _, err := decodeAdmissionReceipt(cr, admit); err == nil {
		t.Fatal("completion receipt is admission")
	}
	if _, err := decodeCompletionReceipt(ar, complete); err == nil {
		t.Fatal("admission receipt is completion")
	}
	// Even a valid outer admission checksum cannot retype the embedded wire ACK.
	copy(ar[42:50], cr[42:50])
	sum := types.DomainHash("OMESH/custody-admission/receipt/v0", ar[:116])
	copy(ar[116:], sum[:])
	if _, err := decodeAdmissionReceipt(ar, admit); err == nil {
		t.Fatal("foreign wire ACK accepted")
	}
	outbox, path, _ := newTestAdmissionOutbox(t, admit)
	_ = outbox.Close()
	if other, err := OpenCompletionOutbox(path, testAssignment(), completeID); err == nil {
		_ = other.Close()
		t.Fatal("admission root opened as completion")
	}
	if _, err := os.Lstat(filepath.Join(path, completionLockName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("foreign open created lock")
	}
}

func TestAdmissionOutboxQUICDoesNotReplaceRejectedRequestOrHead(t *testing.T) {
	for _, field := range []string{"operation", "head"} {
		t.Run(field, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			prepareAdmissionOutboxPhase(t, f, "initial")
			server, client := completionHosts(t)
			c := f.admission.Command
			if field == "operation" {
				c.OperationID = testHash(99)
			} else {
				c.ExpectedHead = testHash(99)
			}
			c, err := c.Sign(testKey(4))
			if err != nil {
				t.Fatal(err)
			}
			entry, err := custodyauthority.SignEntry(c, testKey(1))
			if err != nil {
				t.Fatal(err)
			}
			intent := AdmissionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: entry}
			outbox, path, id := newTestAdmissionOutbox(t, intent)
			before, executor := testCoordination(t, f.coordinator), pruneSnapshot(t, f.executor)
			results := installAdmissionServer(t, f, server, client, nil)
			for range 2 {
				if ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second); !errors.Is(err, admissionwire.ErrUnconfirmed) || ack != (admissionwire.Acknowledgement{}) {
					t.Fatal("rejected command became success", err)
				}
				if r := awaitCompletionServe(t, results); r.err == nil {
					t.Fatal("server accepted foreign binding")
				}
				if s := testAdmissionOutboxSnapshot(t, outbox); s.Intent != intent || s.Acknowledgement != nil {
					t.Fatal("rejection replaced intent")
				}
				_ = outbox.Close()
				outbox = openTestAdmissionOutbox(t, path, id)
			}
			if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) || !reflect.DeepEqual(executor, pruneSnapshot(t, f.executor)) {
				t.Fatal("rejection changed server")
			}
		})
	}
}

func FuzzAdmissionOutboxRecords(f *testing.F) {
	intent := testAdmissionIntent(f)
	id, _ := intent.ID()
	encoded, _ := intent.CanonicalBytes()
	receipt, _ := admissionReceipt(id, testAdmissionOutboxAck(intent))
	f.Add(encoded)
	f.Add(receipt)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if got, err := DecodeAdmissionIntent(data); err == nil {
			encoded, err := got.CanonicalBytes()
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("noncanonical intent", err)
			}
		}
		if ack, err := decodeAdmissionReceipt(data, intent); err == nil {
			encoded, err := admissionReceipt(id, ack)
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("noncanonical receipt", err)
			}
		}
	})
}

// Compile-time assertion keeps the delivery API on the concrete identity-pinned
// transport rather than a user-supplied callback that could invent success.
var _ func(*AdmissionOutbox, context.Context, *libp2ptransport.Host, string, time.Duration) (admissionwire.Acknowledgement, error) = (*AdmissionOutbox).Deliver
