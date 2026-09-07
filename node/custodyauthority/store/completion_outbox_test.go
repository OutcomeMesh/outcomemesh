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
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/completionwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func testCompletionIntent(t testing.TB) CompletionIntent {
	t.Helper()
	history, _ := testHistory(t)
	return CompletionIntent{ClientPeerID: testHash(45), ServerPeerID: testHash(46), Entry: history[3]}
}

func newTestOutbox(t testing.TB, intent CompletionIntent) (*CompletionOutbox, string, types.Hash) {
	t.Helper()
	id, err := intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "outbox")
	outbox, err := CreateCompletionOutbox(path, testAssignment(), intent, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	return outbox, path, id
}

func openTestOutbox(t testing.TB, path string, id types.Hash) *CompletionOutbox {
	t.Helper()
	outbox, err := OpenCompletionOutbox(path, testAssignment(), id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = outbox.Close() })
	return outbox
}

func testOutboxSnapshot(t testing.TB, outbox *CompletionOutbox) CompletionDelivery {
	t.Helper()
	result, err := outbox.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testOutboxAck(intent CompletionIntent) completionwire.Acknowledgement {
	id, _ := intent.Entry.ID()
	return completionwire.Acknowledgement{Nonce: testHash(47), EntryID: id}
}

func TestCompletionIntentCanonicalRecords(t *testing.T) {
	intent := testCompletionIntent(t)
	encoded, _ := intent.CanonicalBytes()
	id, _ := intent.ID()
	ack := testOutboxAck(intent)
	receipt, _ := completionReceipt(id, ack)
	if len(encoded) != 456 || len(receipt) != 148 {
		t.Fatal("changed fixed envelopes")
	}
	if id.String() != "5b0c0521513a39330c0ba2e70a70f1c537a22a30990ed79c6fd5e62262d8520f" ||
		types.DomainHash("test/completion-receipt", receipt).String() != "2131efecee863c62eab5fc268b26858e752084c119500050febfb54fba8b34f7" {
		t.Fatal("completion outbox canonical vectors changed")
	}
	if got, err := DecodeCompletionIntent(encoded); err != nil || got != intent {
		t.Fatal(got, err)
	}
	if got, err := decodeCompletionReceipt(receipt, intent); err != nil || got != ack {
		t.Fatal(got, err)
	}
	for i := range len(encoded) {
		if _, err := DecodeCompletionIntent(encoded[:i]); err == nil {
			t.Fatal("intent truncation", i)
		}
	}
	for i := range len(receipt) {
		if _, err := decodeCompletionReceipt(receipt[:i], intent); err == nil {
			t.Fatal("receipt truncation", i)
		}
	}
	for _, offset := range []int{0, 8, 9, 74, len(encoded) - 1} {
		bad := bytes.Clone(encoded)
		bad[offset] ^= 1
		if _, err := DecodeCompletionIntent(bad); err == nil {
			t.Fatal("invalid intent", offset)
		}
	}
	for i := range receipt {
		bad := bytes.Clone(receipt)
		bad[i] ^= 1
		if _, err := decodeCompletionReceipt(bad, intent); err == nil {
			t.Fatal("changed receipt", i)
		}
	}
	if _, err := DecodeCompletionIntent(append(encoded, 0)); err == nil {
		t.Fatal("intent trailing byte")
	}
	if _, err := decodeCompletionReceipt(append(receipt, 0), intent); err == nil {
		t.Fatal("receipt trailing byte")
	}
	for _, mutate := range []func(*CompletionIntent){
		func(i *CompletionIntent) { i.ClientPeerID = types.Hash{} },
		func(i *CompletionIntent) { i.ServerPeerID = types.Hash{} },
		func(i *CompletionIntent) { i.ClientPeerID = i.ServerPeerID },
		func(i *CompletionIntent) { h, _ := testHistory(t); i.Entry = h[0] },
		func(i *CompletionIntent) { h, _ := testHistory(t); i.Entry = h[2] },
		func(i *CompletionIntent) { h, _ := testHistory(t); i.Entry = h[5] },
	} {
		bad := intent
		mutate(&bad)
		if _, err := bad.CanonicalBytes(); err == nil {
			t.Fatal("invalid intent encoded")
		}
	}
	wrong := intent
	wrong.ServerPeerID = testHash(99)
	if _, err := decodeCompletionReceipt(receipt, wrong); err == nil {
		t.Fatal("receipt changed route pin")
	}
	badAck := ack
	badAck.EntryID = testHash(99)
	badReceipt, _ := completionReceipt(id, badAck)
	if _, err := decodeCompletionReceipt(badReceipt, intent); err == nil {
		t.Fatal("checksummed wrong entry accepted")
	}
}

func TestCompletionOutboxBootstrapAndExactRecovery(t *testing.T) {
	intent := testCompletionIntent(t)
	outbox, path, id := newTestOutbox(t, intent)
	if opened, err := OpenCompletionOutbox(path, testAssignment(), id); !errors.Is(err, ErrBusy) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("missing lifetime lock", err)
	}
	if _, err := CreateCompletionOutbox(path, testAssignment(), intent, id); !errors.Is(err, os.ErrExist) {
		t.Fatal("recreated journal", err)
	}
	s := testOutboxSnapshot(t, outbox)
	if s.IntentID != id || s.Intent != intent || s.Acknowledgement != nil {
		t.Fatal(s)
	}
	s.Intent.Entry.Signature[0] ^= 1
	if testOutboxSnapshot(t, outbox).Intent != intent {
		t.Fatal("snapshot aliases intent")
	}
	_ = outbox.Close()
	outbox = openTestOutbox(t, path, id)
	if testOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("open fabricated delivery")
	}
	ack := testOutboxAck(intent)
	if err := outbox.record(ack); err != nil {
		t.Fatal(err)
	}
	s = testOutboxSnapshot(t, outbox)
	s.Acknowledgement.Nonce[0] ^= 1
	if *testOutboxSnapshot(t, outbox).Acknowledgement != ack {
		t.Fatal("snapshot aliases acknowledgement")
	}
	_ = outbox.Close()
	outbox = openTestOutbox(t, path, id)
	if *testOutboxSnapshot(t, outbox).Acknowledgement != ack {
		t.Fatal("lost durable acknowledgement")
	}
	_ = outbox.Close()
	if _, err := OpenCompletionOutbox(path, testAssignment(), testHash(99)); err == nil {
		t.Fatal("wrong intent pin accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := OpenCompletionOutbox(missing, testAssignment(), id); err == nil {
		t.Fatal("open initialized missing root")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("open created root")
	}
	if _, err := CreateCompletionOutbox(missing, testAssignment(), intent, testHash(99)); err == nil {
		t.Fatal("bad pin created root")
	}
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("bad pin wrote files")
	}
}

func TestCompletionOutboxInitializationFailures(t *testing.T) {
	for _, stage := range []string{"outbox-before-ready", "outbox-ready-file-synced", "outbox-ready-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			intent := testCompletionIntent(t)
			id, _ := intent.ID()
			path := filepath.Join(t.TempDir(), "outbox")
			injected := errors.New("initialization fault")
			outbox, err := createCompletionOutbox(path, testAssignment(), intent, id, storeHooks{at: func(at string) error {
				if at == stage {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) || outbox != nil {
				t.Fatal(outbox, err)
			}
			if _, err := CreateCompletionOutbox(path, testAssignment(), intent, id); !errors.Is(err, os.ErrExist) {
				t.Fatal("partial root rebuilt", err)
			}
			outbox, err = OpenCompletionOutbox(path, testAssignment(), id)
			if outbox != nil {
				defer outbox.Close()
			}
			if stage == "outbox-before-ready" {
				if err == nil || errors.Is(err, ErrBusy) {
					t.Fatal("partial init usable or lock retained", err)
				}
			} else if err != nil || testOutboxSnapshot(t, outbox).Acknowledgement != nil {
				t.Fatal("ready recovery", err)
			}
		})
	}
}

func completionOutboxWriteStages() []string {
	return []string{"outbox-before-write", "outbox-before-file-sync", "outbox-file-synced", "outbox-before-publish", "outbox-after-publish", "outbox-directory-synced", "outbox-after-apply"}
}

func completionOutboxHasReceipt(stage string) bool {
	return stage == "outbox-after-publish" || stage == "outbox-directory-synced" || stage == "outbox-after-apply"
}

func TestCompletionOutboxReceiptPublicationFaults(t *testing.T) {
	for _, stage := range completionOutboxWriteStages() {
		t.Run(stage, func(t *testing.T) {
			intent := testCompletionIntent(t)
			ack := testOutboxAck(intent)
			outbox, path, id := newTestOutbox(t, intent)
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
				outbox = openTestOutbox(t, path, id)
				s := testOutboxSnapshot(t, outbox)
				if s.Intent != intent || (s.Acknowledgement != nil) != completionOutboxHasReceipt(stage) {
					t.Fatal("recovery promoted or discarded receipt", s)
				}
				_ = outbox.Close()
			}
			outbox = openTestOutbox(t, path, id)
			if !completionOutboxHasReceipt(stage) {
				if err := outbox.record(ack); err != nil {
					t.Fatal("explicit publication retry", err)
				}
			}
			if *testOutboxSnapshot(t, outbox).Acknowledgement != ack {
				t.Fatal("wrong recovered receipt")
			}
		})
	}
}

func TestCompletionOutboxRejectsMalformedOrReplacedEvidence(t *testing.T) {
	for _, mutation := range []string{"unknown-root", "missing-intent", "missing-ready", "missing-assignment", "wrong-pin", "bad-signature", "truncated-receipt", "bad-checksum", "extra-receipt", "unknown-pending", "oversized-pending", "pending-directory", "lock-content"} {
		t.Run(mutation, func(t *testing.T) {
			intent := testCompletionIntent(t)
			outbox, path, id := newTestOutbox(t, intent)
			ack := testOutboxAck(intent)
			if err := outbox.record(ack); err != nil {
				t.Fatal(err)
			}
			_ = outbox.Close()
			switch mutation {
			case "unknown-root":
				writeTestFile(t, filepath.Join(path, "unknown"), nil)
			case "missing-intent", "missing-ready", "missing-assignment":
				name := map[string]string{"missing-intent": completionIntentName, "missing-ready": completionReadyName, "missing-assignment": assignmentName}[mutation]
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
				writeTestFile(t, filepath.Join(path, completionIntentName), encoded)
			case "truncated-receipt", "bad-checksum":
				encoded, _ := completionReceipt(id, ack)
				if mutation == "truncated-receipt" {
					encoded = encoded[:len(encoded)-1]
				} else {
					encoded[len(encoded)-1] ^= 1
				}
				writeTestFile(t, filepath.Join(path, completionReceivedName, completionReceiptName), encoded)
			case "extra-receipt":
				writeTestFile(t, filepath.Join(path, completionReceivedName, "extra"), nil)
			case "unknown-pending":
				writeTestFile(t, filepath.Join(path, pendingName, "unknown"), nil)
			case "oversized-pending":
				writeTestFile(t, filepath.Join(path, pendingName, "entry-1"), make([]byte, completionReceiptBytes+1))
			case "pending-directory":
				if err := os.Mkdir(filepath.Join(path, pendingName, "entry-1"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "lock-content":
				writeTestFile(t, filepath.Join(path, completionLockName), []byte{1})
			}
			if reopened, err := OpenCompletionOutbox(path, testAssignment(), id); err == nil {
				_ = reopened.Close()
				t.Fatal("malformed outbox accepted")
			}
		})
	}
	for _, name := range []string{"", completionLockName, completionReadyName, completionIntentName, assignmentName, completionReceivedName, pendingName, filepath.Join(completionReceivedName, completionReceiptName)} {
		t.Run("symlink/"+name, func(t *testing.T) {
			intent := testCompletionIntent(t)
			outbox, path, id := newTestOutbox(t, intent)
			if err := outbox.record(testOutboxAck(intent)); err != nil {
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
			if reopened, err := OpenCompletionOutbox(path, testAssignment(), id); err == nil {
				_ = reopened.Close()
				t.Fatal("symlink accepted")
			}
		})
	}
	t.Run("same-size-live-change", func(t *testing.T) {
		intent := testCompletionIntent(t)
		outbox, path, _ := newTestOutbox(t, intent)
		encoded, _ := intent.CanonicalBytes()
		encoded[42] ^= 1
		writeTestFile(t, filepath.Join(path, completionIntentName), encoded)
		if _, err := outbox.Snapshot(); !errors.Is(err, ErrUncertain) {
			t.Fatal("live intent edit accepted", err)
		}
	})
}

func TestCompletionOutboxQUICLostReplyAndDurableHistoricalRetry(t *testing.T) {
	for _, outcome := range []string{"succeeded", "cancelled"} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/partial-%v", outcome, partial), func(t *testing.T) {
				f := newPruneFixtureWithStorageID(t, testHash(91))
				finishPruneForCompletion(t, f, outcome)
				server, client := completionHosts(t)
				intent := CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: pruneCompletionEntry(t, f)}
				terminal := pruneSnapshot(t, f.executor)
				outbox, path, id := newTestOutbox(t, intent)
				results := installCompletionServer(t, f, server, client, func(s network.Stream) completionwire.Stream { return lostCompletionReply{s, partial} })
				if ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second); !errors.Is(err, completionwire.ErrUnconfirmed) || ack != (completionwire.Acknowledgement{}) {
					t.Fatal("lost reply became success", err)
				}
				_ = awaitCompletionServe(t, results)
				if testOutboxSnapshot(t, outbox).Acknowledgement != nil {
					t.Fatal("unreceived acknowledgement recorded")
				}
				if c := testCoordination(t, f.coordinator); c.Pending != nil || c.Authority.Pending != 0 {
					t.Fatal("server discarded decision")
				}
				_ = outbox.Close()
				f.reopen(t)
				outbox = openTestOutbox(t, path, id)
				results = installCompletionServer(t, f, server, client, nil)
				ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
				if err != nil || *testOutboxSnapshot(t, outbox).Acknowledgement != ack {
					t.Fatal("delivery not durable", err)
				}
				if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
					t.Fatal("retry re-appended completion", r.err)
				}
				_ = outbox.Close()
				_ = server.Close()
				outbox = openTestOutbox(t, path, id)
				if cached, err := outbox.Deliver(t.Context(), client, "not-an-address", 2*time.Second); err != nil || cached != ack {
					t.Fatal("historical delivery dialed again", err)
				}
				if !reflect.DeepEqual(terminal, pruneSnapshot(t, f.executor)) {
					t.Fatal("outbox changed executor")
				}
			})
		}
	}
}

func TestCompletionOutboxQUICRecordsCheckedReplyDespiteCancellation(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "cancelled")
	server, client := completionHosts(t)
	intent := CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: pruneCompletionEntry(t, f)}
	outbox, path, id := newTestOutbox(t, intent)
	results := installCompletionServer(t, f, server, client, nil)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	outbox.hooks.at = func(stage string) error {
		if stage == "outbox-reply-verified" {
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
	outbox = openTestOutbox(t, path, id)
	if *testOutboxSnapshot(t, outbox).Acknowledgement != ack {
		t.Fatal("checked reply lost on reopen")
	}
}

func TestCompletionOutboxMissingReceiptIsUnresolvedNotPermissionToRepeatEffect(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "succeeded")
	terminal := pruneSnapshot(t, f.executor)
	server, client := completionHosts(t)
	intent := CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: pruneCompletionEntry(t, f)}
	outbox, path, id := newTestOutbox(t, intent)
	results := installCompletionServer(t, f, server, client, nil)
	original, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || !r.commit.Appended {
		t.Fatal(r.err)
	}
	_ = outbox.Close()
	// Simulate ACK-only loss without erasing the lost evidence. There is no
	// independent ACK-position pin, so recovery must not claim rollback detection.
	if err := os.Rename(filepath.Join(path, completionReceivedName, completionReceiptName), filepath.Join(t.TempDir(), "old-ack")); err != nil {
		t.Fatal(err)
	}
	outbox = openTestOutbox(t, path, id)
	if testOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("missing ACK invented delivery")
	}
	retry, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
	if err != nil || retry.EntryID != original.EntryID || retry.Nonce == original.Nonce {
		t.Fatal("lost ACK retry changed command or reused nonce", err)
	}
	if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
		t.Fatal("ACK loss repeated authority completion", r.err)
	}
	if !reflect.DeepEqual(terminal, pruneSnapshot(t, f.executor)) {
		t.Fatal("ACK loss repeated effect")
	}
}

func TestCompletionOutboxQUICRejectsWrongClientBeforeSending(t *testing.T) {
	server, client := completionHosts(t)
	intent := testCompletionIntent(t)
	intent.ServerPeerID = server.ID()
	intent.ClientPeerID = testHash(99)
	outbox, _, _ := newTestOutbox(t, intent)
	if _, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second); !errors.Is(err, ErrCompletionIntent) {
		t.Fatal(err)
	}
	if _, err := outbox.Deliver(nil, client, "", time.Second); !errors.Is(err, ErrCompletionIntent) {
		t.Fatal(err)
	}
	if _, err := outbox.Deliver(t.Context(), nil, "", time.Second); !errors.Is(err, ErrCompletionIntent) {
		t.Fatal(err)
	}
	if testOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("bad client acknowledged")
	}
}

func TestCompletionOutboxPendingLimitPreventsNetworkUse(t *testing.T) {
	server, client := completionHosts(t)
	intent := testCompletionIntent(t)
	intent.ServerPeerID = server.ID()
	intent.ClientPeerID = client.ID()
	outbox, path, _ := newTestOutbox(t, intent)
	for i := range MaximumPendingFiles {
		writeTestFile(t, filepath.Join(path, pendingName, fmt.Sprintf("entry-%d", i)), nil)
	}
	called := false
	outbox.hooks.at = func(string) error { called = true; return nil }
	if _, err := outbox.Deliver(t.Context(), client, "not-an-address", time.Second); !errors.Is(err, custodyauthority.ErrLimit) || called {
		t.Fatal("capacity checked after send", err)
	}
}

func TestCompletionOutboxQUICSerializesDeliveryAndClose(t *testing.T) {
	for _, mode := range []string{"duplicate", "close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newPruneFixtureWithStorageID(t, testHash(91))
			finishPruneForCompletion(t, f, "cancelled")
			server, client := completionHosts(t)
			intent := CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: pruneCompletionEntry(t, f)}
			outbox, path, id := newTestOutbox(t, intent)
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
			results := installCompletionServer(t, f, server, client, nil)
			type reply struct {
				ack completionwire.Acknowledgement
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
				outbox = openTestOutbox(t, path, id)
			case "cancel":
				cancel()
				r := <-first
				if !errors.Is(r.err, context.Canceled) || !errors.Is(r.err, completionwire.ErrUnconfirmed) || r.ack != (completionwire.Acknowledgement{}) {
					t.Fatal("cancelled exchange became success", r.err)
				}
				if testOutboxSnapshot(t, outbox).Acknowledgement != nil {
					t.Fatal("cancellation fabricated delivery")
				}
				unblock()
			}
			_ = awaitCompletionServe(t, results)
			setCoordinatorHooks(f.coordinator, storeHooks{})
			if mode == "cancel" {
				_ = outbox.Close()
				outbox = openTestOutbox(t, path, id)
				if _, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second); err != nil {
					t.Fatal(err)
				}
				if r := awaitCompletionServe(t, results); r.err != nil || r.commit.Appended {
					t.Fatal("cancelled client's retry changed decision", r.err)
				}
			}
			if testOutboxSnapshot(t, outbox).Acknowledgement == nil {
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

func TestCompletionOutboxQUICLocalSyncFailureReturnsNoAcknowledgement(t *testing.T) {
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "cancelled")
	server, client := completionHosts(t)
	intent := CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: server.ID(), Entry: pruneCompletionEntry(t, f)}
	outbox, path, id := newTestOutbox(t, intent)
	results := installCompletionServer(t, f, server, client, nil)
	failure := errors.New("receipt directory sync failed")
	outbox.hooks.syncEntriesDirectory = func(string) error { return failure }
	ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], 2*time.Second)
	if !errors.Is(err, failure) || !errors.Is(err, ErrUncertain) || !errors.Is(err, completionwire.ErrUnconfirmed) || ack != (completionwire.Acknowledgement{}) {
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
	outbox = openTestOutbox(t, path, id)
	if s := testOutboxSnapshot(t, outbox); s.Acknowledgement == nil {
		t.Fatal("recovery discarded exact visible receipt")
	}
	if _, err := outbox.Deliver(t.Context(), client, "no-network", time.Second); err != nil {
		t.Fatal("re-synced receipt required network", err)
	}
}

func TestCompletionOutboxAssignmentBindingAndUnknownServer(t *testing.T) {
	intent := testCompletionIntent(t)
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
				c.ExpectedSequence = 2*uint64(a.MaximumOperations) + 2
				c, _ = c.Sign(testKey(4))
				bad.Entry, _ = custodyauthority.SignEntry(c, testKey(1))
			}
			id, err := bad.ID()
			if err != nil {
				t.Fatal("test fixture must be canonically signed", err)
			}
			path := t.TempDir() + "/outbox"
			if outbox, err := CreateCompletionOutbox(path, a, bad, id); err == nil {
				_ = outbox.Close()
				t.Fatal("unbound intent retained")
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid scope wrote files")
			}
		})
	}
	f := newPruneFixtureWithStorageID(t, testHash(91))
	finishPruneForCompletion(t, f, "cancelled")
	server, client := completionHosts(t)
	// Use a working concrete endpoint and a command it would accept. Disabled
	// negotiation or bad terminal evidence must not mask a missing server pin.
	results := installCompletionServer(t, f, server, client, nil)
	intent = CompletionIntent{ClientPeerID: client.ID(), ServerPeerID: testHash(99), Entry: pruneCompletionEntry(t, f)}
	before := testCoordination(t, f.coordinator)
	outbox, _, _ := newTestOutbox(t, intent)
	if ack, err := outbox.Deliver(t.Context(), client, server.Addresses()[0], time.Second); !errors.Is(err, libp2ptransport.ErrUnexpectedPeer) || ack != (completionwire.Acknowledgement{}) {
		t.Fatal("untrusted server acknowledged", err)
	}
	if testOutboxSnapshot(t, outbox).Acknowledgement != nil {
		t.Fatal("failed pin created receipt")
	}
	if !reflect.DeepEqual(before, testCoordination(t, f.coordinator)) {
		t.Fatal("wrong server pin changed authority")
	}
	select {
	case <-results:
		t.Fatal("wrong pin reached completion handler")
	default:
	}
}

func FuzzCompletionOutboxRecords(f *testing.F) {
	intent := testCompletionIntent(f)
	id, _ := intent.ID()
	encoded, _ := intent.CanonicalBytes()
	receipt, _ := completionReceipt(id, testOutboxAck(intent))
	f.Add(encoded)
	f.Add(receipt)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if got, err := DecodeCompletionIntent(data); err == nil {
			encoded, err := got.CanonicalBytes()
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("noncanonical intent", err)
			}
		}
		if ack, err := decodeCompletionReceipt(data, intent); err == nil {
			encoded, err := completionReceipt(id, ack)
			if err != nil || !bytes.Equal(encoded, data) {
				t.Fatal("noncanonical receipt", err)
			}
		}
	})
}

// Compile-time assertion keeps the delivery API on the concrete identity-pinned
// transport rather than a user-supplied callback that could invent success.
var _ func(*CompletionOutbox, context.Context, *libp2ptransport.Host, string, time.Duration) (completionwire.Acknowledgement, error) = (*CompletionOutbox).Deliver
