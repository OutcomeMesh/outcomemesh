package discovery

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"slices"
	"strconv"
	"testing"

	libcrypto "github.com/libp2p/go-libp2p/core/crypto"
	libpeer "github.com/libp2p/go-libp2p/core/peer"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const testNow uint64 = 1_800_000_000

func TestSignedRecordCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	key := testKey("alice")
	record, err := Sign(key, 91, 7, testNow+600, []string{
		"[2001:0db8::1]:9844",
		"127.000.000.001:9844",
		"10.0.0.2:9844",
	})
	if err == nil {
		t.Fatal("leading-zero IPv4 address was unexpectedly accepted")
	}
	record, err = Sign(key, 91, 7, testNow+600, []string{
		"[2001:0db8::1]:9844",
		"127.0.0.1:9844",
		"10.0.0.2:9844",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantAddresses := []string{"10.0.0.2:9844", "127.0.0.1:9844", "[2001:db8::1]:9844"}
	if !slices.Equal(record.Addresses, wantAddresses) {
		t.Fatalf("canonical addresses = %v, want %v", record.Addresses, wantAddresses)
	}
	if err := record.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(record.CanonicalBytes())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(decoded.Addresses, record.Addresses) || !bytes.Equal(decoded.CanonicalBytes(), record.CanonicalBytes()) {
		t.Fatal("record changed during canonical round trip")
	}
	wantID := types.DomainHash("OMESH/p2p/ed25519/v0", key.Public().(ed25519.PublicKey))
	gotID, err := decoded.PeerID()
	if err != nil {
		t.Fatal(err)
	}
	if gotID != wantID {
		t.Fatalf("peer ID = %s, want %s", gotID, wantID)
	}
}

func TestRecordValidationRejectsMutationExpiryAndNonCanonicalOrder(t *testing.T) {
	t.Parallel()

	record := mustSign(t, "validation", 91, 4, testNow+100, "10.0.0.2:9844", "10.0.0.1:9844")
	mutated := record
	mutated.Sequence++
	if err := mutated.Validate(testNow); !errors.Is(err, ErrSignature) {
		t.Fatalf("mutated signature error = %v", err)
	}
	reordered := record
	reordered.Addresses = append([]string(nil), record.Addresses...)
	reordered.Addresses[0], reordered.Addresses[1] = reordered.Addresses[1], reordered.Addresses[0]
	if err := reordered.Validate(testNow); !errors.Is(err, ErrAddressOrder) {
		t.Fatalf("address order error = %v", err)
	}
	if err := record.Validate(record.ExpiresAt); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry error = %v", err)
	}
	longLived := mustSign(t, "long-lived", 91, 1, testNow+MaxLifetime+1, "127.0.0.1:1")
	if err := longLived.Validate(testNow); !errors.Is(err, ErrLifetime) {
		t.Fatalf("lifetime error = %v", err)
	}
}

func TestSignedQUICAddressMustMatchRecordIdentity(t *testing.T) {
	t.Parallel()

	alice := testKey("quic-alice")
	aliceAddress := testQUICAddress(t, alice, 9844)
	record, err := Sign(alice, 91, 1, testNow+100, []string{aliceAddress})
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	if record.Addresses[0] != aliceAddress {
		t.Fatalf("QUIC address changed: %q", record.Addresses[0])
	}
	bobAddress := testQUICAddress(t, testKey("quic-bob"), 9845)
	if _, err := Sign(alice, 91, 2, testNow+100, []string{bobAddress}); !errors.Is(err, ErrAddress) {
		t.Fatalf("foreign libp2p identity error = %v", err)
	}
	if _, err := Sign(alice, 91, 2, testNow+100, []string{"/dns4/example.com/udp/9844/quic-v1/p2p/" + testLibp2pID(t, alice).String()}); !errors.Is(err, ErrAddress) {
		t.Fatalf("DNS multiaddress error = %v", err)
	}
}

func TestBookEnforcesNetworkAntiReplayCapacityAndExpiry(t *testing.T) {
	t.Parallel()

	book, err := NewBook(91, 2)
	if err != nil {
		t.Fatal(err)
	}
	alice := mustSign(t, "alice", 91, 1, testNow+10, "127.0.0.1:1001")
	bob := mustSign(t, "bob", 91, 1, testNow+100, "127.0.0.1:1002")
	carol := mustSign(t, "carol", 91, 1, testNow+100, "127.0.0.1:1003")
	if err := book.Add(alice, testNow); err != nil {
		t.Fatal(err)
	}
	if err := book.MergeBatch([]Record{alice}, testNow); err != nil {
		t.Fatalf("exact gossip replay was not idempotent: %v", err)
	}
	mutatedAlice := mustSign(t, "alice", 91, 1, testNow+10, "127.0.0.1:1999")
	if err := book.MergeBatch([]Record{mutatedAlice}, testNow); !errors.Is(err, ErrStale) {
		t.Fatalf("equal-sequence mutation error = %v", err)
	}
	if err := book.Add(bob, testNow); err != nil {
		t.Fatal(err)
	}
	if err := book.Add(carol, testNow); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	if err := book.Add(alice, testNow); !errors.Is(err, ErrStale) {
		t.Fatalf("replay error = %v", err)
	}
	alice2 := mustSign(t, "alice", 91, 2, testNow+10, "127.0.0.1:2001")
	if err := book.Add(alice2, testNow); err != nil {
		t.Fatal(err)
	}
	foreign := mustSign(t, "foreign", 92, 1, testNow+100, "127.0.0.1:1004")
	if err := book.Add(foreign, testNow); !errors.Is(err, ErrNetwork) {
		t.Fatalf("network error = %v", err)
	}

	listed := book.List(testNow, 1)
	if len(listed) != 1 {
		t.Fatalf("limited list length = %d", len(listed))
	}
	listed[0].Addresses[0] = "127.0.0.1:9999"
	if book.List(testNow, 2)[0].Addresses[0] == "127.0.0.1:9999" {
		t.Fatal("book returned aliased address storage")
	}
	if got := book.Len(testNow + 11); got != 1 {
		t.Fatalf("length after expiry = %d, want 1", got)
	}
	if err := book.Add(carol, testNow+11); err != nil {
		t.Fatalf("add after expiry pruning: %v", err)
	}
}

func TestDecodeRejectsTrailingOversizeAndInvalidSigningInputs(t *testing.T) {
	t.Parallel()

	record := mustSign(t, "decode", 91, 1, testNow+100, "127.0.0.1:9844")
	encoded := append(record.CanonicalBytes(), 0)
	if _, err := Decode(encoded); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing byte error = %v", err)
	}
	if _, err := Decode(make([]byte, MaxRecordBytes+1)); !errors.Is(err, ErrAddress) {
		t.Fatalf("oversize error = %v", err)
	}
	if _, err := Sign(testKey("bad-network"), 0, 1, testNow+1, []string{"127.0.0.1:1"}); !errors.Is(err, ErrNetwork) {
		t.Fatalf("zero network error = %v", err)
	}
	if _, err := Sign(testKey("bad-sequence"), 1, 0, testNow+1, []string{"127.0.0.1:1"}); !errors.Is(err, ErrSequence) {
		t.Fatalf("zero sequence error = %v", err)
	}
}

func TestBookBatchFailureDoesNotPartiallyApply(t *testing.T) {
	t.Parallel()

	book, err := NewBook(91, 4)
	if err != nil {
		t.Fatal(err)
	}
	alice := mustSign(t, "batch-alice", 91, 1, testNow+100, "127.0.0.1:1001")
	bob := mustSign(t, "batch-bob", 91, 1, testNow+100, "127.0.0.1:1002")
	foreign := mustSign(t, "batch-foreign", 92, 1, testNow+100, "127.0.0.1:1003")
	if err := book.Add(alice, testNow); err != nil {
		t.Fatal(err)
	}
	if err := book.AddBatch([]Record{bob, foreign}, testNow); !errors.Is(err, ErrNetwork) {
		t.Fatalf("batch error = %v", err)
	}
	if got := book.Len(testNow); got != 1 {
		t.Fatalf("partially applied batch, book length = %d", got)
	}
}

func TestBookDiversityPolicyCapsIPv4PrefixAtomically(t *testing.T) {
	t.Parallel()

	book, err := NewBookWithPolicy(91, Policy{MaxRecords: 4, MaxPerNetwork: 2})
	if err != nil {
		t.Fatal(err)
	}
	first := mustSign(t, "prefix-first", 91, 1, testNow+100, "10.0.1.1:1001")
	second := mustSign(t, "prefix-second", 91, 1, testNow+100, "10.0.2.1:1002")
	third := mustSign(t, "prefix-third", 91, 1, testNow+100, "10.0.3.1:1003")
	other := mustSign(t, "prefix-other", 91, 1, testNow+100, "10.1.1.1:1004")
	if err := book.AddBatch([]Record{first, second}, testNow); err != nil {
		t.Fatal(err)
	}
	if err := book.AddBatch([]Record{third, other}, testNow); !errors.Is(err, ErrDiversity) {
		t.Fatalf("diversity error = %v", err)
	}
	if got := book.Len(testNow); got != 2 {
		t.Fatalf("diversity failure partially applied batch, length=%d", got)
	}
	if err := book.Add(other, testNow); err != nil {
		t.Fatalf("different /16 bucket rejected: %v", err)
	}
}

func FuzzDecodeNeverPanics(f *testing.F) {
	record := mustSign(f, "fuzz", 91, 1, testNow+100, "127.0.0.1:9844")
	f.Add(record.CanonicalBytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := Decode(input)
		if err == nil {
			_ = decoded.Validate(testNow)
		}
	})
}

func testKey(label string) ed25519.PrivateKey {
	seed := types.DomainHash("test/discovery/key/v0", []byte(label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func testQUICAddress(t testing.TB, key ed25519.PrivateKey, port uint16) string {
	t.Helper()
	return "/ip4/127.0.0.1/udp/" + strconv.FormatUint(uint64(port), 10) + "/quic-v1/p2p/" + testLibp2pID(t, key).String()
}

func testLibp2pID(t testing.TB, key ed25519.PrivateKey) libpeer.ID {
	t.Helper()
	privateKey, err := libcrypto.UnmarshalEd25519PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := libpeer.IDFromPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustSign(t testing.TB, label string, networkID uint32, sequence, expiresAt uint64, addresses ...string) Record {
	t.Helper()
	record, err := Sign(testKey(label), networkID, sequence, expiresAt, addresses)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
