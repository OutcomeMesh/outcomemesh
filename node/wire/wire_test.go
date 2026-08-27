package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/wallet"
)

func TestMessageRoundTripsAndSupportsShortWrites(t *testing.T) {
	t.Parallel()

	status := testStatus()
	request := GetBlocks{
		Version:  Version0,
		Locators: []types.Hash{status.TipID, status.GenesisID},
		Limit:    16,
	}
	blockMessage := Block{Value: testBlock(t)}
	headerRequest := GetHeaders{Version: Version0, Locators: append([]types.Hash(nil), request.Locators...), Limit: 16}
	headerBatch := Headers{Version: Version0, Values: []block.Header{blockMessage.Value.Header}, TipID: status.TipID}
	transactionMessage := Transaction{Value: testTransaction(t)}
	done := BatchDone{Version: Version0, TipID: status.TipID}
	result := Result{Version: Version0, Code: ResultAccepted, ObjectID: status.TipID}
	getPeers := GetPeers{Version: Version0, Limit: 8}
	peers := Peers{Version: Version0, Records: [][]byte{{1, 2, 3}, {4, 5}}}
	getSnapshot := GetSnapshot{Version: Version0, TipID: status.TipID}
	manifest := SnapshotManifest{Version: Version0, Value: []byte{1, 2, 3}}
	chunk := SnapshotChunk{Version: Version0, Value: []byte{4, 5, 6}}
	snapshotDone := SnapshotDone{Version: Version0, TipID: status.TipID}
	share := testWorkShare(t)
	shareID, _ := share.ID()
	shareContext := contextFromTestShare(share)
	inventory := ShareInventory{Version: Version0, Context: shareContext, IDs: []types.Hash{shareID}}
	getShares := GetShares{Version: Version0, Context: shareContext, IDs: []types.Hash{shareID}}
	shares := Shares{Version: Version0, Context: shareContext, Values: []workgraph.Share{share}}
	messages := []Message{
		status, request, headerRequest, headerBatch, blockMessage, transactionMessage, done, result,
		getPeers, peers, getSnapshot, manifest, chunk, snapshotDone, inventory, getShares, shares,
	}

	var storage bytes.Buffer
	writer := oneByteWriter{writer: &storage}
	for _, message := range messages {
		if err := WriteMessage(writer, message); err != nil {
			t.Fatal(err)
		}
	}
	for index, want := range messages {
		got, err := ReadMessage(&storage)
		if err != nil {
			t.Fatalf("message %d: %v", index, err)
		}
		wantPayload, _ := encodePayload(want)
		gotPayload, _ := encodePayload(got)
		if want.messageType() != got.messageType() || !bytes.Equal(wantPayload, gotPayload) {
			t.Fatalf("message %d changed during round trip", index)
		}
	}
	if storage.Len() != 0 {
		t.Fatal("reader left framed bytes behind")
	}
}

func TestReadRejectsOversizeBeforeReadingPayload(t *testing.T) {
	t.Parallel()

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(MaxFrameBodyBytes+1))
	if _, err := ReadMessage(bytes.NewReader(header[:])); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("got %v, want frame-size rejection", err)
	}
}

func TestRejectsUnknownTypeTrailingBytesAndDuplicateLocators(t *testing.T) {
	t.Parallel()

	if _, err := DecodeFrameBody([]byte{0xff}); !errors.Is(err, ErrMessageType) {
		t.Fatalf("unknown type error = %v", err)
	}
	payload, err := encodePayload(testStatus())
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte{byte(TypeStatus)}, payload...)
	body = append(body, 0)
	if _, err := DecodeFrameBody(body); !errors.Is(err, codec.ErrTrailingBytes) {
		t.Fatalf("trailing-byte error = %v", err)
	}
	id := types.DomainHash("test/wire/locator")
	if err := (GetBlocks{Version: Version0, Locators: []types.Hash{id, id}, Limit: 1}).Validate(); !errors.Is(err, ErrDuplicateLocator) {
		t.Fatalf("duplicate locator error = %v", err)
	}
	if err := (GetHeaders{Version: Version0, Locators: []types.Hash{id, id}, Limit: 1}).Validate(); !errors.Is(err, ErrDuplicateLocator) {
		t.Fatalf("duplicate header locator error = %v", err)
	}
}

func TestHeadersRejectDiscontinuityAndOversizeRequest(t *testing.T) {
	t.Parallel()

	first := testBlock(t).Header
	second := first
	second.Height++
	second.Parent = types.DomainHash("test/wire/wrong-header-parent")
	batch := Headers{
		Version: Version0,
		Values:  []block.Header{first, second},
		TipID:   types.DomainHash("test/wire/header-tip"),
	}
	if err := batch.Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("discontinuous headers error = %v", err)
	}
	id := types.DomainHash("test/wire/header-locator")
	if err := (GetHeaders{Version: Version0, Locators: []types.Hash{id}, Limit: MaxHeadersPerRequest + 1}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("oversize header request error = %v", err)
	}
}

func TestReadRejectsTruncatedFrame(t *testing.T) {
	t.Parallel()

	var frame bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 10)
	frame.Write(header[:])
	frame.WriteByte(byte(TypeStatus))
	if _, err := ReadMessage(&frame); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want unexpected EOF", err)
	}
}

func TestPeerMessagesEnforceBounds(t *testing.T) {
	t.Parallel()

	if err := (GetPeers{Version: Version0, Limit: 0}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("zero peer limit error = %v", err)
	}
	if err := (GetPeers{Version: Version0, Limit: MaxPeerRecords + 1}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("large peer limit error = %v", err)
	}
	if err := (Peers{Version: Version0, Records: [][]byte{{}}}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("empty record error = %v", err)
	}
	tooMany := make([][]byte, MaxPeerRecords+1)
	for index := range tooMany {
		tooMany[index] = []byte{1}
	}
	if err := (Peers{Version: Version0, Records: tooMany}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("record count error = %v", err)
	}
}

func TestWorkShareMessagesEnforceInventoryFirstBounds(t *testing.T) {
	t.Parallel()

	share := testWorkShare(t)
	shareID, err := share.ID()
	if err != nil {
		t.Fatal(err)
	}
	context := contextFromTestShare(share)
	if err := (ShareInventory{
		Version: Version0, Context: context, IDs: []types.Hash{shareID, shareID},
	}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("duplicate inventory error=%v", err)
	}
	tooMany := make([]types.Hash, MaxSharesPerMessage+1)
	for index := range tooMany {
		tooMany[index] = types.DomainHash("test/wire/share/request", []byte{byte(index >> 8), byte(index)})
	}
	sort.Slice(tooMany, func(left, right int) bool { return types.CompareHash(tooMany[left], tooMany[right]) < 0 })
	if err := (GetShares{Version: Version0, Context: context, IDs: tooMany}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("oversize share request error=%v", err)
	}
	mismatch := share
	mismatch.PayloadRoot = types.DomainHash("test/wire/share/other-payload")
	if err := (Shares{
		Version: Version0, Context: context, Values: []workgraph.Share{mismatch},
	}).Validate(); !errors.Is(err, ErrMessage) {
		t.Fatalf("mixed payload response error=%v", err)
	}

	values := make([]workgraph.Share, MaxSharesPerMessage)
	for index := range values {
		values[index] = share
		values[index].Nonce = uint64(index)
	}
	sort.Slice(values, func(left, right int) bool {
		leftID, _ := values[left].ID()
		rightID, _ := values[right].ID()
		return types.CompareHash(leftID, rightID) < 0
	})
	batch := Shares{Version: Version0, Context: context, Values: values}
	payload, err := encodePayload(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 96*1024 {
		t.Fatalf("bounded share response bytes=%d", len(payload))
	}
	decoded, err := DecodeFrameBody(append([]byte{byte(TypeShares)}, payload...))
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.(Shares); len(got.Values) != MaxSharesPerMessage {
		t.Fatalf("decoded shares=%d", len(got.Values))
	}
}

func FuzzDecodeFrameBodyNeverPanics(f *testing.F) {
	payload, err := encodePayload(testStatus())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append([]byte{byte(TypeStatus)}, payload...))
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = DecodeFrameBody(input)
	})
}

type oneByteWriter struct {
	writer io.Writer
}

func (writer oneByteWriter) Write(input []byte) (int, error) {
	if len(input) > 1 {
		input = input[:1]
	}
	return writer.writer.Write(input)
}

func testStatus() Status {
	return Status{
		Version:        Version0,
		NetworkID:      91,
		GenesisID:      types.DomainHash("test/wire/genesis"),
		TipID:          types.DomainHash("test/wire/tip"),
		StateRoot:      types.DomainHash("test/wire/state-root"),
		TipHeight:      4,
		CumulativeWork: []byte{7},
		MaxFrameBytes:  uint32(MaxFrameBodyBytes),
	}
}

func testBlock(t testing.TB) block.Block {
	t.Helper()
	var target types.Hash
	for index := range target {
		target[index] = 0xff
	}
	parent := block.Parent{
		ID:             types.DomainHash("test/wire/block/parent"),
		Timestamp:      1_700_000_000,
		MedianTimePast: 1_700_000_000,
		Target:         target,
	}
	parameters := block.Parameters{
		NetworkID:       91,
		BlockSubsidy:    10,
		AnchorTimestamp: parent.Timestamp,
		AnchorTarget:    target,
		TargetSpacing:   1,
		ASERTHalfLife:   block.DefaultASERTHalfLife,
		RewardMaturity:  block.DefaultRewardMaturity,
	}
	value, _, err := block.Prepare(
		state.Empty(), parent, nil,
		types.Address(types.DomainHash("test/wire/block/miner")),
		parent.Timestamp+1, parameters,
	)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testTransaction(t testing.TB) outcome.Transaction {
	t.Helper()
	seed := types.DomainHash("test/wire/transaction/key")
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	owner, err := types.AddressFromPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	preState, err := state.New([]resource.Resource{{
		ID:      types.ResourceID(types.DomainHash("test/wire/transaction/input")),
		Version: resource.Version0,
		Owner:   owner,
		Asset:   types.NativeAssetID(),
		Amount:  100,
	}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := wallet.BuildNativeTransfer(preState, privateKey, wallet.TransferRequest{
		NetworkID:     91,
		CurrentHeight: 0,
		ValidFor:      10,
		Recipient:     types.Address(types.DomainHash("test/wire/transaction/recipient")),
		Amount:        10,
		Fee:           1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testWorkShare(t testing.TB) workgraph.Share {
	t.Helper()
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	return workgraph.Share{
		Version: workgraph.Version0, NetworkID: 91, Height: 5,
		AnchorParent: types.DomainHash("test/wire/share/anchor"), Timestamp: 1_700_000_000,
		Target: target, PayloadRoot: types.DomainHash("test/wire/share/payload"),
		Miner: types.Address(types.DomainHash("test/wire/share/miner")), InclusionRoot: inclusion,
	}
}

func contextFromTestShare(share workgraph.Share) ShareContext {
	return ShareContext{
		NetworkID: share.NetworkID, Height: share.Height, AnchorParent: share.AnchorParent,
		AnchorTarget: share.Target, PayloadRoot: share.PayloadRoot,
	}
}
