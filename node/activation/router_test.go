package activation

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/storage"
	"github.com/outcomemesh/outcomemesh/storage/reference"
)

func TestRouterReorganizesAcrossDistinctActivationBases(t *testing.T) {
	router, ledger, document, config := activationFixture(t)
	defer ledger.Close()
	genesisTip, err := storage.GenesisTip(document)
	if err != nil {
		t.Fatal(err)
	}
	baseA := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("base-a"))
	baseB := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("base-b"))
	baseAID, _ := baseA.Header.ID()
	baseBID, _ := baseB.Header.ID()
	for _, candidate := range []legacyblock.Block{baseA, baseB} {
		routed, err := Legacy(candidate, config.Work.ActivationHeight)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := router.Submit(routed); err != nil {
			t.Fatal(err)
		}
	}

	workA2 := mineWorkOn(t, router, baseAID, baseA.Header.Timestamp+60, "work-a-2")
	workB2 := mineWorkOn(t, router, baseBID, baseB.Header.Timestamp+60, "work-b-2")
	idA2 := submitWork(t, router, workA2, config.Work.ActivationHeight)
	idB2 := submitWork(t, router, workB2, config.Work.ActivationHeight)
	duplicateA2, _ := Work(workA2, config.Work.ActivationHeight)
	if _, err := router.Submit(duplicateA2); !errors.Is(err, storage.ErrBlockExists) {
		t.Fatalf("duplicate routed v1 block error=%v", err)
	}
	tip, err := router.Tip()
	if err != nil {
		t.Fatal(err)
	}
	wantTie := idA2
	if tip.ID != wantTie || tip.Height != config.Work.ActivationHeight {
		t.Fatalf("cross-base equal-work displaced incumbent tip=%+v want=%s competitor=%s", tip, wantTie, idB2)
	}

	workA3 := mineWorkOn(t, router, idA2, workA2.Header.Seal.Timestamp+60, "work-a-3")
	idA3 := submitWork(t, router, workA3, config.Work.ActivationHeight)
	tip, _ = router.Tip()
	if tip.ID != idA3 || tip.Height != config.Work.ActivationHeight+1 {
		t.Fatalf("first extended activation tree did not win: %+v", tip)
	}
	workB3 := mineWorkOn(t, router, idB2, workB2.Header.Seal.Timestamp+60, "work-b-3")
	idB3 := submitWork(t, router, workB3, config.Work.ActivationHeight)
	workB4 := mineWorkOn(t, router, idB3, workB3.Header.Seal.Timestamp+60, "work-b-4")
	idB4 := submitWork(t, router, workB4, config.Work.ActivationHeight)
	tip, _ = router.Tip()
	if tip.ID != idB4 || tip.Height != config.Work.ActivationHeight+2 {
		t.Fatalf("deeper alternate activation base did not reorg: %+v", tip)
	}
	legacyTip, err := ledger.Tip()
	if err != nil {
		t.Fatal(err)
	}
	if legacyTip.Height != config.Work.ActivationHeight-1 || tip.ID == legacyTip.ID {
		t.Fatalf("legacy and routed tips were conflated: legacy=%+v routed=%+v", legacyTip, tip)
	}
	snapshot, err := router.Snapshot()
	if err != nil || snapshot.Root() != tip.StateRoot {
		t.Fatalf("routed snapshot root=%s want=%s err=%v", snapshot.Root(), tip.StateRoot, err)
	}
	loaded, err := router.BlockByID(idA3)
	if err != nil || loaded.Version() != workblock.Version1 {
		t.Fatalf("side-tree block lookup version=%d err=%v", loaded.Version(), err)
	}
	if _, _, err := router.PrepareWork(types.DomainHash("unknown/activation/parent"), tip.Timestamp+60, nil); !errors.Is(err, ErrParent) {
		t.Fatalf("unknown WorkGraph parent error=%v", err)
	}
}

func TestWorkAdmissionObserverRunsOnceOutsideRouterLock(t *testing.T) {
	var router *Router
	var observed []WorkAdmission
	observer := func(event WorkAdmission) {
		if _, err := router.Tip(); err != nil {
			t.Errorf("observer could not reenter router: %v", err)
		}
		observed = append(observed, event)
	}
	var ledger *reference.Store
	var document genesis.Document
	var config Config
	router, ledger, document, config = activationFixtureWithObserver(t, observer)
	defer ledger.Close()
	genesisTip, _ := storage.GenesisTip(document)
	base := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("observer-base"))
	routedBase, _ := Legacy(base, config.Work.ActivationHeight)
	if _, err := router.Submit(routedBase); err != nil {
		t.Fatal(err)
	}
	if len(observed) != 0 {
		t.Fatalf("legacy block produced WorkGraph admission: %+v", observed)
	}
	baseID, _ := base.Header.ID()
	work := mineWorkOn(t, router, baseID, base.Header.Timestamp+60, "observer-work")
	routedWork, _ := Work(work, config.Work.ActivationHeight)
	selected, err := router.Submit(routedWork)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 {
		t.Fatalf("admission count = %d, want 1", len(observed))
	}
	id, _ := work.Header.ID()
	event := observed[0]
	if event.ID != id || event.ParentID != baseID || event.Height != work.Header.Seal.Height ||
		event.BlockTimestamp != work.Header.Seal.Timestamp || event.ObservedAt != document.Timestamp+10_000 ||
		event.Miner != work.Header.Seal.Miner || event.Sequence != 1 || event.SelectedID != selected.ID ||
		event.Selected != (selected.ID == id) {
		t.Fatalf("admission = %+v", event)
	}
	if _, err := router.Submit(routedWork); !errors.Is(err, storage.ErrBlockExists) {
		t.Fatalf("duplicate error = %v", err)
	}
	if len(observed) != 1 {
		t.Fatalf("duplicate produced admission: %+v", observed)
	}
}

func TestRouterCloseWaitsForCommittedAdmissionObserver(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	observer := func(WorkAdmission) {
		close(entered)
		<-release
	}
	router, ledger, document, config := activationFixtureWithObserver(t, observer)
	defer ledger.Close()
	genesisTip, _ := storage.GenesisTip(document)
	base := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("close-observer-base"))
	routedBase, _ := Legacy(base, config.Work.ActivationHeight)
	if _, err := router.Submit(routedBase); err != nil {
		t.Fatal(err)
	}
	baseID, _ := base.Header.ID()
	work := mineWorkOn(t, router, baseID, base.Header.Timestamp+60, "close-observer-work")
	routedWork, _ := Work(work, config.Work.ActivationHeight)
	submitted := make(chan error, 1)
	go func() {
		_, err := router.Submit(routedWork)
		submitted <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- router.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("router closed before admission observer returned: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-submitted; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestWorkAdmissionCallbacksPreserveCommitOrderAcrossConcurrentSubmits(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	events := make(chan WorkAdmission, 2)
	observer := func(event WorkAdmission) {
		if event.Sequence == 1 {
			close(entered)
			<-release
		}
		events <- event
	}
	router, ledger, document, config := activationFixtureWithObserver(t, observer)
	defer ledger.Close()
	genesisTip, _ := storage.GenesisTip(document)
	base := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("ordered-observer-base"))
	routedBase, _ := Legacy(base, config.Work.ActivationHeight)
	if _, err := router.Submit(routedBase); err != nil {
		t.Fatal(err)
	}
	baseID, _ := base.Header.ID()
	first := mineWorkOn(t, router, baseID, base.Header.Timestamp+60, "ordered-observer-first")
	second := mineWorkOn(t, router, baseID, base.Header.Timestamp+60, "ordered-observer-second")
	routedFirst, _ := Work(first, config.Work.ActivationHeight)
	routedSecond, _ := Work(second, config.Work.ActivationHeight)
	firstDone := make(chan error, 1)
	go func() {
		_, err := router.Submit(routedFirst)
		firstDone <- err
	}()
	<-entered
	secondDone := make(chan error, 1)
	go func() {
		_, err := router.Submit(routedSecond)
		secondDone <- err
	}()
	select {
	case err := <-secondDone:
		t.Fatalf("second callback bypassed blocked first callback: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	firstEvent := <-events
	secondEvent := <-events
	firstID, _ := first.Header.ID()
	secondID, _ := second.Header.ID()
	if firstEvent.Sequence != 1 || firstEvent.ID != firstID || firstEvent.SelectedID != firstID ||
		secondEvent.Sequence != 2 || secondEvent.ID != secondID || secondEvent.SelectedID != firstID {
		t.Fatalf("ordered events first=%+v second=%+v", firstEvent, secondEvent)
	}
}

func TestRoutedBlockCodecEnforcesActivationHeight(t *testing.T) {
	router, ledger, document, config := activationFixture(t)
	defer ledger.Close()
	genesisTip, _ := storage.GenesisTip(document)
	legacy := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("codec-v0"))
	routedLegacy, err := Legacy(legacy, config.Work.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	decodedLegacy, err := Decode(routedLegacy.CanonicalBytes(), config.Work.ActivationHeight)
	if err != nil || decodedLegacy.Version() != legacyblock.Version0 ||
		!bytes.Equal(decodedLegacy.CanonicalBytes(), routedLegacy.CanonicalBytes()) {
		t.Fatalf("legacy route roundtrip version=%d err=%v", decodedLegacy.Version(), err)
	}
	if _, err := router.Submit(routedLegacy); err != nil {
		t.Fatal(err)
	}
	legacyID, _ := routedLegacy.ID()
	work := mineWorkOn(t, router, legacyID, legacy.Header.Timestamp+60, "codec-v1")
	routedWork, err := Work(work, config.Work.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	decodedWork, err := Decode(routedWork.CanonicalBytes(), config.Work.ActivationHeight)
	if err != nil || decodedWork.Version() != workblock.Version1 ||
		!bytes.Equal(decodedWork.CanonicalBytes(), routedWork.CanonicalBytes()) {
		t.Fatalf("work route roundtrip version=%d err=%v", decodedWork.Version(), err)
	}
	if _, err := Decode(routedLegacy.CanonicalBytes(), 1); !errors.Is(err, ErrBoundary) {
		t.Fatalf("v0 at activation error=%v", err)
	}
	if _, err := Decode(routedWork.CanonicalBytes(), config.Work.ActivationHeight+1); !errors.Is(err, ErrBoundary) {
		t.Fatalf("early v1 error=%v", err)
	}
	if _, err := Decode([]byte{0, 4}, config.Work.ActivationHeight); !errors.Is(err, ErrEncoding) {
		t.Fatalf("unknown version error=%v", err)
	}
	baseTip, err := ledger.TipByID(legacyID)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenV0 := mineLegacyOn(t, ledger, config.Legacy, baseTip, activationAddress("forbidden-v0"))
	if _, err := Legacy(forbiddenV0, config.Work.ActivationHeight); !errors.Is(err, ErrBoundary) {
		t.Fatalf("v0 continuation at activation error=%v", err)
	}
}

func TestRouterRejectsMismatchedConsensusParameters(t *testing.T) {
	_, ledger, _, config := activationFixture(t)
	defer ledger.Close()
	config.Work.NetworkID++
	if _, err := New(ledger, config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("network mismatch error=%v", err)
	}
	config.Work.NetworkID = config.Legacy.NetworkID
	config.Work.ActivationHeight = 0
	if _, err := New(ledger, config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("zero activation error=%v", err)
	}
}

func TestRouterUsesOneExplicitAdmissionClockForBothVersions(t *testing.T) {
	_, ledger, document, config := activationFixture(t)
	defer ledger.Close()
	config.Now = func() uint64 { return document.Timestamp }
	router, err := New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	genesisTip, _ := storage.GenesisTip(document)
	futureLegacy := mineLegacyAt(
		t, ledger, config.Legacy, genesisTip, activationAddress("future-v0"), document.Timestamp+121,
	)
	routedFuture, err := Legacy(futureLegacy, config.Work.ActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.Submit(routedFuture); !errors.Is(err, legacyblock.ErrFutureTimestamp) {
		t.Fatalf("v0 explicit admission time error=%v", err)
	}
	base := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("clock-base"))
	routedBase, _ := Legacy(base, config.Work.ActivationHeight)
	if _, err := router.Submit(routedBase); err != nil {
		t.Fatal(err)
	}
	baseID, _ := base.Header.ID()
	futureWork := mineWorkOn(t, router, baseID, document.Timestamp+181, "future-v1")
	routedWork, _ := Work(futureWork, config.Work.ActivationHeight)
	if _, err := router.Submit(routedWork); !errors.Is(err, workblock.ErrFutureTime) {
		t.Fatalf("v1 explicit admission time error=%v", err)
	}
}

func FuzzDecodeRoutedBlockNeverPanics(f *testing.F) {
	router, ledger, document, config := activationFixture(f)
	genesisTip, _ := storage.GenesisTip(document)
	legacy := mineLegacyOn(f, ledger, config.Legacy, genesisTip, activationAddress("fuzz-v0"))
	routedLegacy, _ := Legacy(legacy, config.Work.ActivationHeight)
	if _, err := router.Submit(routedLegacy); err != nil {
		f.Fatal(err)
	}
	legacyID, _ := routedLegacy.ID()
	work := mineWorkOn(f, router, legacyID, legacy.Header.Timestamp+60, "fuzz-v1")
	routedWork, _ := Work(work, config.Work.ActivationHeight)
	f.Add(routedLegacy.CanonicalBytes())
	f.Add(routedWork.CanonicalBytes())
	f.Add([]byte{})
	_ = ledger.Close()
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := Decode(input, config.Work.ActivationHeight)
		if err != nil {
			return
		}
		if err := decoded.Validate(config.Work.ActivationHeight); err != nil {
			t.Fatalf("accepted routed block is invalid: %v", err)
		}
		if !bytes.Equal(input, decoded.CanonicalBytes()) {
			t.Fatal("accepted routed block was not canonical")
		}
	})
}

func activationFixture(t testing.TB) (*Router, *reference.Store, genesis.Document, Config) {
	return activationFixtureWithObserver(t, nil)
}

func activationFixtureWithObserver(
	t testing.TB,
	observer func(WorkAdmission),
) (*Router, *reference.Store, genesis.Document, Config) {
	t.Helper()
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version: genesis.Version0, NetworkID: 83, Timestamp: 1_700_000_000,
		Target: target, BlockSubsidy: 10_220,
	}
	ledger, err := reference.New(document)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyblock.ParametersFromGenesis(document)
	config := Config{
		Legacy: legacy,
		Work: workblock.Parameters{
			NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy,
			RewardMaturity: legacy.RewardMaturity, ActivationHeight: 2,
			DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
			TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: 3,
		},
		Now:         func() uint64 { return document.Timestamp + 10_000 },
		ObserveWork: observer,
	}
	router, err := New(ledger, config)
	if err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	return router, ledger, document, config
}

func mineLegacyOn(
	t testing.TB,
	ledger storage.Ledger,
	parameters legacyblock.Parameters,
	parentTip storage.Tip,
	miner types.Address,
) legacyblock.Block {
	return mineLegacyAt(
		t, ledger, parameters, parentTip, miner, parentTip.Timestamp+parameters.TargetSpacing,
	)
}

func mineLegacyAt(
	t testing.TB,
	ledger storage.Ledger,
	parameters legacyblock.Parameters,
	parentTip storage.Tip,
	miner types.Address,
	timestamp uint64,
) legacyblock.Block {
	t.Helper()
	preState, err := ledger.SnapshotAt(parentTip.ID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := storage.ParentContext(ledger, parentTip)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := legacyblock.Prepare(
		preState, parent, nil, miner, timestamp, parameters,
	)
	if err != nil {
		t.Fatal(err)
	}
	mined, _, err := legacyblock.Mine(context.Background(), candidate, 0)
	if err != nil {
		t.Fatal(err)
	}
	return mined
}

func mineWorkOn(
	t testing.TB,
	router *Router,
	parentID types.Hash,
	timestamp uint64,
	label string,
) workblock.Block {
	t.Helper()
	payload, _, err := router.PrepareWork(parentID, timestamp, nil)
	if err != nil {
		t.Fatal(err)
	}
	inclusion, err := workgraph.InclusionRoot(nil)
	if err != nil {
		t.Fatal(err)
	}
	template, err := payload.SealTemplate(activationAddress(label), inclusion, nil)
	if err != nil {
		t.Fatal(err)
	}
	anchor, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := payload.Finalize(anchor, nil)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func submitWork(t testing.TB, router *Router, candidate workblock.Block, activationHeight uint64) types.Hash {
	t.Helper()
	routed, err := Work(candidate, activationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.Submit(routed); err != nil {
		t.Fatal(err)
	}
	id, err := routed.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func activationAddress(label string) types.Address {
	return types.Address(types.DomainHash("test/activation/address", []byte(label)))
}
