package activation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workchain"
	"github.com/outcomemesh/outcomemesh/storage"
	pebblestore "github.com/outcomemesh/outcomemesh/storage/pebble"
)

func TestPersistentRouterRecoversEveryActivationBaseAndForkChoice(t *testing.T) {
	document, config := persistentActivationSettings(t)
	root := t.TempDir()
	ledgerPath := filepath.Join(root, "ledger")
	config.WorkRoot = filepath.Join(root, "work-forest")
	config.MaxWorkTrees = 4
	config.WorkPolicy = workchain.DefaultPolicy()
	config.WorkPolicy.MaxHistoryBytes = 64 << 20
	ledger, err := pebblestore.Open(ledgerPath, document)
	if err != nil {
		t.Fatal(err)
	}
	router, err := New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	genesisTip, _ := storage.GenesisTip(document)
	baseA := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("persistent-base-a"))
	baseB := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("persistent-base-b"))
	baseAID, _ := baseA.Header.ID()
	baseBID, _ := baseB.Header.ID()
	for _, candidate := range []legacyblock.Block{baseA, baseB} {
		routed, routeErr := Legacy(candidate, config.Work.ActivationHeight)
		if routeErr != nil {
			t.Fatal(routeErr)
		}
		if _, err := router.Submit(routed); err != nil {
			t.Fatal(err)
		}
	}

	workA2 := mineWorkOn(t, router, baseAID, baseA.Header.Timestamp+60, "persistent-a-2")
	idA2 := submitWork(t, router, workA2, config.Work.ActivationHeight)
	workA3 := mineWorkOn(t, router, idA2, workA2.Header.Seal.Timestamp+60, "persistent-a-3")
	idA3 := submitWork(t, router, workA3, config.Work.ActivationHeight)
	workB2 := mineWorkOn(t, router, baseBID, baseB.Header.Timestamp+60, "persistent-b-2")
	idB2 := submitWork(t, router, workB2, config.Work.ActivationHeight)
	workB3 := mineWorkOn(t, router, idB2, workB2.Header.Seal.Timestamp+60, "persistent-b-3")
	idB3 := submitWork(t, router, workB3, config.Work.ActivationHeight)
	workB4 := mineWorkOn(t, router, idB3, workB3.Header.Seal.Timestamp+60, "persistent-b-4")
	idB4 := submitWork(t, router, workB4, config.Work.ActivationHeight)
	winnerBeforeRestart, err := router.Tip()
	if err != nil || winnerBeforeRestart.ID != idB4 {
		t.Fatalf("winner before restart=%+v err=%v", winnerBeforeRestart, err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	ledger, err = pebblestore.Open(ledgerPath, document)
	if err != nil {
		t.Fatal(err)
	}
	router, err = New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := router.Tip()
	if err != nil || !storage.EqualTips(recovered, winnerBeforeRestart) {
		t.Fatalf("recovered winner=%+v want=%+v err=%v", recovered, winnerBeforeRestart, err)
	}
	sideBlock, err := router.BlockByID(idA3)
	if err != nil || sideBlock.Version() != workblock.Version1 {
		t.Fatalf("recovered side block version=%d err=%v", sideBlock.Version(), err)
	}
	if _, _, err := router.PrepareWork(idA3, workA3.Header.Seal.Timestamp+60, nil); err != nil {
		t.Fatalf("recovered side branch is not extendable: %v", err)
	}
	snapshot, err := router.Snapshot()
	if err != nil || snapshot.Root() != recovered.StateRoot {
		t.Fatalf("recovered snapshot root=%s want=%s err=%v", snapshot.Root(), recovered.StateRoot, err)
	}

	workA4 := mineWorkOn(t, router, idA3, workA3.Header.Seal.Timestamp+60, "persistent-a-4")
	idA4 := submitWork(t, router, workA4, config.Work.ActivationHeight)
	workA5 := mineWorkOn(t, router, idA4, workA4.Header.Seal.Timestamp+60, "persistent-a-5")
	idA5 := submitWork(t, router, workA5, config.Work.ActivationHeight)
	winnerAfterReorg, err := router.Tip()
	if err != nil || winnerAfterReorg.ID != idA5 {
		t.Fatalf("winner after recovered-tree reorg=%+v err=%v", winnerAfterReorg, err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	ledger, err = pebblestore.Open(ledgerPath, document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	router, err = New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	secondRecovery, err := router.Tip()
	if err != nil || !storage.EqualTips(secondRecovery, winnerAfterReorg) {
		t.Fatalf("second recovered winner=%+v want=%+v err=%v", secondRecovery, winnerAfterReorg, err)
	}
	forest, err := router.WorkForestStatus()
	if err != nil || !forest.Persistent || forest.Trees != 2 || forest.Nodes != 9 ||
		forest.HistoryBytes == 0 || forest.HistoryBytes > forest.MaxHistoryBytes || forest.MaxTrees != 4 {
		t.Fatalf("recovered forest status=%+v err=%v", forest, err)
	}
	entries, err := os.ReadDir(config.WorkRoot)
	if err != nil || len(entries) != 4 {
		t.Fatalf("forest entries=%d err=%v", len(entries), err)
	}
}

func TestPersistentRouterPreservesCrossBaseEqualWorkIncumbent(t *testing.T) {
	document, config := persistentActivationSettings(t)
	root := t.TempDir()
	ledgerPath := filepath.Join(root, "ledger")
	config.WorkRoot = filepath.Join(root, "work-forest")
	config.MaxWorkTrees = 2
	config.WorkPolicy = workchain.DefaultPolicy()
	ledger, err := pebblestore.Open(ledgerPath, document)
	if err != nil {
		t.Fatal(err)
	}
	router, err := New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	genesisTip, _ := storage.GenesisTip(document)
	baseA := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("selected-base-a"))
	baseB := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("selected-base-b"))
	baseAID, _ := baseA.Header.ID()
	baseBID, _ := baseB.Header.ID()
	for _, candidate := range []legacyblock.Block{baseA, baseB} {
		routed, _ := Legacy(candidate, config.Work.ActivationHeight)
		if _, err := router.Submit(routed); err != nil {
			t.Fatal(err)
		}
	}
	workA := mineWorkOn(t, router, baseAID, baseA.Header.Timestamp+60, "selected-work-a")
	workB := mineWorkOn(t, router, baseBID, baseB.Header.Timestamp+60, "selected-work-b")
	idA := submitWork(t, router, workA, config.Work.ActivationHeight)
	idB := submitWork(t, router, workB, config.Work.ActivationHeight)
	before, err := router.Tip()
	if err != nil || before.ID != idA {
		t.Fatalf("pre-restart incumbent=%+v want=%s competitor=%s err=%v", before, idA, idB, err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	ledger, err = pebblestore.Open(ledgerPath, document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	router, err = New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	after, err := router.Tip()
	if err != nil || after.ID != idA {
		t.Fatalf("recovered incumbent=%+v want=%s err=%v", after, idA, err)
	}
	selectedInfo, err := os.Stat(filepath.Join(config.WorkRoot, workForestSelectedName))
	if err != nil || selectedInfo.Mode().Perm() != 0o600 {
		t.Fatalf("selected checkpoint mode=%v err=%v", selectedInfo, err)
	}
}

func TestPersistentRouterMigratesMissingSelectionAndRejectsCorruption(t *testing.T) {
	document, config := persistentActivationSettings(t)
	root := t.TempDir()
	config.WorkRoot = filepath.Join(root, "work-forest")
	config.WorkPolicy = workchain.DefaultPolicy()
	ledger, err := pebblestore.Open(filepath.Join(root, "ledger"), document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	router, err := New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	selectedPath := filepath.Join(config.WorkRoot, workForestSelectedName)
	selectionBytes, err := os.ReadFile(selectedPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(selectedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.WorkRoot, workForestSelectPending), selectionBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	router, err = New(ledger, config)
	if err != nil {
		t.Fatalf("missing selection was not migrated: %v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(selectedPath); err != nil {
		t.Fatalf("migrated selection stat error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(config.WorkRoot, workForestSelectPending)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale selection pending stat error=%v", err)
	}
	if err := os.WriteFile(selectedPath, append([]byte(nil), workForestSelectedMagic...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ledger, config); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("truncated selection error=%v", err)
	}
}

func FuzzDecodeWorkForestSelectionNeverPanics(f *testing.F) {
	selected := types.DomainHash("test/activation/selected-fuzz")
	encoded := append(append([]byte(nil), workForestSelectedMagic...), selected[:]...)
	f.Add(encoded)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decodeWorkForestSelection(input)
	})
}

func TestPersistentRouterRecoversEmptyTreeCreatedBeforePebbleOpen(t *testing.T) {
	document, config := persistentActivationSettings(t)
	root := t.TempDir()
	config.WorkRoot = filepath.Join(root, "work-forest")
	config.MaxWorkTrees = 2
	config.WorkPolicy = workchain.DefaultPolicy()
	config.WorkPolicy.MaxHistoryBytes = 32 << 20
	ledger, err := pebblestore.Open(filepath.Join(root, "ledger"), document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	router, err := New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	genesisTip, _ := storage.GenesisTip(document)
	base := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("empty-tree-base"))
	routed, _ := Legacy(base, config.Work.ActivationHeight)
	if _, err := router.Submit(routed); err != nil {
		t.Fatal(err)
	}
	baseID, _ := base.Header.ID()
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(config.WorkRoot, baseID.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syncDirectory(config.WorkRoot); err != nil {
		t.Fatal(err)
	}

	router, err = New(ledger, config)
	if err != nil {
		t.Fatalf("empty crash-boundary tree did not recover: %v", err)
	}
	work := mineWorkOn(t, router, baseID, base.Header.Timestamp+60, "empty-tree-work")
	workID := submitWork(t, router, work, config.Work.ActivationHeight)
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	router, err = New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	tip, err := router.Tip()
	if err != nil || tip.ID != workID {
		t.Fatalf("tree initialized after crash boundary tip=%+v err=%v", tip, err)
	}
}

func TestPersistentRouterRejectsSwappedAndUnknownTreeDirectories(t *testing.T) {
	t.Run("unknown base", func(t *testing.T) {
		document, config := persistentActivationSettings(t)
		root := t.TempDir()
		config.WorkRoot = filepath.Join(root, "work-forest")
		config.MaxWorkTrees = 2
		config.WorkPolicy = workchain.DefaultPolicy()
		ledger, err := pebblestore.Open(filepath.Join(root, "ledger"), document)
		if err != nil {
			t.Fatal(err)
		}
		defer ledger.Close()
		router, err := New(ledger, config)
		if err != nil {
			t.Fatal(err)
		}
		if err := router.Close(); err != nil {
			t.Fatal(err)
		}
		unknown := types.DomainHash("test/activation/unknown-persisted-base")
		if err := os.Mkdir(filepath.Join(config.WorkRoot, unknown.String()), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := New(ledger, config); !errors.Is(err, storage.ErrCorrupt) {
			t.Fatalf("unknown persisted base error=%v", err)
		}
	})

	t.Run("swapped databases", func(t *testing.T) {
		document, config := persistentActivationSettings(t)
		root := t.TempDir()
		config.WorkRoot = filepath.Join(root, "work-forest")
		config.MaxWorkTrees = 2
		config.WorkPolicy = workchain.DefaultPolicy()
		ledger, err := pebblestore.Open(filepath.Join(root, "ledger"), document)
		if err != nil {
			t.Fatal(err)
		}
		defer ledger.Close()
		router, err := New(ledger, config)
		if err != nil {
			t.Fatal(err)
		}
		genesisTip, _ := storage.GenesisTip(document)
		baseA := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("swap-base-a"))
		baseB := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("swap-base-b"))
		baseAID, _ := baseA.Header.ID()
		baseBID, _ := baseB.Header.ID()
		for _, candidate := range []legacyblock.Block{baseA, baseB} {
			routed, _ := Legacy(candidate, config.Work.ActivationHeight)
			if _, err := router.Submit(routed); err != nil {
				t.Fatal(err)
			}
		}
		submitWork(t, router, mineWorkOn(t, router, baseAID, baseA.Header.Timestamp+60, "swap-a"), config.Work.ActivationHeight)
		submitWork(t, router, mineWorkOn(t, router, baseBID, baseB.Header.Timestamp+60, "swap-b"), config.Work.ActivationHeight)
		if err := router.Close(); err != nil {
			t.Fatal(err)
		}
		pathA := filepath.Join(config.WorkRoot, baseAID.String())
		pathB := filepath.Join(config.WorkRoot, baseBID.String())
		temporary := filepath.Join(config.WorkRoot, "swap-temporary")
		if err := os.Rename(pathA, temporary); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(pathB, pathA); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temporary, pathB); err != nil {
			t.Fatal(err)
		}
		if _, err := New(ledger, config); !errors.Is(err, workchain.ErrConfiguration) {
			t.Fatalf("swapped WorkChain database error=%v", err)
		}
	})
}

func TestPersistentRouterEnforcesGlobalTreeCap(t *testing.T) {
	document, config := persistentActivationSettings(t)
	root := t.TempDir()
	config.WorkRoot = filepath.Join(root, "work-forest")
	config.MaxWorkTrees = 1
	config.WorkPolicy = workchain.DefaultPolicy()
	ledger, err := pebblestore.Open(filepath.Join(root, "ledger"), document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	router, err := New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	genesisTip, _ := storage.GenesisTip(document)
	baseA := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("limited-base-a"))
	baseB := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("limited-base-b"))
	baseAID, _ := baseA.Header.ID()
	baseBID, _ := baseB.Header.ID()
	for _, candidate := range []legacyblock.Block{baseA, baseB} {
		routed, _ := Legacy(candidate, config.Work.ActivationHeight)
		if _, err := router.Submit(routed); err != nil {
			t.Fatal(err)
		}
	}
	submitWork(t, router, mineWorkOn(t, router, baseAID, baseA.Header.Timestamp+60, "limited-a"), config.Work.ActivationHeight)
	workB := mineDetachedWorkOn(t, ledger, config, baseB, "limited-b")
	routedB, _ := Work(workB, config.Work.ActivationHeight)
	if _, err := router.Submit(routedB); !errors.Is(err, ErrTreeLimit) {
		t.Fatalf("second activation tree error=%v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(config.WorkRoot, baseBID.String()), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ledger, config); !errors.Is(err, ErrTreeLimit) {
		t.Fatalf("oversized recovered forest error=%v", err)
	}
}

func TestPersistentRouterRecoversPendingManifestAndRejectsCorruption(t *testing.T) {
	document, config := persistentActivationSettings(t)
	root := t.TempDir()
	config.WorkRoot = filepath.Join(root, "work-forest")
	config.WorkPolicy = workchain.DefaultPolicy()
	if err := os.Mkdir(config.WorkRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(config.WorkRoot, workForestPendingName), workForestManifest, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	ledger, err := pebblestore.Open(filepath.Join(root, "ledger"), document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	router, err := New(ledger, config)
	if err != nil {
		t.Fatalf("complete pending forest manifest: %v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(config.WorkRoot, workForestPendingName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending manifest still exists: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(config.WorkRoot, workForestManifestName), make([]byte, len(workForestManifest)), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ledger, config); !errors.Is(err, storage.ErrCorrupt) {
		t.Fatalf("corrupt forest manifest error=%v", err)
	}
}

func TestPersistentRouterStaticallyPartitionsGlobalHistoryBudget(t *testing.T) {
	document, config := persistentActivationSettings(t)
	root := t.TempDir()
	config.WorkRoot = filepath.Join(root, "work-forest")
	config.MaxWorkTrees = 2
	config.WorkPolicy = workchain.DefaultPolicy()
	config.WorkPolicy.MaxHistoryBytes = 2
	ledger, err := pebblestore.Open(filepath.Join(root, "ledger"), document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	router, err := New(ledger, config)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	genesisTip, _ := storage.GenesisTip(document)
	base := mineLegacyOn(t, ledger, config.Legacy, genesisTip, activationAddress("history-budget-base"))
	routedBase, _ := Legacy(base, config.Work.ActivationHeight)
	if _, err := router.Submit(routedBase); err != nil {
		t.Fatal(err)
	}
	baseID, _ := base.Header.ID()
	work := mineDetachedWorkOn(t, ledger, config, base, "history-budget-work")
	routedWork, _ := Work(work, config.Work.ActivationHeight)
	if _, err := router.Submit(routedWork); !errors.Is(err, storage.ErrHistoryLimit) {
		t.Fatalf("partitioned forest history budget error=%v", err)
	}
	if _, _, err := router.PrepareWork(baseID, base.Header.Timestamp+60, nil); !errors.Is(err, storage.ErrHistoryLimit) {
		t.Fatalf("retry after history budget error=%v", err)
	}
}

func TestRouterRejectsInvalidPersistentForestConfiguration(t *testing.T) {
	document, config := persistentActivationSettings(t)
	ledger, err := pebblestore.Open(filepath.Join(t.TempDir(), "ledger"), document)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()

	config.MaxWorkTrees = MaxWorkTreesLimit + 1
	if _, err := New(ledger, config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("oversized tree cap error=%v", err)
	}
	config.MaxWorkTrees = 2
	config.WorkPolicy = workchain.DefaultPolicy()
	if _, err := New(ledger, config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("policy without persistent root error=%v", err)
	}
	config.WorkRoot = "relative/work-forest"
	if _, err := New(ledger, config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("relative persistent root error=%v", err)
	}
	config.WorkRoot = filepath.Join(t.TempDir(), "work-forest")
	config.WorkPolicy.MaxHistoryBytes = 1
	if _, err := New(ledger, config); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("forest budget below tree partition count error=%v", err)
	}
}

func persistentActivationSettings(t testing.TB) (genesis.Document, Config) {
	t.Helper()
	var target types.Hash
	target[1] = 0x7f
	for index := 2; index < len(target); index++ {
		target[index] = 0xff
	}
	document := genesis.Document{
		Version: genesis.Version0, NetworkID: 84, Timestamp: 1_700_000_000,
		Target: target, BlockSubsidy: 10_220,
	}
	legacy := legacyblock.ParametersFromGenesis(document)
	return document, Config{
		Legacy: legacy,
		Work: workblock.Parameters{
			NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy,
			RewardMaturity: legacy.RewardMaturity, ActivationHeight: 2,
			DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
			TargetSpacing: legacy.TargetSpacing, ASERTHalfLife: legacy.ASERTHalfLife, FeeDelay: 3,
		},
		Now: func() uint64 { return document.Timestamp + 10_000 },
	}
}

func mineDetachedWorkOn(
	t testing.TB,
	ledger storage.Ledger,
	config Config,
	base legacyblock.Block,
	label string,
) workblock.Block {
	t.Helper()
	baseID, _ := base.Header.ID()
	baseTip, err := ledger.TipByID(baseID)
	if err != nil {
		t.Fatal(err)
	}
	baseState, err := ledger.SnapshotAt(baseID)
	if err != nil {
		t.Fatal(err)
	}
	store, err := workchain.New(workchain.Base{
		Tip: baseTip, State: baseState, RecentTimestamps: []uint64{base.Header.Timestamp},
	}, config.Work)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	payload, _, err := store.Prepare(baseID, base.Header.Timestamp+60, nil)
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
	seal, _, err := workgraph.MineAnchor(context.Background(), template, 0)
	if err != nil {
		t.Fatal(err)
	}
	candidate, _, err := payload.Finalize(seal, nil)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
