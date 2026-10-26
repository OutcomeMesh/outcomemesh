package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	legacyblock "github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// This fixture has actual chain history and independently pinned owner pairs.
// The older command-only CLI fixtures deliberately cannot authorize a prune.
type pruneEffectCLIFixture struct {
	root, data, manifestPath, checkpointPath, rootsPath string
	config                                              authoritystore.PruneArchiveEffectServiceConfig
	inventory                                           authoritystore.ArchivePruneInventory
	assignments                                         []custodyauthority.Assignment
	admissions                                          []custodyauthority.Entry
}

type pruneEffectCLIState struct {
	Executor    authoritystore.PruneExecution
	Authorities []authoritystore.Coordination // inventory's immutable replica order
	Storage     workchain.StorageProtection
	History     uint64
	Effect      workchain.CanonicalPruneEffect
	EffectFound bool
}

func newPruneEffectCLIFixture(t testing.TB, lineage bool) *pruneEffectCLIFixture {
	t.Helper()
	f := &pruneEffectCLIFixture{root: t.TempDir()}
	f.data = filepath.Join(f.root, "node")
	if err := runInit([]string{"--data", f.data, "--network", "20261026", "--timestamp", "1700000000",
		"--difficulty-bits", "12", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10)}); err != nil {
		t.Fatal(err)
	}
	document, err := loadGenesis(f.data)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, err := document.ID()
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := openStore(f.data, document)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })
	legacyParameters := legacyblock.ParametersFromGenesis(document)
	legacy, err := chain.New(ledger, legacyParameters)
	if err != nil {
		t.Fatal(err)
	}
	mined, err := legacy.Mine(t.Context(), nil, defaultDevelopmentAddress(), document.Timestamp+60, 0)
	if err != nil {
		t.Fatal(err)
	}
	base, err := archiveBaseFromLedger(ledger, mined.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runWorkEnable([]string{"--data", f.data, "--activation-height", "2", "--confirm-genesis", genesisID.String(),
		"--max-trees", "4", "--max-history-bytes", strconv.FormatUint(minimumHistoryBytes, 10)}); err != nil {
		t.Fatal(err)
	}
	profile, err := loadWorkActivation(f.data, document)
	if err != nil {
		t.Fatal(err)
	}
	parameters := workblock.Parameters{NetworkID: document.NetworkID, BlockSubsidy: document.BlockSubsidy,
		RewardMaturity: legacyParameters.RewardMaturity, ActivationHeight: profile.ActivationHeight,
		DifficultyAnchorTimestamp: document.Timestamp, DifficultyAnchorTarget: document.Target,
		TargetSpacing: legacyParameters.TargetSpacing, ASERTHalfLife: legacyParameters.ASERTHalfLife, FeeDelay: profile.FeeDelay}
	storagePolicy := workchain.DefaultPolicy()
	storagePolicy.CanonicalRetention = 1
	f.config = authoritystore.PruneArchiveEffectServiceConfig{
		ExecutorPath: filepath.Join(f.root, "executor"), ExecutorPinsPath: filepath.Join(f.root, "executor-pins"),
		ChainPath: filepath.Join(f.root, "chain"), ChainPinsPath: filepath.Join(f.root, "chain-pins"),
		Base: base, Parameters: parameters, StoragePolicy: storagePolicy, Limits: workarchive.DefaultLimits(),
	}
	storageID := pruneCLIHash(91)
	tree, err := workchain.CreatePositionPinnedWithPolicy(f.config.ChainPath, f.config.ChainPinsPath, base, parameters, storagePolicy, storageID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tree.Close() })
	parent, timestamp := base.Tip.ID, base.Tip.Timestamp
	var anchorID types.Hash
	for i := range 5 {
		timestamp += parameters.TargetSpacing
		payload, _, err := tree.Prepare(parent, timestamp, nil)
		if err != nil {
			t.Fatal(err)
		}
		inclusion, _ := workgraph.InclusionRoot(nil)
		template, err := payload.SealTemplate(types.Address(pruneCLIHash(byte(40+i))), inclusion, nil)
		if err != nil {
			t.Fatal(err)
		}
		anchor, _, err := workgraph.MineAnchor(t.Context(), template, 0)
		if err != nil {
			t.Fatal(err)
		}
		candidate, _, err := payload.Finalize(anchor, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := tree.Commit(candidate, timestamp); err != nil {
			t.Fatal(err)
		}
		parent, _ = candidate.Header.ID()
		if i == 2 {
			anchorID = parent
		}
	}
	binding := workarchive.Binding{NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight: profile.ActivationHeight, BaseID: base.Tip.ID}
	archivePath := filepath.Join(f.root, "source-archive")
	manifest, _, err := workarchive.ExportDirectory(archivePath, binding, tree, anchorID, workarchive.DefaultExportOptions())
	if err != nil {
		t.Fatal(err)
	}
	statement, err := manifest.ArchiveStatement(1, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	var attestations []workarchive.Attestation
	for _, seed := range []byte{51, 52} {
		attestation, err := workarchive.Attest(pruneCLIKey(seed), statement)
		if err != nil {
			t.Fatal(err)
		}
		attestations = append(attestations, attestation)
	}
	checkpoint, err := workarchive.NewCheckpoint(statement, attestations)
	if err != nil {
		t.Fatal(err)
	}
	policy := authoritystore.ArchivePrunePolicy{Checkpoint: checkpoint,
		CheckpointPolicy: workarchive.Policy{Binding: binding, RequiredAttestations: 2},
		ReplicaPolicy:    workarchive.ReplicaPolicy{RequiredReplicas: 2, MaximumReceiptAge: 1_000, MinimumRemainingTerm: 100}}
	for _, attestation := range checkpoint.Attestations {
		policy.CheckpointPolicy.TrustedAttestors = append(policy.CheckpointPolicy.TrustedAttestors, attestation.PublicKey)
	}
	for _, name := range []string{"inventory", "availability", "lineage", "metadata"} {
		if err := os.Mkdir(filepath.Join(f.root, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.manifestPath, f.checkpointPath = filepath.Join(f.root, "metadata", "manifest.omwm"), filepath.Join(f.root, "metadata", "checkpoint.omwc")
	manifestBytes, _ := manifest.CanonicalBytes()
	checkpointBytes, _ := checkpoint.CanonicalBytes()
	writePruneCLIFile(t, f.manifestPath, manifestBytes)
	writePruneCLIFile(t, f.checkpointPath, checkpointBytes)
	f.config.AvailabilityPath = filepath.Join(f.root, "availability", "availability.omav")
	f.config.InventoryPath = filepath.Join(f.root, "inventory", "prepared.ompi")
	var replicas []workarchive.Replica
	now := uint64(time.Now().Unix())
	storedAt, retainUntil := now, now+20_000
	if lineage {
		storedAt, retainUntil = now-2_000, now+18_000
	}
	for _, seed := range []byte{61, 62} {
		path := filepath.Join(f.root, fmt.Sprintf("replica-%d", seed))
		if err := os.CopyFS(path, os.DirFS(archivePath)); err != nil {
			t.Fatal(err)
		}
		receipt, err := workarchive.CreateReplicaReceipt(path, checkpoint, policy.CheckpointPolicy, base, parameters,
			f.config.Limits, pruneCLIKey(seed), pruneCLIHash(seed), storedAt, retainUntil)
		if err != nil {
			t.Fatal(err)
		}
		replicas = append(replicas, workarchive.Replica{Directory: path, Receipt: receipt})
	}
	sort.Slice(replicas, func(i, j int) bool {
		return bytes.Compare(replicas[i].Receipt.ReplicaPublicKey[:], replicas[j].Receipt.ReplicaPublicKey[:]) < 0
	})
	custodyPolicy := workarchive.CustodyPolicy{TrustedAuditors: [][32]byte{pruneCLIPublic(3)},
		MaximumChallengeLifetime: 60, MaximumProofAge: 100, MaximumRenewalTerm: 20_000}
	var lineages []workarchive.CustodyReceiptLineage
	for i, replica := range replicas {
		policy.ReplicaPolicy.TrustedReplicas = append(policy.ReplicaPolicy.TrustedReplicas, replica.Receipt.ReplicaPublicKey)
		assignment, err := workarchive.CreateCustodyAuthorityAssignment(manifest, replica.Receipt, custodyPolicy, pruneCLIHash(byte(100+i)),
			pruneCLIPublic(1), []custodyauthority.Consumer{{PublicKey: pruneCLIPublic(4), Purposes: custodyauthority.AllPurposes}}, 16, 4)
		if err != nil {
			t.Fatal(err)
		}
		policy.Assignments = append(policy.Assignments, assignment)
		assignmentID, _ := assignment.ID()
		f.config.Replicas = append(f.config.Replicas, authoritystore.PruneArchiveReplicaPath{AssignmentID: assignmentID, Directory: replica.Directory})
		if lineage {
			prefix, selected := makePruneEffectCLILineage(t, f, manifest, checkpoint, policy.CheckpointPolicy,
				assignment, replica, custodyPolicy, 2-i, now)
			lineages = append(lineages, prefix)
			replicas[i].Receipt = selected
		}
	}
	bundle, err := workarchive.VerifyReplicaSet(replicas, checkpoint, policy.CheckpointPolicy, policy.ReplicaPolicy,
		base, parameters, f.config.Limits, now)
	if err != nil {
		t.Fatal(err)
	}
	primaryID, _ := policy.Assignments[0].ID()
	statementID, _ := statement.ID()
	manifestID, _ := manifest.ID()
	bundleID, _ := bundle.ID()
	request := authoritystore.PruneRequest{AssignmentID: primaryID, ConsumerPublicKey: pruneCLIPublic(4), StorageID: storageID,
		Boundary: workchain.CanonicalFloor{Pruned: true, BaseID: base.Tip.ID, Anchor: statement.Anchor,
			AncestryNodes: statement.AncestryNodes, AncestryRoot: statement.AncestryRoot, StatementID: statementID,
			ManifestID: manifestID, AvailabilityID: bundleID, VerifiedAt: now,
			RetainUntil: min(replicas[0].Receipt.RetainUntil, replicas[1].Receipt.RetainUntil)}}
	requestID, err := request.ID()
	if err != nil {
		t.Fatal(err)
	}
	executor, err := authoritystore.CreatePinnedPruneExecutor(f.config.ExecutorPath, f.config.ExecutorPinsPath, policy.Assignments[0], request, requestID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	for i, assignment := range policy.Assignments {
		assignmentID, _ := assignment.ID()
		roots := authoritystore.PruneArchiveAuthorityRoots{AssignmentID: assignmentID,
			AuthorityPath: filepath.Join(f.root, fmt.Sprintf("authority-%d", i)), AuthorityPinsPath: filepath.Join(f.root, fmt.Sprintf("authority-pins-%d", i))}
		coordinator, err := authoritystore.CreateCoordinatedAuthority(roots.AuthorityPath, roots.AuthorityPinsPath, assignment, assignmentID)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = coordinator.Close() })
		command, err := (custodyauthority.Command{AssignmentID: assignmentID, ExpectedHead: assignmentID,
			Kind: custodyauthority.Admit, Purpose: custodyauthority.Prune, OperationID: requestID}).Sign(pruneCLIKey(4))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(command, pruneCLIKey(1))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.Append(t.Context(), entry); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := executor.BindAdmission(t.Context(), coordinator, entry); err != nil {
				t.Fatal(err)
			}
		}
		if err := coordinator.Close(); err != nil {
			t.Fatal(err)
		}
		f.config.Authorities = append(f.config.Authorities, roots)
		f.admissions = append(f.admissions, entry)
	}
	execution, err := executor.Snapshot()
	if err != nil || execution.Protection == nil {
		t.Fatal("fixture executor has no independent stage protection", err)
	}
	protection, err := tree.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	policy.RequestID, policy.ExecutorBindingID, policy.StoragePairID = requestID, execution.Protection.BindingID, protection.PairID
	f.inventory = authoritystore.ArchivePruneInventory{Request: request, Policy: policy, Availability: bundle, Admissions: f.admissions}
	if lineage {
		f.inventory.Mode = authoritystore.ArchivePruneLineage
	}
	f.assignments = policy.Assignments
	f.config.PolicyID, err = f.inventory.PolicyID()
	if err != nil {
		t.Fatal(err)
	}
	f.config.InventoryID, err = f.inventory.ID()
	if err != nil {
		t.Fatal(err)
	}
	if err := authoritystore.SaveArchivePruneInventoryFile(f.config.InventoryPath, f.inventory, f.config.InventoryID, f.config.PolicyID); err != nil {
		t.Fatal(err)
	}
	if lineage {
		evidence, err := authoritystore.PrepareArchivePruneLineageEvidence(t.Context(), f.inventory, f.config.InventoryID, f.config.PolicyID, lineages)
		if err != nil {
			t.Fatal(err)
		}
		f.config.LineageID, _ = evidence.ID()
		f.config.LineagePath = filepath.Join(f.root, "lineage", "lineages.omple")
		if err := authoritystore.SaveArchivePruneLineageEvidenceFile(t.Context(), f.config.LineagePath, evidence, f.config.LineageID); err != nil {
			t.Fatal(err)
		}
	}
	if err := executor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tree.Close(); err != nil {
		t.Fatal(err)
	}
	f.rootsPath = filepath.Join(f.root, "metadata", "roots.json")
	f.writeRoots(t)
	return f
}

func (f *pruneEffectCLIFixture) writeRoots(t testing.TB) {
	t.Helper()
	type authorityPaths struct {
		AssignmentID  string `json:"assignment_id"`
		Authority     string `json:"authority"`
		AuthorityPins string `json:"authority_pins"`
	}
	type replicaPath struct {
		AssignmentID string `json:"assignment_id"`
		Directory    string `json:"directory"`
	}
	metadata := struct {
		Authorities []authorityPaths `json:"authorities"`
		Replicas    []replicaPath    `json:"replicas"`
	}{}
	for _, roots := range f.config.Authorities {
		metadata.Authorities = append(metadata.Authorities, authorityPaths{roots.AssignmentID.String(), roots.AuthorityPath, roots.AuthorityPinsPath})
	}
	for _, replica := range f.config.Replicas {
		metadata.Replicas = append(metadata.Replicas, replicaPath{replica.AssignmentID.String(), replica.Directory})
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, f.rootsPath, encoded)
}

func (f *pruneEffectCLIFixture) args(mode string) []string {
	c, p, limits := f.config, f.config.StoragePolicy, f.config.Limits
	args := []string{"work-prune-archive-effect", "--data", f.data, "--roots", f.rootsPath,
		"--inventory", c.InventoryPath, "--inventory-id", c.InventoryID.String(), "--policy-id", c.PolicyID.String(),
		"--executor", c.ExecutorPath, "--executor-pins", c.ExecutorPinsPath, "--chain", c.ChainPath, "--chain-pins", c.ChainPinsPath,
		"--availability-out", c.AvailabilityPath,
		"--max-history-bytes", strconv.FormatUint(p.MaxHistoryBytes, 10), "--fork-retention", strconv.FormatUint(p.ForkRetention, 10),
		"--checkpoint-every", strconv.FormatUint(p.CheckpointEvery, 10), "--checkpoint-keep", strconv.FormatUint(uint64(p.CheckpointKeep), 10),
		"--canonical-retention", strconv.FormatUint(p.CanonicalRetention, 10),
		"--max-archive-blocks", strconv.FormatUint(limits.MaximumBlocks, 10), "--max-archive-chunks", strconv.FormatUint(uint64(limits.MaximumChunks), 10),
		"--max-archive-bytes", strconv.FormatUint(limits.MaximumBytes, 10)}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	if c.LineagePath != "" {
		args = append(args, "--lineage-evidence", c.LineagePath, "--lineage-evidence-id", c.LineageID.String())
	}
	return args
}

func makePruneEffectCLILineage(t testing.TB, f *pruneEffectCLIFixture, manifest workarchive.Manifest,
	checkpoint workarchive.Checkpoint, checkpointPolicy workarchive.Policy, assignment custodyauthority.Assignment,
	replica workarchive.Replica, policy workarchive.CustodyPolicy, count int, now uint64,
) (workarchive.CustodyReceiptLineage, workarchive.ReplicaReceipt) {
	t.Helper()
	assignmentID, _ := assignment.ID()
	manifestBytes, _ := manifest.CanonicalBytes()
	lineage := workarchive.CustodyReceiptLineage{AssignmentID: assignmentID, Manifest: manifestBytes, InitialReceipt: replica.Receipt, Policy: policy}
	objects, err := workarchive.OpenObjectStore(filepath.Join(f.root, fmt.Sprintf("objects-%s", assignmentID)), workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := objects.ImportArchiveDirectory(replica.Directory, checkpoint, checkpointPolicy, f.config.Base, f.config.Parameters, f.config.Limits); err != nil {
		t.Fatal(err)
	}
	var replicaKey ed25519.PrivateKey
	for _, seed := range []byte{61, 62} {
		if pruneCLIPublic(seed) == replica.Receipt.ReplicaPublicKey {
			replicaKey = pruneCLIKey(seed)
		}
	}
	if replicaKey == nil {
		t.Fatal("fixture selected an unknown replica signing key")
	}
	current, previous := replica.Receipt, (types.Hash{})
	for i := range count {
		at := now - 100 + uint64(i)*10
		challenge, err := workarchive.CreateCustodyChallenge(manifest, current, pruneCLIKey(3), at, 60, 1, current.RetainUntil+100)
		if err != nil {
			t.Fatal(err)
		}
		batch, proof, err := workarchive.AnswerCustodyChallenge(objects, manifest, current, challenge, policy, replicaKey, at)
		if err != nil {
			t.Fatal(err)
		}
		renewed, err := workarchive.RenewReplicaReceipt(manifest, current, challenge, batch, proof, policy, replicaKey, at)
		if err != nil {
			t.Fatal(err)
		}
		entry := workarchive.CustodyJournalEntry{Version: workarchive.CustodyJournalEntryVersion0, Sequence: uint64(i) + 1,
			PreviousEntryID: previous, PreviousReceipt: current, Record: workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0,
				Challenge: challenge, Batch: batch, Proof: proof, RenewedReceipt: renewed}}
		encoded, err := entry.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		lineage.Entries = append(lineage.Entries, encoded)
		previous, _ = entry.ID()
		current = renewed
	}
	return lineage, current
}

func (f *pruneEffectCLIFixture) executor(t testing.TB) *authoritystore.PruneExecutor {
	t.Helper()
	owner, err := authoritystore.OpenPinnedPruneExecutor(f.config.ExecutorPath, f.config.ExecutorPinsPath, f.assignments[0], f.inventory.Policy.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func (f *pruneEffectCLIFixture) coordinator(t testing.TB, index int) *authoritystore.Coordinator {
	t.Helper()
	assignment := f.assignments[index]
	id, _ := assignment.ID()
	for _, roots := range f.config.Authorities {
		if roots.AssignmentID != id {
			continue
		}
		owner, err := authoritystore.OpenCoordinator(roots.AuthorityPath, roots.AuthorityPinsPath, assignment, id)
		if err != nil {
			t.Fatal(err)
		}
		return owner
	}
	t.Fatal("fixture lost an original coordinator path")
	return nil
}

func (f *pruneEffectCLIFixture) chain(t testing.TB) *workchain.Store {
	t.Helper()
	owner, err := workchain.OpenPositionPinnedWithPolicy(f.config.ChainPath, f.config.ChainPinsPath,
		f.config.Base, f.config.Parameters, f.config.StoragePolicy, f.inventory.Request.StorageID)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}

func (f *pruneEffectCLIFixture) snapshot(t testing.TB) pruneEffectCLIState {
	t.Helper()
	executor, tree := f.executor(t), f.chain(t)
	defer executor.Close()
	defer tree.Close()
	state := pruneEffectCLIState{}
	var err error
	state.Executor, err = executor.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.assignments {
		owner := f.coordinator(t, i)
		current, err := owner.Snapshot()
		closeErr := owner.Close()
		if err != nil || closeErr != nil {
			t.Fatal(errors.Join(err, closeErr))
		}
		state.Authorities = append(state.Authorities, current)
	}
	state.Storage, err = tree.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	state.History, _, err = tree.HistoryUsage()
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := f.admissions[0].ID()
	state.Effect, state.EffectFound, err = tree.CanonicalPruneEffect(ticket)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (f *pruneEffectCLIFixture) assertBusy(t testing.TB) {
	t.Helper()
	if owner, err := authoritystore.OpenPinnedPruneExecutor(f.config.ExecutorPath, f.config.ExecutorPinsPath,
		f.assignments[0], f.inventory.Policy.RequestID); !errors.Is(err, authoritystore.ErrBusy) {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("effect CLI released executor ownership", err)
	}
	for _, roots := range f.config.Authorities {
		var assignment custodyauthority.Assignment
		for _, candidate := range f.assignments {
			if id, _ := candidate.ID(); id == roots.AssignmentID {
				assignment = candidate
			}
		}
		if owner, err := authoritystore.OpenCoordinator(roots.AuthorityPath, roots.AuthorityPinsPath,
			assignment, roots.AssignmentID); !errors.Is(err, authoritystore.ErrBusy) {
			if owner != nil {
				_ = owner.Close()
			}
			t.Fatal("effect CLI released a required coordinator", err)
		}
	}
	if tree, err := workchain.OpenPositionPinnedWithPolicy(f.config.ChainPath, f.config.ChainPinsPath,
		f.config.Base, f.config.Parameters, f.config.StoragePolicy, f.inventory.Request.StorageID); !errors.Is(err, workchain.ErrStoragePinBusy) {
		if tree != nil {
			_ = tree.Close()
		}
		t.Fatal("effect CLI released protected WorkChain", err)
	}
}
