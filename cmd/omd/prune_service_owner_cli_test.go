//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	fencefixture "github.com/outcomemesh/outcomemesh/internal/fencetest"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnessnet"
	"github.com/outcomemesh/outcomemesh/node/custodyguard"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type pruneServiceOwnerCLIFixture struct {
	root, public, identityPath, configPath, descriptorPath, requestPath, consumerPath string
	identity                                                                          service.Identity
	config                                                                            service.Config
	descriptor                                                                        wire.Descriptor
	request                                                                           wire.Request
	inventory                                                                         store.ScheduledPruneInventory
	stopNetwork                                                                       func()
}

func preparePruneServiceOwnerCLI(t testing.TB) *pruneServiceOwnerCLIFixture {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &pruneServiceOwnerCLIFixture{root: filepath.Join(parent, "owner"), public: t.TempDir()}
	f.identityPath = filepath.Join(f.public, "identity.json")
	create := []string{pruneServiceCommand, "--action", "identity-create", "--root", f.root, "--out", f.identityPath}
	pruneServiceCLIReview(t, create)
	if _, err := os.Stat(f.root); !os.IsNotExist(err) {
		t.Fatal("identity review created owner", err)
	}
	pruneServiceCLIRun(t, create)
	if err := json.Unmarshal(pruneServiceCLIRead(t, f.identityPath), &f.identity); err != nil {
		t.Fatal(err)
	}
	beforeIdentity := prunePrepareTree(t, f.root)
	pruneServiceCLIRun(t, create)
	if !reflect.DeepEqual(beforeIdentity, prunePrepareTree(t, f.root)) {
		t.Fatal("identity retry replaced private state")
	}
	publicAgain := filepath.Join(f.public, "identity-again.json")
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "identity-public", "--root", f.root, "--out", publicAgain})
	if !bytes.Equal(pruneServiceCLIRead(t, f.identityPath), pruneServiceCLIRead(t, publicAgain)) {
		t.Fatal("public identity differs")
	}
	guardParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := custodyguard.Create(filepath.Join(guardParent, "guard"), custodyguard.Config{Subjects: [][32]byte{f.identity.Service}, Limit: 16})
	if err != nil {
		t.Fatal(err)
	}
	guardHTTP := httptest.NewServer(custodyguard.Handler(guard))
	t.Cleanup(func() { guardHTTP.Close(); guard.Close() })
	guardPublic := guard.Identity().PublicKey

	base, cp, cpPath, sources := prepareCustodyScheduleQuorumCLI(t)
	policy := base.inventory.Policy
	chain, err := workchain.OpenPositionPinnedWithPolicy(base.config.ChainPath, base.config.ChainPinsPath, base.config.Base, base.config.Parameters, base.config.StoragePolicy, base.inventory.Request.StorageID)
	if err != nil {
		t.Fatal(err)
	}
	migration, err := chain.ReviewRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = chain.MigrateRadixSchedule(t.Context(), cp.Statement.RadixActivationHeight, migration.ID()); err != nil {
		t.Fatal(err)
	}
	protection, err := chain.StorageProtection()
	if err != nil {
		t.Fatal(err)
	}
	if err = chain.Close(); err != nil {
		t.Fatal(err)
	}
	quorumPath := filepath.Join(f.public, "quorum.json")
	pruneServiceCLIJSON(t, quorumPath, sources)
	keys := func(v [][32]byte) string {
		var out []string
		for _, k := range v {
			out = append(out, hex.EncodeToString(k[:]))
		}
		return strings.Join(out, ",")
	}
	cpID, _ := cp.Statement.ID()
	planArgs := []string{scheduledPlanCommand, "--sources", quorumPath, "--checkpoint", cpPath, "--checkpoint-id", cpID.String(), "--attestors", keys(policy.CheckpointPolicy.TrustedAttestors), "--replicas", keys(policy.ReplicaPolicy.TrustedReplicas), "--max-receipt-age-seconds", "1000", "--min-remaining-term-seconds", "100", "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000", "--primary-assignment-id", sources[0].AssignmentID, "--storage-id", protection.StorageID.String(), "--storage-pair-id", protection.PairID.String(), "--consumer-public-key", hex.EncodeToString(base.inventory.Request.ConsumerPublicKey[:]), "--verified-at", strconv.FormatUint(base.inventory.Request.Boundary.VerifiedAt, 10)}
	var prepared struct {
		PlanID, RequestID types.Hash
		Plan              store.ScheduledPrunePlan
	}
	scheduledCLIRun(t, planArgs, &prepared)
	originalPlan, originalRequest := filepath.Join(f.public, "original-plan"), filepath.Join(f.public, "original-request")
	scheduledCLIRun(t, append(append([]string(nil), planArgs...), "--mode", "publish", "--expected-plan-id", prepared.PlanID.String(), "--out", originalPlan, "--request-out", originalRequest), nil)
	issuer := fencefixture.Public(109)
	enrollmentDraft, enrollmentPath, issuerPath := filepath.Join(f.public, "enrollment.json"), filepath.Join(f.public, "enrollment"), filepath.Join(f.public, "issuer.seed")
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "enrollment-prepare", "--identity", f.identityPath, "--plan", originalPlan, "--plan-id", prepared.PlanID.String(), "--issuer", hex.EncodeToString(issuer[:]), "--guard", hex.EncodeToString(guardPublic[:]), "--out", enrollmentDraft})
	writePruneCLIFile(t, issuerPath, fencefixture.Key(109).Seed())
	enrollmentID := pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "enrollment-sign", "--input", enrollmentDraft, "--key", issuerPath, "--out", enrollmentPath})
	policyDraft, policyPath := filepath.Join(f.public, "policy.json"), filepath.Join(f.public, "policy")
	policyJSON := pruneFencePolicyJSON{Owner: hex.EncodeToString(pruneCLIKey(4)[32:]), Controller: hex.EncodeToString(pruneCLIKey(1)[32:]), Threshold: 3}
	for i := byte(70); i < 74; i++ {
		policyJSON.Witnesses = append(policyJSON.Witnesses, hex.EncodeToString(fencefixture.Key(i)[32:]))
	}
	pruneServiceCLIJSON(t, policyDraft, policyJSON)
	policyArgs := []string{pruneFencePolicyCommand, "--input", policyDraft, "--service-enrollment", enrollmentPath, "--service-enrollment-id", enrollmentID}
	var published struct {
		ArtifactID string `json:"artifact_id"`
	}
	scheduledCLIRun(t, policyArgs, &published)
	scheduledCLIRun(t, append(append([]string(nil), policyArgs...), "--mode", "publish", "--expected-id", published.ArtifactID, "--out", policyPath), nil)
	planArgs = append(planArgs, "--fence-policy", policyPath, "--fence-policy-id", published.ArtifactID)
	scheduledCLIRun(t, planArgs, &prepared)
	planPath, pruneRequest := filepath.Join(f.public, "plan"), filepath.Join(f.public, "prune-request")
	scheduledCLIRun(t, append(append([]string(nil), planArgs...), "--mode", "publish", "--expected-plan-id", prepared.PlanID.String(), "--out", planPath, "--request-out", pruneRequest), nil)
	executor, pins := filepath.Join(t.TempDir(), "executor"), filepath.Join(t.TempDir(), "pins")
	if err = runPruneBootstrap(t.Context(), []string{pruneExecutorPrepareCommand, "--mode", "create", "--assignment", sources[0].Assignment, "--assignment-id", sources[0].AssignmentID, "--request", pruneRequest, "--request-id", prepared.RequestID.String(), "--executor", executor, "--executor-pins", pins}, io.Discard); err != nil {
		t.Fatal(err)
	}
	var admissions []scheduledPruneAdmissionJSON
	var executionSources []scheduledPruneCLISource
	for i, s := range sources {
		common := []string{"--plan", planPath, "--plan-id", prepared.PlanID.String(), "--assignment-id", s.AssignmentID, "--authority", s.Authority, "--authority-pins", s.Pins, "--executor", executor, "--executor-pins", pins}
		var reviewed store.ScheduledPruneCommandResult
		scheduledCLIRun(t, append([]string{scheduledApplyCommand}, common...), &reviewed)
		if reviewed.Review.Authority.Authority.Pending != 1 {
			t.Fatal("lost original obligation")
		}
		entry, eid := scheduledCLISign(t, []string{"--plan", planPath, "--plan-id", prepared.PlanID.String(), "--assignment-id", s.AssignmentID, "--kind", "admit", "--expected-sequence", strconv.FormatUint(reviewed.Review.Authority.Confirmed.Sequence, 10), "--expected-head", reviewed.Review.Authority.Confirmed.HeadID.String()})
		apply := append(append([]string{scheduledApplyCommand}, common...), "--entry", entry, "--entry-id", eid.String(), "--journal", s.Journal, "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000")
		scheduledCLIRun(t, apply, &reviewed)
		scheduledCLIRun(t, append(apply, "--mode", "apply", "--expected-review-id", reviewed.Review.ReviewID.String()), &reviewed)
		if reviewed.Commit == nil || reviewed.Commit.Snapshot.Pending != 2 {
			t.Fatal("admission reset original obligation")
		}
		admissions = append(admissions, scheduledPruneAdmissionJSON{AssignmentID: s.AssignmentID, Authority: s.Authority, Pins: s.Pins, Entry: entry, EntryID: eid.String()})
		directory := filepath.Join(t.TempDir(), "archive")
		if _, _, err = workarchive.MigrateRadixArchiveDirectory(base.config.Replicas[i].Directory, directory, policy.Checkpoint, cp, policy.CheckpointPolicy, base.config.Base, base.config.Parameters, workarchive.DefaultLimits()); err != nil {
			t.Fatal(err)
		}
		executionSources = append(executionSources, scheduledPruneCLISource{AssignmentID: s.AssignmentID, Authority: s.Authority, Pins: s.Pins, Journal: s.Journal, Directory: directory})
	}
	admissionsPath := filepath.Join(f.public, "admissions.json")
	pruneServiceCLIJSON(t, admissionsPath, admissions)
	inventoryArgs := []string{scheduledInventoryCommand, "--plan", planPath, "--plan-id", prepared.PlanID.String(), "--executor", executor, "--executor-pins", pins, "--sources", admissionsPath}
	var packaged struct {
		InventoryID types.Hash
		Inventory   store.ScheduledPruneInventory
	}
	scheduledCLIRun(t, inventoryArgs, &packaged)
	inventoryPath := filepath.Join(f.public, "inventory")
	scheduledCLIRun(t, append(inventoryArgs, "--mode", "publish", "--expected-inventory-id", packaged.InventoryID.String(), "--out", inventoryPath), nil)
	f.inventory = packaged.Inventory
	scope, err := packaged.Inventory.FencePolicy.Scope(packaged.Inventory.Request.AssignmentID, prepared.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	scopeID, _ := scope.ID()
	network := pruneFenceNetworkJSON{ClientTransport: hex.EncodeToString(f.identity.Transport[:])}
	var witnessServers []*witnessnet.Service
	for i := byte(0); i < 4; i++ {
		w, err := custodyfence.Create(filepath.Join(t.TempDir(), "witness"), scope, scopeID, fencefixture.Key(70+i))
		if err != nil {
			t.Fatal(err)
		}
		server, err := witnessnet.Start(t.Context(), w, scope, scopeID, fencefixture.Key(90+i), libp2ptransport.DefaultConfig(), []types.Hash{types.DomainHash("OMESH/p2p/ed25519/v0", f.identity.Transport[:])}, time.Second)
		if err != nil {
			w.Close()
			t.Fatal(err)
		}
		witnessServers = append(witnessServers, server)
		network.Witnesses = append(network.Witnesses, struct {
			Witness   string `json:"witness"`
			Transport string `json:"transport"`
			Address   string `json:"address"`
		}{hex.EncodeToString(fencefixture.Key(70 + i)[32:]), hex.EncodeToString(fencefixture.Key(90 + i)[32:]), server.Addresses()[0]})
	}
	f.stopNetwork = func() {
		for _, s := range witnessServers {
			s.Close()
		}
		guardHTTP.Close()
		guard.Close()
	}
	t.Cleanup(f.stopNetwork)
	networkPath, sourcesPath := filepath.Join(f.public, "network.json"), filepath.Join(f.public, "sources.json")
	pruneServiceCLIJSON(t, networkPath, network)
	pruneServiceCLIJSON(t, sourcesPath, executionSources)
	f.configPath = filepath.Join(f.public, "runtime.json")
	export := []string{"--inventory", inventoryPath, "--inventory-id", packaged.InventoryID.String(), "--data", base.data, "--sources", sourcesPath, "--executor", executor, "--executor-pins", pins, "--chain", base.config.ChainPath, "--chain-pins", base.config.ChainPinsPath, "--storage-migration-id", migration.ID().String(), "--canonical-retention", strconv.FormatUint(base.config.StoragePolicy.CanonicalRetention, 10), "--max-history-bytes", strconv.FormatUint(base.config.StoragePolicy.MaxHistoryBytes, 10), "--max-challenge-lifetime-seconds", "60", "--max-proof-age-seconds", "100", "--max-renewal-term-seconds", "20000", "--runtime-config-out", f.configPath, "--service-identity", f.identityPath, "--service-guard-url", guardHTTP.URL, "--service-witness-network", networkPath, "--service-witness-timeout", "1s"}
	if err = runScheduledPrune(t.Context(), export, io.Discard); err != nil {
		t.Fatal("runtime export", err)
	}
	runtimeBytes := pruneServiceCLIRead(t, f.configPath)
	for _, bad := range [][]string{
		append(append([]string(nil), export...), "--fence-owner-key", filepath.Join(f.public, "absent.seed")),
		replaceRemoteCLIFlag(export, "--runtime-config-out", filepath.Join(executor, "public-config")),
		replaceRemoteCLIFlag(export, "--runtime-config-out", ""),
		append(append([]string(nil), export...), "--mode", "execute", "--expected-review-id", fencefixture.Hash("not reviewed").String()),
	} {
		if err = runScheduledPrune(t.Context(), bad, io.Discard); err == nil {
			t.Fatal("invalid runtime export accepted")
		}
	}
	network.ClientTransport = hex.EncodeToString(fencefixture.Key(99)[32:])
	pruneServiceCLIJSON(t, networkPath, network)
	if err = runScheduledPrune(t.Context(), export, io.Discard); err == nil {
		t.Fatal("runtime export accepted another transport")
	}
	network.ClientTransport = hex.EncodeToString(f.identity.Transport[:])
	pruneServiceCLIJSON(t, networkPath, network)
	if !bytes.Equal(runtimeBytes, pruneServiceCLIRead(t, f.configPath)) {
		t.Fatal("invalid export changed retained configuration")
	}
	f.config, err = service.DecodeConfig(pruneServiceCLIRead(t, f.configPath))
	if err != nil {
		t.Fatal(err)
	}
	if f.config.Runtime.Base.State.Root() != base.config.Base.State.Root() {
		t.Fatal("runtime export lost base resources")
	}
	for _, root := range pruneServiceRuntimeRoots(f.config.Runtime) {
		if err = os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err = runScheduledPrune(t.Context(), export, io.Discard); err != nil {
		t.Fatal("exact runtime export", err)
	}
	draftPath := filepath.Join(f.public, "descriptor.json")
	f.descriptorPath = filepath.Join(f.public, "descriptor")
	participant := uint32(65534)
	if f.identity.OwnerUID == participant {
		participant--
	}
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "descriptor-prepare", "--root", f.root, "--input", f.configPath, "--participant-uid", strconv.FormatUint(uint64(participant), 10), "--out", draftPath})
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "descriptor-sign", "--input", draftPath, "--key", issuerPath, "--out", f.descriptorPath})
	f.descriptor, err = wire.DecodeDescriptor(pruneServiceCLIRead(t, f.descriptorPath))
	if err != nil {
		t.Fatal(err)
	}
	did, _ := f.descriptor.ID()
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "configure", "--root", f.root, "--input", f.configPath, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--out", filepath.Join(f.public, "configured.json")})
	f.consumerPath = filepath.Join(f.public, "consumer.seed")
	writePruneCLIFile(t, f.consumerPath, pruneCLIKey(4).Seed())
	requestDraft := filepath.Join(f.public, "request.json")
	f.requestPath = filepath.Join(f.public, "request")
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "request-prepare", "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--nonce", fencefixture.Hash("service execution nonce").String(), "--out", requestDraft})
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "request-sign", "--input", requestDraft, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--key", f.consumerPath, "--out", f.requestPath})
	f.request, err = wire.DecodeRequest(pruneServiceCLIRead(t, f.requestPath))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *pruneServiceOwnerCLIFixture) open(t testing.TB, position wire.Position, request *wire.Request) *service.Owner {
	t.Helper()
	did, _ := f.descriptor.ID()
	owner, err := service.Open(t.Context(), f.root, did, position, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	return owner
}
func (f *pruneServiceOwnerCLIFixture) assertObligations(t testing.TB) {
	t.Helper()
	for _, replica := range f.inventory.Replicas {
		aid, _ := replica.Assignment.ID()
		for _, root := range f.config.Runtime.Authorities {
			if root.AssignmentID != aid {
				continue
			}
			owner, err := store.OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, replica.Assignment, aid)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := owner.Snapshot()
			closeErr := owner.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			if snapshot.Authority.Pending != 2 {
				t.Fatal("service cleared original or replica obligation", snapshot.Authority.Pending)
			}
		}
	}
}

func TestPruneServiceCLIOwnerDeletionAndOfflineRecovery(t *testing.T) {
	f := preparePruneServiceOwnerCLI(t)
	owner := f.open(t, wire.Position{}, nil)
	calls := 0
	challengeOut, approvalOut := filepath.Join(f.public, "challenge"), filepath.Join(f.public, "approval")
	response, err := owner.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		calls++
		missingSeed := filepath.Join(f.public, "absent-consumer.seed")
		badChallenge, badApproval := filepath.Join(f.public, "unverified-challenge"), filepath.Join(f.public, "unverified-approval")
		bad := ch
		bad.Signature[0] ^= 1
		if _, err := approvePruneServiceChallenge(ctx, f.descriptor, f.request, bad, missingSeed, badChallenge, badApproval); err == nil {
			t.Fatal("unverified candidate reached signer")
		}
		if _, err := os.Stat(badChallenge); !os.IsNotExist(err) {
			t.Fatal("unverified candidate published evidence", err)
		}
		if _, err := approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, missingSeed, challengeOut, approvalOut); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing signer after verified challenge", err)
		}
		raw, _ := ch.CanonicalBytes()
		if !bytes.Equal(raw, pruneServiceCLIRead(t, challengeOut)) {
			t.Fatal("signer opened before durable full challenge")
		}
		if _, err := os.Stat(approvalOut); !os.IsNotExist(err) {
			t.Fatal("missing signer published approval", err)
		}
		approval, err := approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, f.consumerPath, challengeOut, approvalOut)
		if err != nil {
			return custodyfence.Command{}, err
		}
		retry, err := approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, missingSeed, challengeOut, approvalOut)
		if err != nil || retry != approval {
			t.Fatal("retained approval needed private seed", err)
		}
		// A callback owns its detached challenge. Mutating nested policy values
		// after signing must not alter the owner's frozen candidate or draft.
		ch.Candidate.Policy.Service.Service = fencefixture.Public(125)
		ch.Candidate.Policy.Witnesses[0] = fencefixture.Public(126)
		return approval, nil
	})
	if err != nil || calls != 1 {
		t.Fatal("original execution", err, calls)
	}
	if err = response.Verify(f.descriptor, f.request); err != nil {
		t.Fatal(err)
	}
	if response.Result == nil || response.Settlement != nil {
		t.Fatal("execution did not retain result")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertObligations(t)
	f.stopNetwork()
	if err = os.Remove(f.consumerPath); err != nil {
		t.Fatal(err)
	}
	for _, root := range append(pruneServiceRuntimeRoots(f.config.Runtime), f.config.Runtime.InventoryPath) {
		if err = os.Rename(root, root+".offline"); err != nil {
			t.Fatal(err)
		}
	}
	position, err := response.Position()
	if err != nil {
		t.Fatal(err)
	}
	owner = f.open(t, position, nil)
	replayed, err := owner.Execute(t.Context(), f.request, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
		t.Fatal("historical replay requested a signature")
		return custodyfence.Command{}, io.ErrClosedPipe
	})
	if err != nil {
		t.Fatal("offline replay", err)
	}
	a, _ := response.CanonicalBytes()
	b, _ := replayed.CanonicalBytes()
	if !bytes.Equal(a, b) {
		t.Fatal("offline replay changed retained response")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	positionPath, responsePath := filepath.Join(f.public, "position.json"), filepath.Join(f.public, "response")
	pruneServiceCLIJSON(t, positionPath, position)
	did, _ := f.descriptor.ID()
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "recover", "--root", f.root, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", positionPath, "--request", f.requestPath, "--out", responsePath})
	if !bytes.Equal(a, pruneServiceCLIRead(t, responsePath)) {
		t.Fatal("CLI recovery changed outcome")
	}
	confirmedPath := filepath.Join(f.public, "confirmed-position.json")
	pruneServiceCLIRun(t, []string{pruneServiceCommand, "--action", "inspect", "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--request", f.requestPath, "--response", responsePath, "--out", filepath.Join(f.public, "inspection.json"), "--position-out", confirmedPath})
	var confirmed wire.Position
	if err = json.Unmarshal(pruneServiceCLIRead(t, confirmedPath), &confirmed); err != nil || confirmed != position {
		t.Fatal("confirmed cursor export", err)
	}
}

func TestPruneServiceCLIOwnerDisconnectRetainsAttemptWithoutRetry(t *testing.T) {
	testPruneServiceCLIOwnerHeldAttempt(t, false)
}

func TestPruneServiceCLIRecoversConfirmedExecutorBeforeOuterPublication(t *testing.T) {
	f := preparePruneServiceOwnerCLI(t)
	owner := f.open(t, wire.Position{}, nil)
	approvals := 0
	want, err := owner.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		approvals++
		return approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, f.consumerPath, filepath.Join(f.public, "challenge"), filepath.Join(f.public, "approval"))
	})
	if err != nil || approvals != 1 || want.Result == nil || want.Settlement != nil {
		t.Fatal("original executor did not confirm its full result", err, approvals)
	}
	wantBytes, err := want.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertObligations(t)

	originalRoots := []string{f.config.Runtime.ExecutorPath, f.config.Runtime.ExecutorPinsPath, f.config.Runtime.ChainPath, f.config.Runtime.ChainPinsPath}
	for _, roots := range f.config.Runtime.Authorities {
		originalRoots = append(originalRoots, roots.AuthorityPath, roots.AuthorityPinsPath)
	}
	before := make(map[string]map[string]string)
	for _, root := range originalRoots {
		before[root] = prunePrepareTree(t, root)
	}
	f.stopNetwork()
	if err = os.Remove(f.consumerPath); err != nil {
		t.Fatal(err)
	}
	for _, source := range f.config.Runtime.Sources {
		for _, path := range []string{source.Directory, source.JournalPath} {
			if err = os.Rename(path, path+".offline"); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Construct a disposable fixture at the boundary after the original executor
	// confirmed its result and before the outer response was published. This is
	// test-state construction, not an operator recovery or journal-repair step.
	// The retained intent and every original executor, authority and storage
	// journal remain untouched. This does not simulate an actual process exit.
	if err = os.Remove(filepath.Join(f.root, "events", "result")); err != nil {
		t.Fatal(err)
	}
	intentPosition, err := f.request.IntentPosition()
	if err != nil {
		t.Fatal(err)
	}
	owner = f.open(t, intentPosition, &f.request)
	held, err := owner.Snapshot()
	if err != nil || held.Position != intentPosition || held.Intent == nil || *held.Intent != f.request || held.Response != nil {
		t.Fatal("fixture does not model missing outer response", err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}

	positionPath, responsePath := filepath.Join(f.public, "intent-position.json"), filepath.Join(f.public, "recovered-response")
	confirmedPath := filepath.Join(f.public, "recovered-position.json")
	pruneServiceCLIJSON(t, positionPath, intentPosition)
	did, _ := f.descriptor.ID()
	args := []string{pruneServiceCommand, "--action", "recover", "--root", f.root, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", positionPath, "--request", f.requestPath, "--out", responsePath, "--position-out", confirmedPath}
	pruneServiceCLIRun(t, args)
	if !bytes.Equal(wantBytes, pruneServiceCLIRead(t, responsePath)) || !bytes.Equal(wantBytes, pruneServiceCLIRead(t, filepath.Join(f.root, "events", "result"))) {
		t.Fatal("confirmed original proof did not recreate the exact outer response")
	}
	confirmed, err := want.Position()
	if err != nil {
		t.Fatal(err)
	}
	var exported wire.Position
	if err = json.Unmarshal(pruneServiceCLIRead(t, confirmedPath), &exported); err != nil || exported != confirmed {
		t.Fatal("recovery did not export confirmed cursor", err)
	}
	owner = f.open(t, confirmed, nil)
	snapshot, err := owner.Snapshot()
	if err != nil || snapshot.Response == nil || snapshot.Position != confirmed {
		t.Fatal("recovery response was not retained", err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	pruneServiceCLIRun(t, args)
	for _, root := range originalRoots {
		if !reflect.DeepEqual(before[root], prunePrepareTree(t, root)) {
			t.Fatal("response recovery changed original execution or accounting", root)
		}
	}
	f.assertObligations(t)
}

func TestPruneServiceCLIOwnerRejectsAlteredConsumerApproval(t *testing.T) {
	testPruneServiceCLIOwnerHeldAttempt(t, true)
}

func testPruneServiceCLIOwnerHeldAttempt(t *testing.T, alterApproval bool) {
	f := preparePruneServiceOwnerCLI(t)
	owner := f.open(t, wire.Position{}, nil)
	calls := 0
	_, err := owner.Execute(t.Context(), f.request, func(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		calls++
		if alterApproval {
			_, draft, err := ch.Candidate.Draft()
			if err != nil {
				t.Fatal(err)
			}
			ch.Candidate.Policy.Service.Service = fencefixture.Public(125)
			ch.Candidate.Policy.Witnesses[0] = fencefixture.Public(126)
			draft.EvidenceID = fencefixture.Hash("substituted consumer approval")
			return draft.Sign(pruneCLIKey(4))
		}
		return custodyfence.Command{}, io.ErrUnexpectedEOF
	})
	if err == nil || calls != 1 {
		t.Fatal("disconnected approval was not held", err, calls)
	}
	snapshot, err := owner.Snapshot()
	if err != nil || snapshot.Intent == nil || snapshot.Response != nil || snapshot.Position.Sequence != 1 {
		t.Fatal("lost durable intent", err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertObligations(t)
	did, _ := f.descriptor.ID()
	if bad, err := service.Open(t.Context(), f.root, did, wire.Position{}, nil); err == nil {
		bad.Close()
		t.Fatal("stale initial cursor accepted")
	}
	owner = f.open(t, wire.Position{}, &f.request)
	_, err = owner.Execute(t.Context(), f.request, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
		calls++
		return custodyfence.Command{}, io.ErrUnexpectedEOF
	})
	if !errors.Is(err, service.ErrHeld) || calls != 1 {
		t.Fatal("retained attempt restarted", err, calls)
	}
	if _, err = owner.Recover(t.Context(), f.request); err == nil {
		t.Fatal("missing result resolved as success")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	f.assertObligations(t)
	bad := f.config
	bad.WitnessTimeout += time.Millisecond
	if err = service.Configure(t.Context(), f.root, f.descriptor, bad); err == nil {
		t.Fatal("configuration substitution accepted")
	}
	badDescriptor := f.descriptor
	badDescriptor.ParticipantUID++
	badDescriptor, err = badDescriptor.Sign(fencefixture.Key(109))
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Configure(t.Context(), f.root, badDescriptor, f.config); err == nil {
		t.Fatal("participant replacement accepted")
	}
	if _, err = service.Prepare(t.Context(), f.root, f.config, f.descriptor.ParticipantUID); err == nil {
		t.Fatal("new descriptor replaced held placement")
	}
}
