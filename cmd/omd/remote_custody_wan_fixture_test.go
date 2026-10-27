//go:build integration && (darwin || linux)

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type remoteV1Public struct {
	Version                           int               `json:"version"`
	Role                              string            `json:"role"`
	Keys                              map[string]string `json:"public_keys"`
	Incarnation                       string            `json:"incarnation_id"`
	InitialReceiptID                  string            `json:"initial_receipt_id"`
	InitialRetainUntil                uint64            `json:"initial_retain_until"`
	Lifetime, ProofAge, RenewalTerm   uint64
	MaximumOperations, MaximumPending uint64
}

// Export only immutable archive data and never-started test keys/nonces. Every
// assignment, original journal/authority, admission and worker is created by CLI
// at its destination. No fixture clock is used during network execution.
func TestExportRemoteV1Fixture(t *testing.T) {
	parent := os.Getenv(remoteCustodyFixtureOutputEnvironment)
	if parent == "" {
		t.Skip("explicit V1 WAN fixture export")
	}
	parent, err := managedCustodyCanonicalDirectory(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(parent); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("private export parent required", err)
	}
	root, err := os.MkdirTemp(parent, "v1-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	archive := newPruneEffectCLIFixture(t, false)
	m, err := loadArchiveManifest(archive.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	private := make(map[string]ed25519.PrivateKey)
	public := make(map[string]string)
	for _, name := range []string{"authority", "audit-consumer", "serve-consumer", "auditor", "a-control", "a-data", "b-control", "b-transport", "replica"} {
		seed := make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			t.Fatal(err)
		}
		private[name] = ed25519.NewKeyFromSeed(seed)
		public[name] = fmt.Sprintf("%x", private[name].Public().(ed25519.PublicKey))
	}
	peer, err := transport.PeerIDFromPublicKey(private["b-transport"].Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	public["b-peer"] = peer.String()
	now := uint64(time.Now().Unix())
	r, err := workarchive.CreateReplicaReceipt(archive.config.Replicas[0].Directory, archive.inventory.Policy.Checkpoint, archive.inventory.Policy.CheckpointPolicy, archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits(), private["replica"], remoteCustodyRandomHash(t), now-30, now+8*3600)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := r.ID()
	p := remoteV1Public{Version: 1, Keys: public, Incarnation: remoteCustodyRandomHash(t).String(), InitialReceiptID: rid.String(), InitialRetainUntil: r.RetainUntil, Lifetime: 600, ProofAge: 20, RenewalTerm: 24 * 3600, MaximumOperations: 128, MaximumPending: 4}
	for _, role := range []string{"a", "b"} {
		dir := filepath.Join(root, "role-"+role)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"metadata", "intent", "keys", "operations", "workers", "nonces"} {
			if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		p.Role = role
		writeRemoteCustodyFixtureJSON(t, filepath.Join(dir, "scope.json"), p)
		for _, item := range []struct {
			name  string
			value interface{ CanonicalBytes() ([]byte, error) }
		}{{"manifest", m}, {"initial", r}} {
			b, err := item.value.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			writeRemoteCustodyFixtureFile(t, filepath.Join(dir, "metadata", item.name), b)
		}
		var names []string
		if role == "a" {
			names = []string{"authority", "audit-consumer", "auditor", "a-control", "a-data"}
		} else {
			names = []string{"serve-consumer", "b-control", "b-transport", "replica"}
		}
		for _, name := range names {
			writeRemoteCustodyFixtureFile(t, filepath.Join(dir, "keys", name+".seed"), private[name].Seed())
		}
		for i := 1; i <= 64; i++ {
			if err := os.Mkdir(filepath.Join(dir, "operations", fmt.Sprintf("%03d", i)), 0o700); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"intent", "plan"} {
				nonce := remoteCustodyRandomHash(t)
				writeRemoteCustodyFixtureFile(t, filepath.Join(dir, "nonces", fmt.Sprintf("%03d-%s", i, kind)), nonce[:])
			}
		}
		if role == "b" {
			objects, err := workarchive.OpenObjectStore(filepath.Join(dir, "objects"), workarchive.DefaultObjectStorePolicy())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := objects.ImportArchiveDirectory(archive.config.Replicas[0].Directory, archive.inventory.Policy.Checkpoint, archive.inventory.Policy.CheckpointPolicy, archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits()); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeRemoteCustodyFixtureJSON(t, filepath.Join(root, "summary.json"), p)
	fmt.Printf("remote_v1_fixture root=%s initialized_owners=false single_assignment=true\n", root)
}

type remoteV1Session struct {
	Cycle        int    `json:"cycle"`
	AssignmentID string `json:"assignment_id"`
	PlanID       string `json:"plan_id"`
	BeginID      string `json:"begin_id"`
	Peer         string `json:"peer,omitempty"`
}

// Send the exact old Start directly over the authenticated wire after sealing.
// This adversarial packet bypasses A's normal operator guard only in the test
// binary. It cannot sign evidence, append authority or mutate a local source.
func TestRemoteV1LateStart(t *testing.T) {
	if os.Getenv("OUTCOMEMESH_REMOTE_ROLE_ROOT") == "" {
		t.Skip("explicit delayed Start acceptance probe")
	}
	root, p, s := remoteV1ReadSession(t)
	if p.Role != "a" || s.Peer == "" {
		t.Fatal("A's exact pinned route required")
	}
	scope := remoteV1Scope(t, root, p, s)
	key, err := loadPruneOfflineKey(filepath.Join(root, "keys", "a-control.seed"))
	if err != nil {
		t.Fatal(err)
	}
	if !remoteKeyMatches(key, scope.Worker.Plan.AuthorityTransportPublicKey) {
		t.Fatal("wrong control role")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cfg := libp2ptransport.DefaultConfig()
	cfg.Listen = []string{"/ip4/127.0.0.1/udp/43971/quic-v1"}
	host, err := libp2ptransport.New(ctx, key, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := transport.PeerIDFromPublicKey(scope.Worker.Assignment.RemoteTransportPublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	stream, _, err := host.OpenRemoteCustodyControlStream(ctx, s.Peer, peer)
	if err != nil {
		_ = host.Close()
		t.Fatal("probe did not authenticate B", err)
	}
	request := remotewire.Request{Version: remotewire.Version0, Kind: remotewire.Start, Nonce: remoteCustodyRandomHash(t), Plan: scope.Worker.Plan, Begin: scope.Worker.Begin}
	_, exchangeErr := remotewire.Exchange(ctx, stream, request, 3*time.Second)
	closeErr := host.Close()
	if exchangeErr == nil || ctx.Err() != nil || closeErr != nil {
		t.Fatal("delayed Start was confirmed or transport did not finish", exchangeErr, ctx.Err(), closeErr)
	}
	var timeout interface{ Timeout() bool }
	if errors.As(exchangeErr, &timeout) && timeout.Timeout() {
		t.Fatal("timeout is not evidence of sealed Start refusal", exchangeErr)
	}
	fmt.Println("remote_v1_late_start authenticated=true confirmed=false transport_timeout=false")
}

func remoteV1ReadSession(t testing.TB) (string, remoteV1Public, remoteV1Session) {
	t.Helper()
	root, err := managedCustodyCanonicalDirectory(os.Getenv("OUTCOMEMESH_REMOTE_ROLE_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	var p remoteV1Public
	var s remoteV1Session
	b, err := readRegularArtifact(filepath.Join(root, "scope.json"), 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &p); err != nil || p.Version != 1 || p.Role != "a" && p.Role != "b" {
		t.Fatal("invalid V1 public role", err)
	}
	path, err := custodyCommandFile(os.Getenv("OMESH_REMOTE_GATE_ARGS"))
	if err != nil {
		t.Fatal(err)
	}
	if !workarchive.CustodyEvidencePathsOverlap(root, path) {
		t.Fatal("session must be inside its original role")
	}
	b, err = readRegularArtifact(path, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &s); err != nil || s.Cycle < 1 || s.Cycle > 64 {
		t.Fatal("invalid V1 session", err)
	}
	return root, p, s
}

func remoteV1Scope(t testing.TB, root string, p remoteV1Public, s remoteV1Session) store.RemoteCustodyScope {
	t.Helper()
	id, err := managedCustodyExternalID("assignment", s.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	a, err := loadPruneOfflineAssignment(filepath.Join(root, "metadata", "assignment"), id)
	if err != nil || a.Version != custodyauthority.Version1 {
		t.Fatal(err)
	}
	m, err := loadArchiveManifest(filepath.Join(root, "metadata", "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := loadArchiveReplicaReceipt(filepath.Join(root, "metadata", "initial"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "operations", fmt.Sprintf("%03d", s.Cycle))
	previous, err := loadArchiveReplicaReceipt(filepath.Join(dir, "previous"))
	if err != nil {
		t.Fatal(err)
	}
	plan, _, err := remoteOfflinePlan(filepath.Join(dir, "plan"), s.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	begin, _, err := custodyCommandEntry(filepath.Join(dir, "begin"), s.BeginID)
	if err != nil {
		t.Fatal(err)
	}
	b, err := readRegularArtifact(filepath.Join(dir, "challenge"), workarchive.MaximumCustodyChallengeBytes)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := workarchive.DecodeCustodyChallenge(b)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := plan.ID()
	bid, _ := begin.ID()
	scope := store.RemoteCustodyScope{Worker: remoteworker.Config{Assignment: a, Plan: plan, PlanID: pid, Begin: begin, BeginID: bid}, Manifest: m, InitialReceipt: r, PreviousReceipt: previous, Challenge: challenge, CustodyPolicy: workarchive.CustodyPolicy{TrustedAuditors: a.Auditors, MaximumChallengeLifetime: p.Lifetime, MaximumProofAge: p.ProofAge, MaximumRenewalTerm: p.RenewalTerm}}
	if err := store.ValidateRemoteCustodyScope(scope); err != nil {
		t.Fatal(err)
	}
	return scope
}

// Read existing original roots without loading any role seed or publishing
// evidence. A busy B worker is reported as busy, never as a confirmed snapshot.
func TestInspectRemoteV1Fixture(t *testing.T) {
	if os.Getenv("OUTCOMEMESH_REMOTE_ROLE_ROOT") == "" {
		t.Skip("explicit V1 role inspection")
	}
	root, p, s := remoteV1ReadSession(t)
	scope := remoteV1Scope(t, root, p, s)
	journal, state, err := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), filepath.Join(root, "journal"), scope.Manifest, scope.InitialReceipt, scope.CustodyPolicy, workarchive.DefaultCustodyJournalLimits())
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := state.CurrentReceipt.ID()
	result := map[string]any{"assignment_id": s.AssignmentID, "journal_sequence": state.Sequence, "journal_head_id": state.HeadEntryID.String(), "current_receipt_id": rid.String(), "role": p.Role}
	operation := filepath.Join(root, "operations", fmt.Sprintf("%03d", s.Cycle))
	intentBytes, err := readRegularArtifact(filepath.Join(root, "intent", fmt.Sprintf("%03d", s.Cycle)), workarchive.MaximumCustodyAuditIntentBytes)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := workarchive.DecodeCustodyAuditIntent(intentBytes)
	if err != nil {
		t.Fatal(err)
	}
	auditBytes, err := readRegularArtifact(filepath.Join(operation, "audit"), custodyauthority.MaximumEntryBytes)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := custodyauthority.DecodeEntry(auditBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ValidateRemoteCustodyAuditScope(scope, intent, audit); err != nil {
		t.Fatal(err)
	}
	iid, _ := intent.ID()
	aid, _ := audit.ID()
	sid, _ := scope.Worker.Plan.Admission.ID()
	result["intent_id"], result["audit_ticket_id"], result["serve_ticket_id"] = iid.String(), aid.String(), sid.String()
	if body, err := readRegularArtifact(filepath.Join(operation, "drain"), remotewire.MaxFrameBytes); err == nil {
		response, err := remotewire.DecodeResponse(body)
		if err != nil {
			t.Fatal(err)
		}
		_, id, err := store.RemoteCustodyDrainArtifact(scope, response)
		if err != nil {
			t.Fatal(err)
		}
		result["drain_id"] = id.String()
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	identities := make(map[string]string)
	paths := []string{"journal", "journal/journal.lock"}
	if p.Role == "a" {
		paths = append(paths, "authority", "authority-pins", "artifacts", "artifacts/custody.lock")
	}
	for _, name := range paths {
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatal("missing native file identity")
		}
		identities[name] = fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
	}
	result["original_identities"] = identities
	if head, exists, err := journal.Head(); err != nil {
		t.Fatal(err)
	} else if exists {
		pid, _ := head.Record.Proof.ID()
		result["proof_id"], result["responded_at"] = pid.String(), head.Record.Proof.RespondedAt
	}
	if p.Role == "a" {
		owner, err := store.OpenCoordinator(filepath.Join(root, "authority"), filepath.Join(root, "authority-pins"), scope.Worker.Assignment, scope.Worker.Plan.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		c, err := owner.Snapshot()
		closeErr := owner.Close()
		if err != nil || closeErr != nil {
			t.Fatal(err, closeErr)
		}
		result["confirmed_sequence"], result["confirmed_head"], result["pending_attempt"], result["pending_operations"] = c.Confirmed.Sequence, c.Confirmed.HeadID.String(), c.Pending != nil, c.Authority.Pending
		result["active_remote"] = c.Authority.Remote != nil
	} else {
		worker, err := remoteworker.Open(t.Context(), filepath.Join(root, "workers", fmt.Sprintf("%03d", s.Cycle)), scope.Worker)
		if errors.Is(err, remoteworker.ErrBusy) {
			result["worker_busy"] = true
		} else {
			if err != nil {
				t.Fatal(err)
			}
			snap, err := worker.Snapshot(t.Context())
			closeErr := worker.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			result["worker_busy"], result["worker_stage"], result["worker_pending"], result["seal_id"] = false, snap.Stage, snap.Pending, snap.SealID.String()
			if snap.Seal != nil {
				result["disposition"], result["result_id"] = snap.Seal.Disposition, snap.Seal.ResultID.String()
			}
		}
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("remote_v1_inspect %s\n", b)
}

// B-only private store-test configuration, derived from the exact CLI-produced
// artifacts. No authority root/key or A transport seed is loaded or serialized.
func TestPrepareRemoteV1GateConfig(t *testing.T) {
	if os.Getenv("OUTCOMEMESH_REMOTE_ROLE_ROOT") == "" {
		t.Skip("explicit B-only V1 pause helper")
	}
	root, p, s := remoteV1ReadSession(t)
	if p.Role != "b" {
		t.Fatal("pause helper requires B")
	}
	scope := remoteV1Scope(t, root, p, s)
	dir := filepath.Join(root, "operations", fmt.Sprintf("%03d", s.Cycle))
	key := func(name string) ed25519.PrivateKey {
		k, err := loadPruneOfflineKey(filepath.Join(root, "keys", name+".seed"))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	for _, stage := range []string{"remote-data-admitted", "remote-data-before-response-write", "remote-control-drained-before-response-write"} {
		value := map[string]any{"Scope": scope, "WorkerPath": filepath.Join(root, "workers", fmt.Sprintf("%03d", s.Cycle)), "JournalPath": filepath.Join(root, "journal"), "ObjectPath": filepath.Join(root, "objects"), "ObjectPolicy": workarchive.DefaultObjectStorePolicy(), "JournalLimits": workarchive.DefaultCustodyJournalLimits(), "ReplicaPrivateKey": key("replica"), "ControlPrivateKey": key("b-control"), "TransportPrivateKey": key("b-transport"), "Timeout": int64(10 * time.Second), "Now": uint64(0), "PauseStage": stage, "Listen": []string{"/ip4/0.0.0.0/udp/43980/quic-v1"}, "Marker": filepath.Join(dir, "gate.marker")}
		writeRemoteCustodyFixtureJSON(t, filepath.Join(dir, stage+".json"), value)
	}
	fmt.Println("remote_v1_gate_config prepared=true authority_keys_loaded=false")
}
