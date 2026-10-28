//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type v2WANMetadata struct {
	Version                                                int `json:"version"`
	Scenario, Role                                         string
	ContextID, ScopeID, ServeScopeID, AssignmentID, PlanID string
	IssuedAt, ExpiresAt, ProofAge                          uint64
	Keys                                                   map[string]string
	Members                                                []map[string]string
	OriginalOwnersCreated                                  bool
}

func exportV2WAN(t testing.TB, parent, scenario string) string {
	t.Helper()
	if scenario != "lost-result" && scenario != "lost-session" && scenario != "expired-result" {
		t.Fatal("unknown V2 WAN scenario")
	}
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private existing export parent required", e)
	}
	root, e := os.MkdirTemp(parent, "v2-wan-")
	if e != nil {
		t.Fatal(e)
	}
	archive := newPruneEffectCLIFixture(t, false)
	m, e := loadArchiveManifest(archive.manifestPath)
	if e != nil {
		t.Fatal(e)
	}
	now := uint64(time.Now().Unix())
	receipt, e := workarchive.CreateReplicaReceipt(archive.config.Replicas[0].Directory, archive.inventory.Policy.Checkpoint, archive.inventory.Policy.CheckpointPolicy, archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits(), f.Key(61), remoteCustodyRandomHash(t), now-30, now+8*3600)
	if e != nil {
		t.Fatal(e)
	}
	age := uint64(600)
	if scenario == "expired-result" {
		age = 2
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: [][32]byte{f.Public(3)}, MaximumChallengeLifetime: 600, MaximumProofAge: age, MaximumRenewalTerm: 24 * 3600}
	consumers := []custodyauthority.Consumer{{PublicKey: f.Public(4), Purposes: custodyauthority.Audit | custodyauthority.Prune}, {PublicKey: f.Public(5), Purposes: custodyauthority.Serve}}
	sort.Slice(consumers, func(i, j int) bool { return bytes.Compare(consumers[i].PublicKey[:], consumers[j].PublicKey[:]) < 0 })
	base, e := workarchive.CreateRemoteCustodyAuthorityAssignment(m, receipt, policy, remoteCustodyRandomHash(t), f.Public(1), consumers, 16, 4, f.Public(14), f.Public(15))
	if e != nil {
		t.Fatal(e)
	}
	a := v2.Assignment{Version: 2, Base: base, Policy: v2.Policy{Version: 2, Threshold: 3, Witnesses: f.Scope().Witnesses}}
	aid, e := a.ID()
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := workarchive.CreateCustodyChallenge(m, receipt, f.Key(3), now, 600, 1, receipt.RetainUntil+3600)
	if e != nil {
		t.Fatal(e)
	}
	rid, _ := receipt.ID()
	peer, _ := transportPeer(f.Public(15))
	intent := workarchive.CustodyAuditIntent{AssignmentID: aid, ConsumerPublicKey: f.Public(4), AuditorPublicKey: f.Public(3), ReplicaPeerID: peer, PriorReceiptID: rid, IssuedAt: challenge.IssuedAt, ExpiresAt: challenge.ExpiresAt, RenewUntil: challenge.RenewUntil, RequestedSamples: challenge.RequestedSamples, Nonce: challenge.Nonce}
	plan := v2.Plan{Version: 2, AssignmentID: aid, Intent: intent, Challenge: challenge, ServeConsumer: f.Public(5), ClientTransportPublicKey: f.Public(46)}
	for _, role := range []struct {
		name string
		seed byte
	}{{"audit", 4}, {"serve", 5}, {"authority", 1}} {
		plan, e = plan.Sign(role.name, f.Key(role.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	c := v2.Context{Assignment: a, Plan: plan, Manifest: m, Initial: receipt, Previous: receipt, CustodyPolicy: policy}
	scope, e := c.Scope()
	if e != nil {
		t.Fatal(e)
	}
	sid, _ := scope.ID()
	cid, _ := c.ID()
	pid, _ := plan.ID()
	contextBytes, _ := c.CanonicalBytes()
	keys := map[string]string{}
	for name, seed := range map[string]byte{"authority": 1, "auditor": 3, "audit": 4, "serve": 5, "control": 14, "transport": 15, "replica": 61, "client": 46} {
		keys[name] = types.Hash(f.Public(seed)).String()
	}
	client, _ := transportPeer(f.Public(46))
	keys["client-peer"] = client.String()
	var members []map[string]string
	for i := byte(0); i < 4; i++ {
		members = append(members, map[string]string{"signing_public_key": types.Hash(f.Public(70 + i)).String(), "transport_public_key": types.Hash(f.Public(90 + i)).String()})
	}
	serveScope, e := c.ServeScope()
	if e != nil {
		t.Fatal(e)
	}
	serveID, _ := serveScope.ID()
	metadata := v2WANMetadata{ServeScopeID: serveID.String(), Version: 2, Scenario: scenario, ContextID: cid.String(), ScopeID: sid.String(), AssignmentID: aid.String(), PlanID: pid.String(), IssuedAt: now, ExpiresAt: challenge.ExpiresAt, ProofAge: age, Keys: keys, Members: members}
	sourceObjects, e := workarchive.OpenObjectStore(filepath.Join(t.TempDir(), "source-objects"), workarchive.DefaultObjectStorePolicy())
	if e != nil {
		t.Fatal(e)
	}
	if _, e := sourceObjects.ImportArchiveDirectory(archive.config.Replicas[0].Directory, archive.inventory.Policy.Checkpoint, archive.inventory.Policy.CheckpointPolicy, archive.config.Base, archive.config.Parameters, workarchive.DefaultLimits()); e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"a", "b", "clone"} {
		dir := filepath.Join(root, role)
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Mkdir(filepath.Join(dir, "keys"), 0700); e != nil {
			t.Fatal(e)
		}
		metadata.Role = role
		writeRemoteCustodyFixtureJSON(t, filepath.Join(dir, "public.json"), metadata)
		writeRemoteCustodyFixtureFile(t, filepath.Join(dir, "expected-context"), contextBytes)
		if _, _, e := workarchive.OpenOrCreateCustodyJournal(filepath.Join(dir, "journal"), m, receipt, policy); e != nil {
			t.Fatal(e)
		}
		seeds := map[string]byte{"serve": 5, "control": 14, "transport": 15, "replica": 61}
		if role == "a" {
			seeds = map[string]byte{"authority": 1, "auditor": 3, "audit": 4, "client": 46}
		}
		for name, seed := range seeds {
			writeRemoteCustodyFixtureFile(t, filepath.Join(dir, "keys", name+".seed"), f.Key(seed).Seed())
		}
		for i := byte(0); i < 4; i++ {
			if (role == "a" && i < 2) || (role == "b" && i >= 2) {
				writeRemoteCustodyFixtureFile(t, filepath.Join(dir, "keys", fmt.Sprintf("witness-%d.seed", i)), f.Key(70+i).Seed())
				writeRemoteCustodyFixtureFile(t, filepath.Join(dir, "keys", fmt.Sprintf("witness-transport-%d.seed", i)), f.Key(90+i).Seed())
			}
		}
		if role != "a" {
			objects, e := workarchive.OpenObjectStore(filepath.Join(dir, "objects"), workarchive.DefaultObjectStorePolicy())
			if e != nil {
				t.Fatal(e)
			}
			for _, chunk := range m.Chunks {
				b, e := sourceObjects.Get(chunk.ID)
				if e != nil {
					t.Fatal(e)
				}
				if _, e := objects.Put(m, chunk.ID, b); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	draft := c
	draft.Plan.AuditSignature = [64]byte{}
	draft.Plan.ServeSignature = [64]byte{}
	draft.Plan.AuthoritySignature = [64]byte{}
	writeRemoteCustodyFixtureJSON(t, filepath.Join(root, "a", "draft.json"), draft)
	return root
}
func TestExportCustodyV2WANFixture(t *testing.T) {
	parent := os.Getenv("OUTCOMEMESH_REMOTE_FIXTURE_OUT")
	if parent == "" {
		t.Skip("explicit never-started V2 WAN fixture export")
	}
	root := exportV2WAN(t, parent, os.Getenv("OMESH_V2_SCENARIO"))
	fmt.Printf("custody_v2_fixture root=%s owners_created=false test_keys_public=true\n", root)
}
func TestInspectCustodyV2WANFixture(t *testing.T) {
	root := os.Getenv("OUTCOMEMESH_REMOTE_ROLE_ROOT")
	if root == "" {
		t.Skip("explicit original V2 fixture inspection")
	}
	b, e := readRegularArtifact(filepath.Join(root, "public.json"), 32768)
	if e != nil {
		t.Fatal(e)
	}
	var meta v2WANMetadata
	if e := json.Unmarshal(b, &meta); e != nil {
		t.Fatal(e)
	}
	b, e = readRegularArtifact(filepath.Join(root, "context"), v2.MaximumContextBytes)
	if e != nil {
		t.Fatal(e)
	}
	c, e := v2.DecodeContext(b)
	if e != nil {
		t.Fatal(e)
	}
	cid, _ := c.ID()
	if cid.String() != meta.ContextID {
		t.Fatal("unexpected context")
	}
	journal, _, e := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), filepath.Join(root, "journal"), c.Manifest, c.Initial, c.CustodyPolicy, workarchive.DefaultCustodyJournalLimits())
	if e != nil {
		t.Fatal(e)
	}
	state, e := journal.State()
	if e != nil {
		t.Fatal(e)
	}
	rid, _ := state.CurrentReceipt.ID()
	out := map[string]any{"role": meta.Role, "context_id": meta.ContextID, "scope_id": meta.ScopeID, "source_sequence": state.Sequence, "source_head": state.HeadEntryID.String(), "receipt_id": rid.String(), "now": uint64(time.Now().Unix()), "consumed": false, "result": false, "accepted": false}
	identities := map[string]any{}
	for _, name := range []string{"journal", "journal/journal.lock", "owner", "owner/owner.lock"} {
		if i, e := os.Stat(filepath.Join(root, name)); e == nil {
			s := i.Sys().(*syscall.Stat_t)
			identities[name] = []uint64{uint64(s.Dev), s.Ino, uint64(s.Uid), uint64(i.Mode())}
		}
	}
	raw, _ := json.Marshal(identities)
	out["original_identities_sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
	if _, e := os.Lstat(filepath.Join(root, "owner", "consumed")); e == nil {
		out["consumed"] = true
	}
	if b, exists := optionalV2WANArtifact(t, root, "owner/result", v2.MaximumResultBytes); exists {
		result, e := v2.DecodeResult(b)
		if e != nil {
			t.Fatal(e)
		}
		qraw, e := readRegularArtifact(filepath.Join(root, "claim.qc"), custodyfence.MaximumCertificateBytes)
		if e != nil {
			t.Fatal(e)
		}
		q, e := custodyfence.DecodeCertificate(qraw)
		if e != nil || result.Verify(c, q) != nil {
			t.Fatal("result is not bound to original claim", e)
		}
		id, _ := result.ID()
		eid, _ := result.Entry.ID()
		if state.HeadEntryID != eid || state.Sequence != result.Entry.Sequence {
			t.Fatal("retained result differs from original source")
		}
		out["result"] = true
		out["result_id"] = id.String()
		out["result_sha256"] = fmt.Sprintf("%x", sha256.Sum256(b))
		out["responded_at"] = result.Entry.Record.Proof.RespondedAt
	}
	if b, exists := optionalV2WANArtifact(t, root, "owner/accepted", v2.ReceiptBytes); exists {
		receipt, e := v2.DecodeReceipt(b)
		if e != nil {
			t.Fatal(e)
		}
		bundleRaw, e := readRegularArtifact(filepath.Join(root, "bundle"), v2.MaximumBundleBytes)
		if e != nil {
			t.Fatal(e)
		}
		bundle, e := v2.DecodeBundle(bundleRaw)
		if e != nil || receipt.Verify(c, bundle) != nil {
			t.Fatal("invalid accepted bundle", e)
		}
		if receipt.SourceSequence != state.Sequence || receipt.SourceHeadID != state.HeadEntryID {
			t.Fatal("receipt differs from original accepted source")
		}
		id, _ := receipt.ID()
		out["accepted"] = true
		out["accepted_id"] = id.String()
		out["accepted_sha256"] = fmt.Sprintf("%x", sha256.Sum256(b))
		out["accepted_at"] = receipt.AcceptedAt
		resultID, _ := bundle.Result.ID()
		out["result_id"] = resultID.String()
		out["responded_at"] = bundle.Result.Entry.Record.Proof.RespondedAt
	}
	raw, e = json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println("custody_v2_inspect " + string(raw))
}
func TestCustodyV2WANFixtureContainsOnlyFreshSources(t *testing.T) {
	parent := t.TempDir()
	_ = os.Chmod(parent, 0700)
	root := exportV2WAN(t, parent, "lost-result")
	for _, role := range []string{"a", "b", "clone"} {
		dir := filepath.Join(root, role)
		if _, e := os.Stat(filepath.Join(dir, "owner")); !os.IsNotExist(e) {
			t.Fatal("exported operational owner", e)
		}
		if _, e := os.Stat(filepath.Join(dir, "keys", "authority.seed")); role != "a" && !os.IsNotExist(e) {
			t.Fatal("A private role reached B", e)
		}
	}
}

func optionalV2WANArtifact(t testing.TB, root, name string, limit int) ([]byte, bool) {
	t.Helper()
	b, e := readRegularArtifact(filepath.Join(root, name), limit)
	if errors.Is(e, os.ErrNotExist) {
		return nil, false
	}
	if e != nil {
		t.Fatal(e)
	}
	return b, true
}

// Test-only authenticated hostile packets bypass local CLI validation. This
// helper cannot sign a proof, change an owner or accept a source record.
func TestCustodyV2WANProbe(t *testing.T) {
	root := os.Getenv("OUTCOMEMESH_REMOTE_ROLE_ROOT")
	if root == "" {
		t.Skip("explicit V2 WAN rejection probe")
	}
	b, e := readRegularArtifact(filepath.Join(root, "probe.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	var probe struct{ Kind, Peer string }
	if e := json.Unmarshal(b, &probe); e != nil {
		t.Fatal(e)
	}
	b, e = readRegularArtifact(filepath.Join(root, "context"), v2.MaximumContextBytes)
	if e != nil {
		t.Fatal(e)
	}
	c, e := v2.DecodeContext(b)
	if e != nil {
		t.Fatal(e)
	}
	key, e := witnessKey(filepath.Join(root, "keys/client.seed"), c.Plan.ClientTransportPublicKey)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key)
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	config := libp2ptransport.DefaultConfig()
	config.Listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1"}
	host, e := libp2ptransport.New(ctx, key, config, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer host.Close()
	peer, e := transportPeer(c.Assignment.Base.RemoteTransportPublicKey)
	if e != nil {
		t.Fatal(e)
	}
	if probe.Kind == "legacy" {
		if stream, _, e := host.OpenArchiveCustodyStream(ctx, probe.Peer, peer); e == nil {
			_ = stream.Close()
			t.Fatal("legacy effect endpoint enabled")
		}
		fmt.Println("custody_v2_probe kind=legacy refused=true")
		return
	}
	b, e = readRegularArtifact(filepath.Join(root, "claim.qc"), custodyfence.MaximumCertificateBytes)
	if e != nil {
		t.Fatal(e)
	}
	claim, e := custodyfence.DecodeCertificate(b)
	if e != nil {
		t.Fatal(e)
	}
	scope, _ := c.Scope()
	sid, _ := scope.ID()
	request := v2.Request{Version: 2, Operation: v2.Execute, ScopeID: sid, Nonce: f.Hash("wan-probe-" + probe.Kind), Prefix: []custodyfence.Certificate{claim}}
	switch probe.Kind {
	case "weak":
		request.Prefix[0].Votes = request.Prefix[0].Votes[:2]
	case "wrong-scope":
		request.ScopeID = f.Hash("wrong-scope")
	case "late":
	default:
		t.Fatal("unknown bounded V2 probe")
	}
	stream, _, e := host.OpenCustodyV2Stream(ctx, probe.Peer, peer)
	if e != nil {
		t.Fatal("probe did not reach selected authenticated endpoint", e)
	}
	defer stream.Close()
	_, cleanup, e := remotewire.BoundStream(ctx, stream, 2*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer cleanup()
	if e := v2.WriteRequest(stream, request); e != nil {
		t.Fatal(e)
	}
	if e := stream.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	if _, e := v2.ReadResponse(stream); e == nil {
		t.Fatal("hostile execution request succeeded")
	}
	fmt.Printf("custody_v2_probe kind=%s refused=true\n", probe.Kind)
}
