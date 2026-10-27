package store

import (
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type remoteExecutionFixture struct {
	base                                *managedAuditFixture
	scope                               RemoteCustodyScope
	intent                              workarchive.CustodyAuditIntent
	audit                               custodyauthority.Entry
	authorityPath, pinsPath, workerPath string
}

// Only A has an authority root. B's independently bootstrapped worker journal
// contains the public plan/proposal and never a copy of A's owner or private key.
func newRemoteExecutionFixture(t testing.TB) *remoteExecutionFixture {
	t.Helper()
	f := &remoteExecutionFixture{base: newManagedAuditFixture(t)}
	b := f.base
	a, err := workarchive.CreateRemoteCustodyAuthorityAssignment(b.config.Manifest, b.config.InitialReceipt, b.config.CustodyPolicy,
		testHash(211), testPublic(1), []custodyauthority.Consumer{{PublicKey: testPublic(4), Purposes: custodyauthority.AllPurposes}},
		4, 2, testPublic(14), testPublic(15))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := a.ID()
	f.intent = b.intent
	f.intent.AssignmentID, f.intent.ReplicaPeerID = id, runtimePeer(15)
	intentID, _ := f.intent.ID()
	root := t.TempDir()
	f.authorityPath, f.pinsPath = filepath.Join(root, "authority"), filepath.Join(root, "pins")
	owner, err := CreateCoordinatedAuthority(f.authorityPath, f.pinsPath, a, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	f.audit = remoteStoreCommand(t, a, testCoordination(t, owner).Authority, custodyauthority.Admit, custodyauthority.Audit,
		intentID, types.Hash{}, types.Hash{}, 4)
	appendCoordinated(t, owner, f.audit)
	challengeID, _ := b.serve.challenge.ID()
	serve := remoteStoreCommand(t, a, testCoordination(t, owner).Authority, custodyauthority.Admit, custodyauthority.Serve,
		challengeID, types.Hash{}, types.Hash{}, 4)
	appendCoordinated(t, owner, serve)
	receiptID, _ := b.config.InitialReceipt.ID()
	plan := remoteworker.Plan{AssignmentID: id, Admission: serve, AuthorityTransportPublicKey: testPublic(16),
		AuditorTransportPublicKey: testPublic(46), PriorReceiptID: receiptID, Nonce: testHash(212)}
	planID, err := plan.ID()
	if err != nil {
		t.Fatal(err)
	}
	draft, err := custodyauthority.BuildRemoteBeginCommand(a, serve, planID, testCoordination(t, owner).Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	begin := remoteFoundationCosign(t, a, draft)
	beginID, _ := begin.ID()
	f.scope = RemoteCustodyScope{Worker: remoteworker.Config{Assignment: a, Plan: plan, PlanID: planID, Begin: begin, BeginID: beginID},
		Manifest: b.config.Manifest, InitialReceipt: b.config.InitialReceipt, PreviousReceipt: b.config.InitialReceipt,
		CustodyPolicy: b.config.CustodyPolicy, Challenge: b.serve.challenge}
	if err := validateRemoteAuditScope(f.scope, f.intent, f.audit); err != nil {
		t.Fatal(err)
	}
	f.workerPath = filepath.Join(t.TempDir(), "worker")
	worker, err := remoteworker.Create(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *remoteExecutionFixture) auditConfig(t testing.TB) RemoteCustodyAuditRuntimeConfig {
	t.Helper()
	audit := f.base.config
	audit.AssignmentID = f.scope.Worker.Plan.AssignmentID
	audit.Admission, audit.IntentID = f.audit, mustRemoteIntentID(t, f.intent)
	audit.IntentPath = filepath.Join(t.TempDir(), "intent.omcai")
	if err := workarchive.PublishCustodyAuditIntent(t.Context(), audit.IntentPath, f.intent); err != nil {
		t.Fatal(err)
	}
	return RemoteCustodyAuditRuntimeConfig{AuthorityPath: f.authorityPath, AuthorityPinsPath: f.pinsPath,
		Scope: f.scope, Audit: audit, AuthorityPrivateKey: testKey(1)}
}

func (f *remoteExecutionFixture) serveConfig() RemoteCustodyServeServiceConfig {
	b := f.base.serve.config
	return RemoteCustodyServeServiceConfig{Scope: f.scope, WorkerPath: f.workerPath, JournalPath: b.JournalPath,
		ObjectPath: b.Objects.Directory(), ObjectPolicy: workarchive.DefaultObjectStorePolicy(), JournalLimits: b.JournalLimits,
		ReplicaPrivateKey: b.ReplicaPrivateKey, ControlPrivateKey: testKey(14), SessionConfig: b.SessionConfig}
}

func mustRemoteIntentID(t testing.TB, intent workarchive.CustodyAuditIntent) types.Hash {
	t.Helper()
	id, err := intent.ID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *remoteExecutionFixture) openOwner(t testing.TB) *Coordinator {
	t.Helper()
	owner, err := OpenCoordinator(f.authorityPath, f.pinsPath, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner
}
