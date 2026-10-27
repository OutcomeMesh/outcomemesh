package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func openRemoteAuditFixture(t testing.TB) (*remoteExecutionFixture, *RemoteCustodyAuditRuntime, RemoteCustodyAuditRuntimeConfig) {
	t.Helper()
	f := newRemoteExecutionFixture(t)
	config := f.auditConfig(t)
	runtime, err := OpenRemoteCustodyAuditRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	return f, runtime, config
}

func TestRemoteAuditRuntimePreparedBeginAndOriginalOwner(t *testing.T) {
	f, runtime, config := openRemoteAuditFixture(t)
	before := testCoordination(t, runtime.life.owner)
	if before.Pending != nil || before.Authority.Remote != nil || before.Authority.Pending != 2 || before.Confirmed.Sequence != 2 {
		t.Fatal("Open changed the original authority", before)
	}
	if entries, err := os.ReadDir(config.Audit.ArtifactsPath); err != nil || len(entries) != 1 {
		t.Fatal("Open published challenge/output", entries, err)
	}
	if other, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID); !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("runtime did not retain the original A owner", err)
	}
	if _, err := runtime.Begin(t.Context()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Begin implicitly prepared a challenge", err)
	}
	if _, err := runtime.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), "unused-before-confirmation"); !errors.Is(err, ErrRemoteCustody) {
		t.Fatal("Start attempted without confirmed Begin", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, runtime.life.owner)) {
		t.Fatal("rejected Begin/Start changed authority")
	}
	challenge, err := runtime.PrepareChallenge(t.Context())
	got, encodeErr := challenge.CanonicalBytes()
	want, _ := f.scope.Challenge.CanonicalBytes()
	if err != nil || encodeErr != nil || !bytes.Equal(got, want) {
		t.Fatal("preparation changed selected challenge", err, encodeErr)
	}
	commit, err := runtime.Begin(t.Context())
	if err != nil || !commit.Appended || commit.EntryID != f.scope.Worker.BeginID {
		t.Fatal("explicit Begin did not confirm exact proposal", commit, err)
	}
	confirmed := testCoordination(t, runtime.life.owner)
	if confirmed.Pending != nil || confirmed.Authority.Remote == nil || confirmed.Authority.Pending != 2 || confirmed.Confirmed.HeadID != f.scope.Worker.BeginID {
		t.Fatal("Begin lost the remote obligation", confirmed)
	}
	if retry, err := runtime.Begin(t.Context()); err != nil || retry.Appended || retry.EntryID != commit.EntryID {
		t.Fatal("exact confirmed Begin retry appended/replaced work", retry, err)
	}
	if _, err := runtime.PrepareChallenge(t.Context()); !errors.Is(err, custodyauthority.ErrRemoteActive) {
		t.Fatal("active hold widened generic preparation", err)
	}
	if err := runtime.life.owner.WithOperation(t.Context(), runtime.session.binding, func() error {
		t.Error("generic Audit entered during remote hold")
		return nil
	}); !errors.Is(err, custodyauthority.ErrRemoteActive) {
		t.Fatal("generic guard was bypassed", err)
	}
	if _, err := runtime.ResumeBegin(t.Context()); !errors.Is(err, ErrNoAttempt) {
		t.Fatal("ResumeBegin invented a pending attempt", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRemoteCustodyAuditRuntime(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(confirmed, testCoordination(t, reopened.life.owner)) {
		t.Fatal("Open resumed or cleared a durable hold")
	}
	if state, err := reopened.journal.State(); err != nil || state.Sequence != f.scope.Worker.Plan.PriorSequence {
		t.Fatal("Begin/Open manufactured local Audit acceptance", state, err)
	}
}

func TestRemoteAuditRuntimeScopeMismatchRejectsBeforeOutput(t *testing.T) {
	for _, mutate := range []struct {
		name  string
		apply func(*RemoteCustodyAuditRuntimeConfig)
	}{
		{"wrong authority key", func(c *RemoteCustodyAuditRuntimeConfig) { c.AuthorityPrivateKey = testKey(2) }},
		{"changed selected challenge", func(c *RemoteCustodyAuditRuntimeConfig) { c.Scope.Challenge.Nonce = testHash(240) }},
		{"wrong predecessor", func(c *RemoteCustodyAuditRuntimeConfig) { c.Scope.Worker.Plan.PriorReceiptID = testHash(241) }},
		{"wrong Audit admission", func(c *RemoteCustodyAuditRuntimeConfig) { c.Audit.Admission = c.Scope.Worker.Plan.Admission }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			f := newRemoteExecutionFixture(t)
			config := f.auditConfig(t)
			mutate.apply(&config)
			if opened, err := OpenRemoteCustodyAuditRuntime(t.Context(), config); err == nil {
				_ = opened.Close()
				t.Fatal("mismatched pinned scope opened")
			}
			if entries, err := os.ReadDir(config.Audit.ArtifactsPath); err != nil || len(entries) != 1 {
				t.Fatal("invalid Open signed/published challenge", entries, err)
			}
			owner := f.openOwner(t)
			if state := testCoordination(t, owner); state.Pending != nil || state.Authority.Remote != nil || state.Confirmed.Sequence != 2 {
				t.Fatal("invalid Open changed authority", state)
			}
		})
	}
}

func TestRemoteAuditRuntimePendingBeginNeedsExplicitResume(t *testing.T) {
	for _, authorityDecided := range []bool{false, true} {
		t.Run(map[bool]string{false: "intent only", true: "authority decided"}[authorityDecided], func(t *testing.T) {
			f, runtime, config := openRemoteAuditFixture(t)
			if _, err := runtime.PrepareChallenge(t.Context()); err != nil {
				t.Fatal(err)
			}
			owner := runtime.life.owner
			owner.mu.Lock()
			err := owner.journal.prepare(t.Context(), f.scope.Worker.Begin)
			if err == nil && authorityDecided {
				_, err = owner.authority.Append(t.Context(), f.scope.Worker.Begin)
			}
			owner.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Begin(t.Context()); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("Begin implicitly resumed its pending attempt", err)
			}
			if _, err := runtime.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), "unused-pending-begin"); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("observed/unconfirmed Begin enabled Start", err)
			}
			if _, err := runtime.SealQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), "unused-pending-begin"); !errors.Is(err, ErrPendingAttempt) {
				t.Fatal("Seal implicitly resumed pending Begin", err)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenRemoteCustodyAuditRuntime(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			before := testCoordination(t, reopened.life.owner)
			if before.Pending == nil || *before.Pending != f.scope.Worker.Begin || before.Confirmed.Sequence != 2 {
				t.Fatal("Open auto-confirmed Begin", before)
			}
			commit, err := reopened.ResumeBegin(t.Context())
			if err != nil || commit.EntryID != f.scope.Worker.BeginID || commit.Appended == authorityDecided {
				t.Fatal("explicit Begin resume changed exact decision", commit, err)
			}
			after := testCoordination(t, reopened.life.owner)
			if after.Pending != nil || after.Authority.Remote == nil || after.Confirmed.HeadID != f.scope.Worker.BeginID || after.Authority.Pending != 2 {
				t.Fatal("Begin resume lost hold or completed work", after)
			}
		})
	}
}

func TestRemoteAuditRuntimeRejectsOtherPendingCommand(t *testing.T) {
	f, runtime, _ := openRemoteAuditFixture(t)
	owner := runtime.life.owner
	stop := remoteStoreCommand(t, f.scope.Worker.Assignment, testCoordination(t, owner).Authority,
		custodyauthority.Stop, 0, types.Hash{}, types.Hash{}, testHash(242), 1)
	owner.mu.Lock()
	err := owner.journal.prepare(t.Context(), stop)
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.ResumeBegin(t.Context()); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal("ResumeBegin resumed a Stop", err)
	}
	if _, err := runtime.ResumeDrainQUIC(t.Context(), testKey(16), libp2ptransport.DefaultConfig(), "unused-other-pending"); !errors.Is(err, ErrPendingAttempt) {
		t.Fatal("ResumeDrain reconciled another pending kind", err)
	}
	if state := testCoordination(t, owner); state.Pending == nil || *state.Pending != stop || state.Confirmed.Sequence != 2 {
		t.Fatal("explicit remote recovery replaced retained Stop", state)
	}
}

func TestRemoteAuditRuntimePreexistingResultCannotBeginNewRemoteSession(t *testing.T) {
	f, runtime, _ := openRemoteAuditFixture(t)
	if _, err := runtime.PrepareChallenge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.base.journal.Append(f.base.answer(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Begin(t.Context()); !errors.Is(err, ErrRemoteCustody) {
		t.Fatal("preexisting A result enabled a new remote execution", err)
	}
	if state := testCoordination(t, runtime.life.owner); state.Authority.Remote != nil || state.Confirmed.Sequence != 2 || state.Authority.Pending != 2 {
		t.Fatal("preexisting result changed remote authority", state)
	}
}

func TestRemoteAuditRuntimeRejectsReplacedOriginalSource(t *testing.T) {
	for _, selected := range []string{"journal directory", "journal lock", "artifact directory", "artifact lock"} {
		t.Run(selected, func(t *testing.T) {
			f, runtime, _ := openRemoteAuditFixture(t)
			before := testCoordination(t, runtime.life.owner)
			var path string
			directory := false
			switch selected {
			case "journal directory":
				path, directory = runtime.session.journalPath, true
			case "journal lock":
				path = filepath.Join(runtime.session.journalPath, "journal.lock")
			case "artifact directory":
				path, directory = runtime.session.artifactsPath, true
			case "artifact lock":
				path = filepath.Join(runtime.session.artifactsPath, "custody.lock")
			}
			// Keep the original inode alive, including on filesystems that
			// immediately recycle an unlinked inode for a same-byte rewrite.
			retained := filepath.Join(t.TempDir(), "original")
			if err := os.Rename(path, retained); err != nil {
				t.Fatal(err)
			}
			if directory {
				if err := os.CopyFS(path, os.DirFS(retained)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.PrepareChallenge(t.Context()); !errors.Is(err, ErrRemoteCustody) {
				t.Fatal("same-byte replacement became the original A source", err)
			}
			if _, err := runtime.Begin(t.Context()); !errors.Is(err, ErrRemoteCustody) {
				t.Fatal("replacement enabled Begin", err)
			}
			if _, err := runtime.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), "unused-replaced-source"); !errors.Is(err, ErrRemoteCustody) {
				t.Fatal("replacement enabled remote Start", err)
			}
			if !reflect.DeepEqual(before, testCoordination(t, runtime.life.owner)) || before.Confirmed.HeadID == f.scope.Worker.BeginID {
				t.Fatal("replaced source changed authority")
			}
		})
	}
}

func TestRemoteAuditRuntimeDrainedSessionCannotRestartOrPrepare(t *testing.T) {
	f, runtime, config := openRemoteAuditFixture(t)
	if _, err := runtime.PrepareChallenge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Begin(t.Context()); err != nil {
		t.Fatal(err)
	}
	worker, err := remoteworker.Open(t.Context(), f.workerPath, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.BeginSeal(t.Context()); err != nil {
		t.Fatal(err)
	}
	seal, err := worker.CommitSeal(t.Context(), remoteworker.Unseen, types.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	sealID, _ := seal.ID()
	draft, err := worker.DrainedDraft(t.Context(), sealID, testCoordination(t, runtime.life.owner).Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	drain := remoteFoundationCosign(t, f.scope.Worker.Assignment, draft)
	appendCoordinated(t, runtime.life.owner, drain)
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRemoteCustodyAuditRuntime(t.Context(), config)
	if err != nil {
		t.Fatal("post-drain owner did not open for terminal work", err)
	}
	defer reopened.Close()
	before := testCoordination(t, reopened.life.owner)
	if _, err := reopened.PrepareChallenge(t.Context()); !errors.Is(err, custodyauthority.ErrOperation) {
		t.Fatal("drained session reopened challenge execution", err)
	}
	if _, err := reopened.ExecuteQUIC(t.Context(), testKey(16), testKey(46), libp2ptransport.DefaultConfig(), "unused-after-drain"); !errors.Is(err, ErrRemoteCustody) {
		t.Fatal("sealed session reopened Start", err)
	}
	if !reflect.DeepEqual(before, testCoordination(t, reopened.life.owner)) || before.Authority.Pending != 2 {
		t.Fatal("drain implicitly completed or restarted work")
	}
}

func TestRemoteAuditRuntimeCloseWaitsForGuardedActionWithoutClearingDebt(t *testing.T) {
	f, runtime, config := openRemoteAuditFixture(t)
	if _, err := runtime.PrepareChallenge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Begin(t.Context()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	injected := errors.New("stop before any network dispatch")
	runtime.hooks = storeHooks{at: func(stage string) error {
		if stage == "remote-audit-before-start" {
			close(entered)
			<-release
			return injected
		}
		return nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	executed := make(chan error, 1)
	go func() {
		_, err := runtime.ExecuteQUIC(ctx, testKey(16), testKey(46), libp2ptransport.DefaultConfig(), "unused-hooked-dispatch")
		executed <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("action did not reach exact confirmed guard")
	}
	closed := make(chan error, 1)
	go func() { closed <- runtime.Close() }()
	select {
	case err := <-closed:
		t.Fatal("Close released owner before synchronous action drained", err)
	case <-time.After(20 * time.Millisecond):
	}
	if owner, err := OpenCoordinator(config.AuthorityPath, config.AuthorityPinsPath, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID); !errors.Is(err, ErrBusy) {
		if owner != nil {
			_ = owner.Close()
		}
		t.Fatal("Close exposed original owner during callback drain", err)
	}
	close(release)
	if err := <-executed; !errors.Is(err, injected) {
		t.Fatal("action error was lost", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	owner := f.openOwner(t)
	if state := testCoordination(t, owner); state.Pending != nil || state.Authority.Remote == nil || state.Authority.Pending != 2 || state.Confirmed.HeadID != f.scope.Worker.BeginID {
		t.Fatal("Close/error implicitly drained or completed remote obligation", state)
	}
}
