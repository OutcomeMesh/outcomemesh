package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type remoteCLIFixture struct {
	base                                                         *managedCustodyAuditCLIFixture
	scope                                                        store.RemoteCustodyScope
	audit                                                        custodyauthority.Entry
	intent                                                       workarchive.CustodyAuditIntent
	public, authority, pins, worker, intentPath, drain, terminal string
	keyPaths                                                     map[byte]string
}

func signRemoteCLI(t testing.TB, c custodyauthority.Command, actor byte) custodyauthority.Entry {
	t.Helper()
	signed, err := c.Sign(pruneCLIKey(actor))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(signed, pruneCLIKey(1))
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func newRemoteCLIFixture(t testing.TB) *remoteCLIFixture {
	t.Helper()
	base := newManagedCustodyAuditCLIFixture(t)
	c := base.config.Audit
	f := &remoteCLIFixture{base: base, public: t.TempDir(), authority: filepath.Join(t.TempDir(), "authority"), pins: filepath.Join(t.TempDir(), "pins"), worker: filepath.Join(t.TempDir(), "worker"), keyPaths: make(map[byte]string)}
	a, err := workarchive.CreateRemoteCustodyAuthorityAssignment(c.Manifest, c.InitialReceipt, c.CustodyPolicy, pruneCLIHash(233), pruneCLIPublic(1), base.config.Assignment.Consumers, 4, 2, pruneCLIPublic(14), pruneCLIPublic(15))
	if err != nil {
		t.Fatal(err)
	}
	aid, _ := a.ID()
	f.intent = base.intent
	f.intent.AssignmentID = aid
	f.intent.ReplicaPeerID, _ = transportPeer(pruneCLIPublic(15))
	iid, _ := f.intent.ID()
	f.intentPath = filepath.Join(t.TempDir(), "intent.omcai")
	if err := workarchive.PublishCustodyAuditIntent(t.Context(), f.intentPath, f.intent); err != nil {
		t.Fatal(err)
	}
	owner, err := store.CreateCoordinatedAuthority(f.authority, f.pins, a, aid)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	appendEntry := func(p custodyauthority.Purpose, op types.Hash) custodyauthority.Entry {
		s, err := owner.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		e := signRemoteCLI(t, custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: aid, ExpectedSequence: s.Confirmed.Sequence, ExpectedHead: s.Confirmed.HeadID, Kind: custodyauthority.Admit, Purpose: p, OperationID: op}, 4)
		if _, err := owner.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	f.audit = appendEntry(custodyauthority.Audit, iid)
	challenge := base.serve.challenge
	cid, _ := challenge.ID()
	serve := appendEntry(custodyauthority.Serve, cid)
	receiptID, _ := c.InitialReceipt.ID()
	plan := remoteworker.Plan{AssignmentID: aid, Admission: serve, AuthorityTransportPublicKey: pruneCLIPublic(16), AuditorTransportPublicKey: pruneCLIPublic(46), PriorReceiptID: receiptID, Nonce: pruneCLIHash(234)}
	pid, _ := plan.ID()
	s, _ := owner.Snapshot()
	draft, err := custodyauthority.BuildRemoteBeginCommand(a, serve, pid, s.Confirmed)
	if err != nil {
		t.Fatal(err)
	}
	begin := signRemoteCLI(t, draft, 14)
	bid, _ := begin.ID()
	f.scope = store.RemoteCustodyScope{Worker: remoteworker.Config{Assignment: a, Plan: plan, PlanID: pid, Begin: begin, BeginID: bid}, Manifest: c.Manifest, InitialReceipt: c.InitialReceipt, PreviousReceipt: c.InitialReceipt, CustodyPolicy: c.CustodyPolicy, Challenge: challenge}
	if err := store.ValidateRemoteCustodyAuditScope(f.scope, f.intent, f.audit); err != nil {
		t.Fatal(err)
	}
	worker, err := remoteworker.Create(t.Context(), f.worker, f.scope.Worker)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name  string
		value interface{ CanonicalBytes() ([]byte, error) }
	}{{"assignment", a}, {"plan", plan}, {"begin", begin}, {"challenge", challenge}, {"audit", f.audit}} {
		b, err := item.value.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		writePruneCLIFile(t, filepath.Join(f.public, item.name), b)
	}
	for _, seed := range []byte{1, 3, 14, 15, 16, 46} {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("key-%d.seed", seed))
		writePruneCLIFile(t, path, pruneCLIKey(seed).Seed())
		f.keyPaths[seed] = path
	}
	out := t.TempDir()
	f.drain, f.terminal = filepath.Join(out, "drain.omcr"), filepath.Join(out, "terminal.omcrt")
	return f
}

func (f *remoteCLIFixture) args(role, mode string) []string {
	w := f.scope.Worker
	c := f.base.config.Audit
	command := remoteCustodyAuditCommand
	journal := c.JournalPath
	control, key := f.keyPaths[16], f.keyPaths[46]
	if role == "serve" {
		command = remoteCustodyServeCommand
		journal = f.base.serve.config.Session.JournalPath
		control, key = f.keyPaths[14], f.keyPaths[15]
	}
	args := []string{command, "--assignment", filepath.Join(f.public, "assignment"), "--assignment-id", w.Plan.AssignmentID.String(), "--plan", filepath.Join(f.public, "plan"), "--plan-id", w.PlanID.String(), "--begin", filepath.Join(f.public, "begin"), "--begin-id", w.BeginID.String(), "--manifest", f.base.serve.manifestPath, "--receipt", f.base.serve.receiptPath, "--previous-receipt", f.base.serve.receiptPath, "--challenge", filepath.Join(f.public, "challenge"), "--journal", journal, "--control-key", control, "--key", key, "--timeout", "5s",
		"--max-challenge-lifetime-seconds", strconv.FormatUint(c.CustodyPolicy.MaximumChallengeLifetime, 10), "--max-proof-age-seconds", strconv.FormatUint(c.CustodyPolicy.MaximumProofAge, 10), "--max-renewal-term-seconds", strconv.FormatUint(c.CustodyPolicy.MaximumRenewalTerm, 10)}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	if role == "serve" {
		return append(args, "--worker", f.worker, "--objects", f.base.serve.config.ObjectPath, "--replica-key", f.base.serve.replicaKey)
	}
	iid, _ := f.intent.ID()
	ticket, _ := f.audit.ID()
	return append(args, "--authority", f.authority, "--authority-pins", f.pins, "--intent", f.intentPath, "--intent-id", iid.String(), "--audit-admission", filepath.Join(f.public, "audit"), "--audit-ticket-id", ticket.String(), "--artifacts", c.ArtifactsPath, "--authority-key", f.keyPaths[1], "--auditor-key", f.keyPaths[3], "--drain", f.drain, "--terminal", f.terminal)
}

type remoteCLIControl struct {
	input  *io.PipeWriter
	lines  chan string
	done   chan error
	cancel context.CancelFunc
}

func startRemoteCLIControl(t testing.TB, args []string) *remoteCLIControl {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &remoteCLIControl{input: inW, lines: make(chan string, 2048), done: make(chan error, 1), cancel: cancel}
	go func() { err := runRemoteCustody(ctx, args, inR, outW); _ = outW.Close(); s.done <- err }()
	go func() {
		scanner := bufio.NewScanner(outR)
		for scanner.Scan() {
			s.lines <- scanner.Text()
		}
		_ = outR.Close()
		close(s.lines)
	}()
	t.Cleanup(func() { cancel(); _ = inW.Close() })
	s.next(t, "remote_custody_ready")
	return s
}
func (s *remoteCLIControl) next(t testing.TB, prefix string) map[string]string {
	t.Helper()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				t.Fatal("remote control closed", prefix)
			}
			if strings.HasPrefix(line, prefix) {
				fields := make(map[string]string)
				for _, field := range strings.Fields(line) {
					key, value, ok := strings.Cut(field, "=")
					if ok {
						fields[key] = value
					}
				}
				return fields
			}
		case <-timer.C:
			t.Fatal("remote control timed out", prefix)
		}
	}
}
func (s *remoteCLIControl) send(t testing.TB, line string) {
	t.Helper()
	if _, err := io.WriteString(s.input, line+"\n"); err != nil {
		t.Fatal(err)
	}
}
func (s *remoteCLIControl) review(t testing.TB) string {
	t.Helper()
	s.send(t, "review")
	fields := s.next(t, "remote_custody_review")
	s.next(t, "remote_custody_scope_end")
	return fields["review_id"]
}
func (s *remoteCLIControl) close(t testing.TB) {
	t.Helper()
	s.send(t, "close")
	select {
	case err := <-s.done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("remote control did not drain")
	}
}

func TestRemoteCustodyCLIReviewDoesNotSealOrInitialize(t *testing.T) {
	f := newRemoteCLIFixture(t)
	before := remoteCLITrees(t, []string{f.authority, f.pins, f.worker, f.base.config.Audit.JournalPath, f.base.serve.config.Session.JournalPath})
	for _, role := range []string{"serve", "audit"} {
		var out strings.Builder
		if err := runRemoteCustody(t.Context(), f.args(role, ""), nil, &out); err != nil {
			t.Fatal(role, err)
		}
		if !strings.Contains(out.String(), "owners_retained=false") {
			t.Fatal(out.String())
		}
	}
	after := remoteCLITrees(t, []string{f.authority, f.pins, f.worker, f.base.config.Audit.JournalPath, f.base.serve.config.Session.JournalPath})
	if !reflect.DeepEqual(before, after) {
		t.Fatal("default review changed retained state")
	}
}

func remoteCLITrees(t testing.TB, roots []string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				result[path] = "directory"
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result[path] = string(b)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func TestRemoteCustodyCLINetworkPersistsEvidenceAndIndependentCompletion(t *testing.T) {
	f := newRemoteCLIFixture(t)
	b := startRemoteCLIControl(t, f.args("serve", "control"))
	token := b.review(t)
	b.send(t, "serve "+token)
	ready := b.next(t, "remote_custody_serving")
	a := startRemoteCLIControl(t, append(f.args("audit", "control"), "--peer", ready["listen"]))
	for _, action := range []struct{ command, prefix string }{{"prepare", "remote_custody_prepared"}, {"begin", "remote_custody_begun"}, {"execute", "remote_custody_executed"}, {"seal", "remote_custody_metadata"}, {"capture", "remote_custody_captured"}} {
		token := a.review(t)
		a.send(t, action.command+" "+token)
		a.next(t, action.prefix)
	}
	a.close(t)
	// Lost metadata output can be recovered after Drain is already confirmed.
	drainBytes, err := os.ReadFile(f.drain)
	if err != nil {
		t.Fatal(err)
	}
	response, err := remotewire.DecodeResponse(drainBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, drainID, err := store.RemoteCustodyDrainArtifact(f.scope, response)
	if err != nil {
		t.Fatal(err)
	}
	termBytes, err := os.ReadFile(f.terminal)
	if err != nil {
		t.Fatal(err)
	}
	term, err := store.DecodeRemoteCustodyTerminal(termBytes)
	if err != nil {
		t.Fatal(err)
	}
	termID, _ := term.ID()
	for _, ticket := range []custodyauthority.Entry{f.audit, f.scope.Worker.Plan.Admission} {
		owner, err := store.OpenCoordinator(f.authority, f.pins, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID)
		if err != nil {
			t.Fatal(err)
		}
		current, err := owner.Snapshot()
		_ = owner.Close()
		if err != nil {
			t.Fatal(err)
		}
		entry, path := remoteOfflineCompleteEntry(t, f, ticket, termID, current.Confirmed)
		eid, _ := entry.ID()
		args := append(f.args("audit", "control"), "--peer", ready["listen"], "--drain-id", drainID.String(), "--terminal-id", termID.String(), "--complete-entry", path, "--complete-entry-id", eid.String())
		a = startRemoteCLIControl(t, args)
		token := a.review(t)
		a.send(t, "reconcile "+token)
		a.next(t, "remote_custody_metadata")
		token = a.review(t)
		a.send(t, "apply-complete "+token)
		a.next(t, "remote_custody_completed")
		a.close(t)
	}
	b.close(t)
}

func TestRemoteCustodyCLIRejectsWrongPinsBeforeKeys(t *testing.T) {
	f := newRemoteCLIFixture(t)
	args := f.args("serve", "")
	for i := range args {
		if args[i] == "--plan-id" {
			args[i+1] = pruneCLIHash(250).String()
		}
		if args[i] == "--control-key" {
			args[i+1] = filepath.Join(t.TempDir(), "missing.seed")
		}
	}
	_, err := loadRemoteCustodyOptions(t.Context(), args)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("public scope was not checked first", err)
	}
}
