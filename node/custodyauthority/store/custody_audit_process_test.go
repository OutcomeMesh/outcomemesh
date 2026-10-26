//go:build integration

package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type managedAuditProcessInput struct {
	Authority      string
	Pins           string
	Assignment     custodyauthority.Assignment
	AssignmentID   types.Hash
	IntentID       types.Hash
	Admission      custodyauthority.Entry
	IntentPath     string
	JournalPath    string
	ArtifactsPath  string
	Manifest       workarchive.Manifest
	InitialReceipt workarchive.ReplicaReceipt
	Policy         workarchive.CustodyPolicy
	Limits         workarchive.CustodyJournalLimits
	Key            ed25519.PrivateKey
	Now            uint64
	Timeout        time.Duration
	Record         []byte
}

func managedAuditProcessFixture(t testing.TB, f *managedAuditFixture) managedAuditProcessInput {
	t.Helper()
	c := f.config
	record, err := f.answer(t).CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return managedAuditProcessInput{Authority: f.serve.archive.f.authorityPath, Pins: f.serve.archive.f.pinsPath, Assignment: f.serve.archive.policy.Assignments[0],
		AssignmentID: c.AssignmentID, IntentID: c.IntentID, Admission: c.Admission, IntentPath: c.IntentPath, JournalPath: c.JournalPath, ArtifactsPath: c.ArtifactsPath,
		Manifest: c.Manifest, InitialReceipt: c.InitialReceipt, Policy: c.CustodyPolicy, Limits: c.JournalLimits, Key: c.AuditorPrivateKey, Now: c.SessionConfig.Now(), Timeout: c.SessionConfig.RequestTimeout, Record: record}
}

func (c managedAuditProcessInput) open(t testing.TB) (*Coordinator, *ManagedCustodyAuditSession) {
	t.Helper()
	owner, err := OpenCoordinator(c.Authority, c.Pins, c.Assignment, c.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	session, err := NewManagedCustodyAuditSession(t.Context(), owner, ManagedCustodyAuditConfig{AssignmentID: c.AssignmentID, IntentID: c.IntentID, Admission: c.Admission,
		IntentPath: c.IntentPath, JournalPath: c.JournalPath, ArtifactsPath: c.ArtifactsPath, Manifest: c.Manifest, InitialReceipt: c.InitialReceipt, CustodyPolicy: c.Policy,
		JournalLimits: c.Limits, AuditorPrivateKey: c.Key, SessionConfig: workarchive.CustodySessionConfig{Now: func() uint64 { return c.Now }, RequestTimeout: c.Timeout}})
	if err != nil {
		t.Fatal(err)
	}
	return owner, session
}

func (c managedAuditProcessInput) response(t testing.TB) *managedAuditResponseStream {
	t.Helper()
	record, err := workarchive.DecodeCustodyRecord(c.Record)
	if err != nil {
		t.Fatal(err)
	}
	return newManagedAuditResponseStream(t, record)
}

func TestManagedCustodyAuditProcessRecovery(t *testing.T) {
	for _, stage := range []string{"constructed", "prepared", "before-append", "missing-outputs", "returned"} {
		t.Run(stage, func(t *testing.T) {
			f := newManagedAuditFixture(t)
			input := managedAuditProcessFixture(t, f)
			coordinator := f.serve.archive.f.coordinator
			before := testCoordination(t, coordinator)
			if err := coordinator.Close(); err != nil {
				t.Fatal(err)
			}
			fixturePath := filepath.Join(t.TempDir(), "fixture.json")
			b, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixturePath, b, 0o600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "ready")
			command := exec.Command(os.Args[0], "-test.run=^TestManagedCustodyAuditCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "OUTCOMEMESH_MANAGED_AUDIT_FIXTURE="+fixturePath, "OUTCOMEMESH_MANAGED_AUDIT_STAGE="+stage, "OUTCOMEMESH_MANAGED_AUDIT_MARKER="+marker)
			var output bytes.Buffer
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan struct{})
			var exitErr error
			go func() { exitErr = command.Wait(); close(exited) }()
			t.Cleanup(func() {
				select {
				case <-exited:
				default:
					_ = command.Process.Kill()
					<-exited
				}
			})
			deadline := time.NewTimer(15 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
			var checkpoint []byte
		waiting:
			for {
				if b, err := os.ReadFile(marker); err == nil && (string(b) == "ready" || string(b) == "permission-not-enforced") {
					checkpoint = b
					break waiting
				}
				select {
				case <-exited:
					t.Fatal("audit helper exited before checkpoint", exitErr, output.String())
				case <-deadline.C:
					_ = command.Process.Kill()
					<-exited
					t.Fatal("audit checkpoint not reached", output.String())
				case <-tick.C:
				}
			}
			if other, err := OpenCoordinator(input.Authority, input.Pins, input.Assignment, input.AssignmentID); !errors.Is(err, ErrBusy) {
				if other != nil {
					_ = other.Close()
				}
				t.Fatal("helper released original coordinator", err)
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-exited
			if exitErr == nil {
				t.Fatal("helper was not killed")
			}
			if stage == "missing-outputs" {
				if err := os.Chmod(filepath.Join(input.ArtifactsPath, "cycle-00000000000000000001"), 0o700); err != nil {
					t.Fatal(err)
				}
				if string(checkpoint) == "permission-not-enforced" {
					t.Skip("directory publication denial is not enforced for this test user/filesystem")
				}
			}
			wantSequence := uint64(0)
			if stage == "missing-outputs" || stage == "returned" {
				wantSequence = 1
			}
			for range 2 {
				owner, session := input.open(t)
				if !reflect.DeepEqual(before, testCoordination(t, owner)) {
					t.Fatal("restart changed admission/completion history")
				}
				journal, state, err := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), input.JournalPath, input.Manifest, input.InitialReceipt, input.Policy, input.Limits)
				if err != nil || state.Sequence != wantSequence {
					t.Fatal("lost or fabricated commit", state.Sequence, err)
				}
				challenge, err := session.PrepareChallenge(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				expected, _ := f.serve.challenge.CanonicalBytes()
				actual, _ := challenge.CanonicalBytes()
				if !bytes.Equal(expected, actual) {
					t.Fatal("restart generated another challenge")
				}
				var result workarchive.CustodyAuditResult
				if wantSequence == 0 {
					if _, err := session.Recover(t.Context()); err == nil {
						t.Fatal("absent journal result promoted as recovery")
					}
					result, err = session.Audit(t.Context(), f.intent.ReplicaPeerID, input.response(t))
				} else {
					result, err = session.Recover(t.Context())
				}
				if err != nil || result.JournalSequence != 1 {
					t.Fatal("exact audit recovery failed", err)
				}
				encoded, err := result.Record.CanonicalBytes()
				if err != nil || !bytes.Equal(encoded, input.Record) {
					t.Fatal("recovery changed signed result", err)
				}
				after, err := journal.State()
				if err != nil || after.Sequence != 1 {
					t.Fatal(after, err)
				}
				if state.Sequence != 0 && state != after {
					t.Fatal("recovery changed retained journal head")
				}
				wantSequence = 1
				for _, name := range []string{"challenge.omcc", "record.omcr", "receipt.omrr"} {
					if _, err := os.Stat(filepath.Join(input.ArtifactsPath, "cycle-00000000000000000001", name)); err != nil {
						t.Fatal("missing recovered artifact", name, err)
					}
				}
				if !reflect.DeepEqual(before, testCoordination(t, owner)) {
					t.Fatal("audit implicitly completed its ticket")
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestManagedCustodyAuditCrashHelper(t *testing.T) {
	fixture := os.Getenv("OUTCOMEMESH_MANAGED_AUDIT_FIXTURE")
	if fixture == "" {
		t.Skip("subprocess helper")
	}
	b, err := readRegular(fixture, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	var input managedAuditProcessInput
	if err := json.Unmarshal(b, &input); err != nil {
		t.Fatal(err)
	}
	_, session := input.open(t)
	stage := os.Getenv("OUTCOMEMESH_MANAGED_AUDIT_STAGE")
	marker := os.Getenv("OUTCOMEMESH_MANAGED_AUDIT_MARKER")
	pause := func(value string) {
		if err := os.WriteFile(marker, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	if stage == "constructed" {
		pause("ready")
	}
	if _, err := session.PrepareChallenge(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stage == "prepared" {
		pause("ready")
	}
	stream := input.response(t)
	if stage == "before-append" {
		stream.closeEntered = make(chan struct{})
		release := make(chan struct{})
		stream.releaseClose = release
		go func() { <-stream.closeEntered; pause("ready") }()
	}
	if stage == "missing-outputs" {
		dir := filepath.Join(input.ArtifactsPath, "cycle-00000000000000000001")
		if err := os.Chmod(dir, 0o500); err != nil {
			pause("permission-not-enforced")
		}
		if _, err := session.Audit(context.Background(), session.cycle.Intent().ReplicaPeerID, stream); err == nil {
			pause("permission-not-enforced")
		}
		journal, state, err := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), input.JournalPath, input.Manifest, input.InitialReceipt, input.Policy, input.Limits)
		if err != nil || journal == nil || state.Sequence != 1 {
			t.Fatal("output failure did not follow journal commit", state.Sequence, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "record.omcr")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("record output unexpectedly published", err)
		}
		pause("ready")
	}
	result, err := session.Audit(t.Context(), session.cycle.Intent().ReplicaPeerID, stream)
	if err != nil {
		t.Fatal(err)
	}
	if stage == "returned" && result.JournalSequence == 1 {
		pause("ready")
	}
	t.Fatal("helper missed checkpoint", stage)
}
