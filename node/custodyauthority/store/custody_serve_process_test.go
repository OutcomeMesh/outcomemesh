//go:build integration

package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
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

// Disposable subprocess fixture metadata, not an operator or protocol format.
type managedServeProcessConfig struct {
	Authority, Pins, Journal, Objects string
	Assignment                        custodyauthority.Assignment
	Admission                         custodyauthority.Entry
	Challenge                         workarchive.CustodyChallenge
	Peer                              types.Hash
	Manifest                          workarchive.Manifest
	Initial                           workarchive.ReplicaReceipt
	Policy                            workarchive.CustodyPolicy
	Limits                            workarchive.CustodyJournalLimits
	Key                               []byte // deterministic test key only
	Now                               uint64
	Timeout                           time.Duration
}

func managedServeProcessInputs(f *managedServeFixture) managedServeProcessConfig {
	c := f.config
	return managedServeProcessConfig{Authority: f.archive.f.authorityPath, Pins: f.archive.f.pinsPath, Journal: c.JournalPath, Objects: c.Objects.Directory(),
		Assignment: f.archive.policy.Assignments[0], Admission: c.Admission, Challenge: f.challenge, Peer: c.AuditorPeerID,
		Manifest: c.Manifest, Initial: c.InitialReceipt, Policy: c.CustodyPolicy, Limits: c.JournalLimits, Key: c.ReplicaPrivateKey, Now: f.now, Timeout: c.SessionConfig.RequestTimeout}
}

func (c managedServeProcessConfig) open(t testing.TB) (*Coordinator, *ManagedCustodyServeSession) {
	t.Helper()
	id, _ := c.Assignment.ID()
	owner, err := OpenCoordinator(c.Authority, c.Pins, c.Assignment, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	objects, err := workarchive.OpenObjectStore(c.Objects, workarchive.DefaultObjectStorePolicy())
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewManagedCustodyServeSession(t.Context(), owner, ManagedCustodyServeConfig{AssignmentID: id, Admission: c.Admission, ChallengeID: c.Admission.Command.OperationID,
		AuditorPeerID: c.Peer, JournalPath: c.Journal, Manifest: c.Manifest, InitialReceipt: c.Initial, CustodyPolicy: c.Policy, JournalLimits: c.Limits,
		ReplicaPrivateKey: c.Key, SessionConfig: workarchive.CustodySessionConfig{RequestTimeout: c.Timeout, Now: func() uint64 { return c.Now }}, Objects: objects})
	if err != nil {
		t.Fatal(err)
	}
	return owner, session
}

type managedServeProcessStream struct {
	input  *bytes.Reader
	output bytes.Buffer
	first  bool
	reach  func(string)
}

func (s *managedServeProcessStream) Read(p []byte) (int, error) {
	if s.input.Len() != 0 {
		return s.input.Read(p)
	}
	if s.reach != nil {
		s.reach("awaiting-eof")
	}
	return 0, io.EOF
}
func (s *managedServeProcessStream) Write(p []byte) (int, error) {
	if !s.first {
		s.first = true
		if s.reach != nil {
			s.reach("before-first-write")
		}
	}
	return s.output.Write(p)
}
func (s *managedServeProcessStream) Close() error {
	if s.reach != nil {
		s.reach("before-close")
	}
	return nil
}
func (s *managedServeProcessStream) SetDeadline(time.Time) error { return nil }

func managedServeChallengeStream(t testing.TB, c managedServeProcessConfig) *managedServeProcessStream {
	t.Helper()
	encoded, err := c.Challenge.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	framed := binary.BigEndian.AppendUint32(nil, uint32(len(encoded)))
	return &managedServeProcessStream{input: bytes.NewReader(append(framed, encoded...))}
}

func TestManagedCustodyServeProcessRecovery(t *testing.T) {
	for _, stage := range []string{"constructed", "before-first-write", "awaiting-eof", "before-close", "returned"} {
		t.Run(stage, func(t *testing.T) {
			f := newManagedServeFixture(t)
			config := managedServeProcessInputs(f)
			before := testCoordination(t, f.archive.f.coordinator)
			if err := f.archive.f.coordinator.Close(); err != nil {
				t.Fatal(err)
			}
			file, marker := filepath.Join(t.TempDir(), "fixture.json"), filepath.Join(t.TempDir(), "reached")
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, file, encoded)
			command := exec.Command(os.Args[0], "-test.run=^TestManagedCustodyServeCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(), "OUTCOMEMESH_MANAGED_SERVE_FIXTURE="+file, "OUTCOMEMESH_MANAGED_SERVE_STAGE="+stage, "OUTCOMEMESH_MANAGED_SERVE_MARKER="+marker)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var exitErr error
			go func() { exitErr = command.Wait(); close(done) }()
			t.Cleanup(func() { _ = command.Process.Kill(); <-done })
			deadline := time.NewTimer(15 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
		wait:
			for {
				if _, err := os.Stat(marker); err == nil {
					break wait
				}
				select {
				case <-done:
					t.Fatal("managed child exited before barrier", exitErr, output.String())
				case <-deadline.C:
					_ = command.Process.Kill()
					<-done
					t.Fatal("managed barrier not reached", output.String())
				case <-tick.C:
				}
			}
			id, _ := config.Assignment.ID()
			if other, err := OpenCoordinator(config.Authority, config.Pins, config.Assignment, id); !errors.Is(err, ErrBusy) {
				if other != nil {
					_ = other.Close()
				}
				t.Fatal("child released original authority", err)
			}
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			<-done
			if exitErr == nil {
				t.Fatal("child was not killed")
			}
			wantSequence := uint64(1)
			if stage == "constructed" {
				wantSequence = 0
			}
			var firstRecoveredWire []byte
			for range 2 {
				owner, session := config.open(t)
				if !reflect.DeepEqual(before, testCoordination(t, owner)) {
					t.Fatal("reopen admitted/completed another operation")
				}
				journal, state, err := workarchive.OpenExistingCustodyJournalWithLimits(t.Context(), config.Journal, config.Manifest, config.Initial, config.Policy, config.Limits)
				if err != nil || state.Sequence != wantSequence {
					t.Fatal("reopen lost or advanced journal", state.Sequence, err)
				}
				stream := managedServeChallengeStream(t, config)
				report, err := session.Serve(t.Context(), config.Peer, stream)
				if err != nil || report.JournalSequence != 1 {
					t.Fatal("exact recovered response failed", err)
				}
				after, err := journal.State()
				if err != nil || after.Sequence != 1 {
					t.Fatal("recovered exchange did not retain its first response", after.Sequence, err)
				}
				if state.Sequence != 0 && !reflect.DeepEqual(state, after) {
					t.Fatal("recovered delivery changed retained evidence")
				}
				// Construction killed before any response must still permit the
				// original admitted exchange; the second reopen replays that result.
				wantSequence = 1
				head, exists, err := journal.Head()
				if err != nil || !exists {
					t.Fatal(err)
				}
				recovered := f.verifiedRecord(t, stream.output.Bytes())
				persistedBytes, err := head.Record.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				recoveredBytes, err := recovered.CanonicalBytes()
				if err != nil || !bytes.Equal(persistedBytes, recoveredBytes) || after.CurrentReceipt != recovered.RenewedReceipt {
					t.Fatal("verified response differs from the persisted record", err)
				}
				var expected []byte
				for _, body := range []interface{ CanonicalBytes() ([]byte, error) }{head.Record.Batch, head.Record.Proof, head.Record.RenewedReceipt} {
					b, err := body.CanonicalBytes()
					if err != nil {
						t.Fatal(err)
					}
					expected = binary.BigEndian.AppendUint32(expected, uint32(len(b)))
					expected = append(expected, b...)
				}
				if !bytes.Equal(expected, stream.output.Bytes()) {
					t.Fatal("retry changed the committed wire response")
				}
				if firstRecoveredWire == nil {
					firstRecoveredWire = bytes.Clone(stream.output.Bytes())
				} else if !bytes.Equal(firstRecoveredWire, stream.output.Bytes()) {
					t.Fatal("second reopen changed the exact recovered wire response")
				}
				if !reflect.DeepEqual(before, testCoordination(t, owner)) {
					t.Fatal("delivery automatically completed the ticket")
				}
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestManagedCustodyServeCrashHelper(t *testing.T) {
	file := os.Getenv("OUTCOMEMESH_MANAGED_SERVE_FIXTURE")
	if file == "" {
		t.Skip("subprocess helper")
	}
	encoded, err := readRegular(file, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var c managedServeProcessConfig
	if err := json.Unmarshal(encoded, &c); err != nil {
		t.Fatal(err)
	}
	_, session := c.open(t)
	reach := func(stage string) {
		if stage == os.Getenv("OUTCOMEMESH_MANAGED_SERVE_STAGE") {
			writeTestFile(t, os.Getenv("OUTCOMEMESH_MANAGED_SERVE_MARKER"), nil)
			select {}
		}
	}
	reach("constructed")
	stream := managedServeChallengeStream(t, c)
	stream.reach = reach
	if _, err := session.Serve(t.Context(), c.Peer, stream); err != nil {
		t.Fatal(err)
	}
	reach("returned")
	t.Fatal("child missed selected barrier")
}
