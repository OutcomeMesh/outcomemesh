package custodycutover

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
)

func TestRemoteCutoverPreparationCrashRecoveryNeverChoosesReplacement(t *testing.T) {
	proposal, pins := proposalFixture(t, evidenceFixture(t, false))
	raw, _ := proposal.CanonicalBytes()
	for _, stage := range []string{"placement-before-sync", "placement-durable", "proposal-before-sync", "proposal-durable", "ready-before-sync", "ready-durable"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(originalTemp(t), "preparation")
			err := createPreparation(path, proposal, pins, func(at string) error {
				if at == stage {
					return errors.New("injected write failure")
				}
				return nil
			})
			if !errors.Is(err, ErrUncertain) {
				t.Fatal("lost uncertainty", err)
			}
			if err := CreatePreparation(path, proposal, pins); err == nil {
				t.Fatal("recreated original journal")
			}
			p, err := RecoverPreparation(path, pins)
			if stage == "placement-before-sync" || stage == "placement-durable" {
				if err == nil {
					p.Close()
					t.Fatal("reconstructed missing proposal")
				}
				return
			}
			if err != nil {
				t.Fatal("exact original recovery", err)
			}
			defer p.Close()
			got, err := p.Read(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := got.CanonicalBytes()
			if !bytes.Equal(raw, encoded) {
				t.Fatal("recovery changed signed proposal")
			}
			if _, err := OpenPreparation(path, pins); err == nil {
				t.Fatal("two original handles")
			}
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
			other := pins
			other.ProposalID = f.Hash("alternate proposal")
			if q, err := RecoverPreparation(path, other); err == nil {
				q.Close()
				t.Fatal("wrong proposal pin selected")
			}
			p, err = OpenPreparation(path, pins)
			if err != nil {
				t.Fatal("cold reopen", err)
			}
			if err = p.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRemoteCutoverPreparationCopiesMovesAndTamperingRefused(t *testing.T) {
	proposal, pins := proposalFixture(t, evidenceFixture(t, false))
	for _, kind := range []string{"copy", "move", "proposal", "ready", "placement", "extra", "mode", "lock", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(originalTemp(t), "preparation")
			if err := CreatePreparation(path, proposal, pins); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "copy":
				dest := filepath.Join(originalTemp(t), "copy")
				if err := os.CopyFS(dest, os.DirFS(path)); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(dest, 0700); err != nil {
					t.Fatal(err)
				}
				path = dest
			case "move":
				dest := filepath.Join(filepath.Dir(path), "moved")
				if err := os.Rename(path, dest); err != nil {
					t.Fatal(err)
				}
				path = dest
			case "extra":
				if err := os.WriteFile(filepath.Join(path, "unexpected"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(filepath.Join(path, "proposal"), 0644); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Remove(filepath.Join(path, "owner.lock")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "owner.lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				dest := filepath.Join(filepath.Dir(path), "alias")
				if err := os.Symlink(path, dest); err != nil {
					t.Fatal(err)
				}
				path = dest
			default:
				if err := os.WriteFile(filepath.Join(path, kind), []byte("substitution"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, open := range []func(string, Pins) (*Preparation, error){OpenPreparation, RecoverPreparation} {
				if p, err := open(path, pins); err == nil {
					p.Close()
					t.Fatal("changed journal accepted", kind)
				}
			}
		})
	}
}
func TestRemoteCutoverPreparationLiveMutationPoisonsAndReadsDetached(t *testing.T) {
	proposal, pins := proposalFixture(t, evidenceFixture(t, false))
	path := filepath.Join(originalTemp(t), "preparation")
	if err := CreatePreparation(path, proposal, pins); err != nil {
		t.Fatal(err)
	}
	p, err := OpenPreparation(path, pins)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 2 {
				got, err := p.Read(t.Context())
				if err != nil {
					t.Error(err)
					return
				}
				got.Evidence.History[0].Signature[0] ^= 1
				got.Successor.Witnesses[0][0] ^= 1
			}
		})
	}
	wg.Wait()
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.Read(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(path, "proposal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "proposal"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Read(t.Context()); err == nil {
		t.Fatal("corrupt retained file read")
	}
	if err := os.WriteFile(filepath.Join(path, "proposal"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Read(t.Context()); err == nil {
		t.Fatal("failed handle recovered implicitly")
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	p, err = OpenPreparation(path, pins)
	if err != nil {
		t.Fatal("explicit exact reopen", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
}

func originalTemp(t testing.TB) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
