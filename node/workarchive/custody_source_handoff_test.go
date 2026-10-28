package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func sourceHandoffFixture(t testing.TB) (*CustodyJournal, CustodySourceHandoff, []byte) {
	t.Helper()
	f := newCustodyRecordFixture(t)
	j, _, e := OpenOrCreateCustodyJournal(filepath.Join(t.TempDir(), "source"), f.manifest, f.receipt, f.policy)
	if e != nil {
		t.Fatal(e)
	}
	entry, _, e := j.Append(f.record)
	if e != nil {
		t.Fatal(e)
	}
	head, _ := entry.ID()
	rid, _ := f.record.RenewedReceipt.ID()
	id := types.DomainHash("test/source/handoff", []byte("selected"))
	proof := []byte("bounded full proof checked by the higher-level selection verifier")
	h := CustodySourceHandoff{Version: 1, TargetVersion: 5, Role: 1, RegistryID: id, RegistryDescriptorID: id, GenesisID: id, GenesisDescriptorID: id, EnrollmentID: id, ProposalID: id, PlacementID: id, ProofID: CustodySourceHandoffProofID(proof), SourceSequence: 1, SourceHeadID: head, ReceiptID: rid, RetainUntil: f.record.RenewedReceipt.RetainUntil, SpentOperations: 2}
	return j, h, proof
}
func openSourceTransfer(t testing.TB, j *CustodyJournal, h CustodySourceHandoff) *CustodyJournalDecision {
	t.Helper()
	d, e := OpenCustodySourceHandoff(t.Context(), j.path, j.manifest, j.header.InitialReceipt, j.policy, h)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestSourceHandoffSealColdRetryAndNoLegacyAccess(t *testing.T) {
	j, h, proof := sourceHandoffFixture(t)
	d := openSourceTransfer(t, j, h)
	if _, e := d.Rotate(); !errors.Is(e, ErrCustodySourceHandedOff) {
		t.Fatal("transfer opened live rotation", e)
	}
	if _, e := d.InspectSourceHandoff(); e == nil {
		t.Fatal("uncommitted inspected")
	}
	changed, e := d.SealSourceHandoff(t.Context(), proof)
	if e != nil || !changed {
		t.Fatal(changed, e)
	}
	got, e := d.InspectSourceHandoff()
	if e != nil || got != h {
		t.Fatal(got, e)
	}
	d.Close()
	for name, call := range map[string]func() error{
		"state": func() error { _, e := j.State(); return e }, "head": func() error { _, _, e := j.Head(); return e }, "usage": func() error { _, e := j.Usage(); return e }, "append": func() error { _, _, e := j.Append(CustodyRecord{}); return e }, "rotate": func() error { _, e := j.Rotate(); return e }, "decision": func() error {
			d, e := j.AcquireDecision()
			if d != nil {
				d.Close()
			}
			return e
		}, "reopen": func() error {
			_, _, e := OpenExistingCustodyJournalWithLimits(t.Context(), j.path, j.manifest, j.header.InitialReceipt, j.policy, j.limits)
			return e
		}, "create-or-open": func() error {
			_, _, e := OpenOrCreateCustodyJournal(j.path, j.manifest, j.header.InitialReceipt, j.policy)
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			if e := call(); !errors.Is(e, ErrCustodySourceHandedOff) {
				t.Fatal("legacy access", e)
			}
		})
	}
	d = openSourceTransfer(t, j, h)
	defer d.Close()
	changed, e = d.SealSourceHandoff(t.Context(), proof)
	if e != nil || changed {
		t.Fatal("cold retry", changed, e)
	}
	state, e := d.State()
	if e != nil || state.Sequence != h.SourceSequence || state.HeadEntryID != h.SourceHeadID {
		t.Fatal("source advanced", state, e)
	}
}
func TestSourceHandoffPublicationFailuresRequireExactColdRecovery(t *testing.T) {
	for _, name := range []string{custodySourceHandoffName, custodySourceHandoffProofName} {
		for _, stage := range []string{"before-link", "after-link", "durable"} {
			t.Run(name+"-"+stage, func(t *testing.T) {
				j, h, proof := sourceHandoffFixture(t)
				d := openSourceTransfer(t, j, h)
				injected := errors.New("publication failure")
				_, e := d.sealSourceHandoff(t.Context(), proof, func(at string) error {
					if at == name+"-"+stage {
						return injected
					}
					return nil
				})
				if !errors.Is(e, injected) {
					t.Fatal(e)
				}
				if e := d.CheckAccess(); e == nil {
					t.Fatal("uncertain handle usable")
				}
				d.Close()
				if name == custodySourceHandoffName && stage == "before-link" {
					if _, e := j.State(); e != nil {
						t.Fatal("no marker was committed", e)
					}
				} else {
					if _, e := j.State(); !errors.Is(e, ErrCustodySourceHandedOff) {
						t.Fatal("partial seal left active", e)
					}
				}
				bad := h
				bad.GenesisID[0] ^= 1
				if name != custodySourceHandoffName || stage != "before-link" {
					if wrong, e := OpenCustodySourceHandoff(t.Context(), j.path, j.manifest, j.header.InitialReceipt, j.policy, bad); e == nil {
						wrong.Close()
						t.Fatal("replacement recovery")
					}
				}
				d = openSourceTransfer(t, j, h)
				defer d.Close()
				if _, e := d.SealSourceHandoff(t.Context(), proof); e != nil {
					t.Fatal(e)
				}
				if got, e := d.InspectSourceHandoff(); e != nil || got != h {
					t.Fatal(e)
				}
			})
		}
	}
}
func TestSourceHandoffHeldDecisionRechecksAndPoisonsAfterSubstitution(t *testing.T) {
	for _, kind := range []string{"marker", "proof", "lock", "root"} {
		t.Run(kind, func(t *testing.T) {
			j, _, _ := sourceHandoffFixture(t)
			d, e := j.AcquireDecision()
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			switch kind {
			case "marker":
				os.WriteFile(filepath.Join(j.path, custodySourceHandoffName), []byte("partial"), 0600)
			case "proof":
				os.Mkdir(filepath.Join(j.path, custodySourceHandoffProofName), 0700)
			case "lock":
				os.Remove(filepath.Join(j.path, custodyJournalLockName))
				os.WriteFile(filepath.Join(j.path, custodyJournalLockName), nil, 0600)
			case "root":
				os.Rename(j.path, j.path+"-old")
				os.Mkdir(j.path, 0700)
			}
			if e := d.CheckAccess(); e == nil {
				t.Fatal("substitution accepted")
			}
			if _, e := d.State(); e == nil {
				t.Fatal("state bypass")
			}
			if _, _, e := d.Head(); e == nil {
				t.Fatal("head bypass")
			}
			if _, e := d.Usage(); e == nil {
				t.Fatal("usage bypass")
			}
			if _, _, e := d.Append(CustodyRecord{}); e == nil {
				t.Fatal("append bypass")
			}
			if _, e := d.Rotate(); e == nil {
				t.Fatal("rotate bypass")
			}
			if kind == "marker" {
				os.Remove(filepath.Join(j.path, custodySourceHandoffName))
				if e := d.CheckAccess(); e == nil {
					t.Fatal("poisoned handle revived")
				}
			}
		})
	}
}
func TestSourceHandoffRefusesWrongProofPredecessorAndCorruption(t *testing.T) {
	for _, kind := range []string{"proof-id", "head", "receipt", "sequence", "retention", "proof-only", "corrupt-marker", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			j, h, proof := sourceHandoffFixture(t)
			switch kind {
			case "proof-id":
				proof = append(proof, 1)
			case "head":
				h.SourceHeadID[0] ^= 1
			case "receipt":
				h.ReceiptID[0] ^= 1
			case "sequence":
				h.SourceSequence++
			case "retention":
				h.RetainUntil--
			case "proof-only":
				os.WriteFile(filepath.Join(j.path, custodySourceHandoffProofName), proof, 0600)
			case "corrupt-marker":
				os.WriteFile(filepath.Join(j.path, custodySourceHandoffName), []byte("bad"), 0600)
			case "symlink":
				os.Symlink("/missing", filepath.Join(j.path, custodySourceHandoffName))
			}
			d, e := OpenCustodySourceHandoff(t.Context(), j.path, j.manifest, j.header.InitialReceipt, j.policy, h)
			if e == nil {
				defer d.Close()
				if _, e = d.SealSourceHandoff(t.Context(), proof); e == nil {
					t.Fatal("invalid handoff accepted")
				}
			}
		})
	}
}
func TestSourceHandoffWaitsForWholeSourceActionAndHonorsCancellation(t *testing.T) {
	j, h, _ := sourceHandoffFixture(t)
	d, e := j.AcquireDecision()
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if other, e := OpenCustodySourceHandoff(ctx, j.path, j.manifest, j.header.InitialReceipt, j.policy, h); !errors.Is(e, context.DeadlineExceeded) {
		if other != nil {
			other.Close()
		}
		t.Fatal(e)
	}
	if _, e := os.Lstat(filepath.Join(j.path, custodySourceHandoffName)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("cancel wrote marker", e)
	}
}
func TestSourceHandoffCanonicalVector(t *testing.T) {
	var h CustodySourceHandoff // Pin the envelope independently of source randomness.
	id := types.Hash{1}
	h = CustodySourceHandoff{Version: 1, TargetVersion: 5, Role: 2, RegistryID: id, RegistryDescriptorID: id, GenesisID: id, GenesisDescriptorID: id, EnrollmentID: id, ProposalID: id, PlacementID: id, ProofID: id, SourceHeadID: id, ReceiptID: id, SourceSequence: 9, RetainUntil: 1234, SpentOperations: 6}
	raw, e := h.CanonicalBytes()
	if e != nil || len(raw) != 353 {
		t.Fatal(len(raw), e)
	}
	got, e := DecodeCustodySourceHandoff(raw)
	if e != nil || got != h {
		t.Fatal(e)
	}
	hash, _ := h.ID()
	if hash.String() != "8a948c573e28f6b19a6dd1fca6480f0ecf3161b9b63766ab19184864becffaa2" {
		t.Fatal("vector changed", hash)
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), 0), raw[:len(raw)-1], append([]byte("OMCSHOF2"), raw[8:]...)} {
		if _, e := DecodeCustodySourceHandoff(bad); e == nil {
			t.Fatal("noncanonical")
		}
	}
}
func FuzzDecodeCustodySourceHandoff(f *testing.F) {
	id := types.Hash{1}
	h := CustodySourceHandoff{Version: 1, TargetVersion: 5, Role: 1, RegistryID: id, RegistryDescriptorID: id, GenesisID: id, GenesisDescriptorID: id, EnrollmentID: id, ProposalID: id, PlacementID: id, ProofID: id, ReceiptID: id, RetainUntil: 1}
	raw, _ := h.CanonicalBytes()
	f.Add(raw)
	f.Add([]byte("OMCSHOF1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, e := DecodeCustodySourceHandoff(b)
		if e == nil {
			again, e := h.CanonicalBytes()
			if e != nil || !bytes.Equal(again, b) {
				t.Fatal("noncanonical")
			}
		}
	})
}
func TestSourceHandoffCopiesProofBeforePublicationCallbacks(t *testing.T) {
	j, h, proof := sourceHandoffFixture(t)
	original := append([]byte(nil), proof...)
	d := openSourceTransfer(t, j, h)
	defer d.Close()
	_, e := d.sealSourceHandoff(t.Context(), proof, func(at string) error {
		if at == custodySourceHandoffName+"-durable" {
			proof[0] ^= 1
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	got, e := readRegularArchiveFile(filepath.Join(j.path, custodySourceHandoffProofName), len(original))
	if e != nil || !bytes.Equal(original, got) {
		t.Fatal("caller mutation changed retained proof", e)
	}
}

func TestSourceHandoffReservesCompleteEvidenceBeforeFirstSeal(t *testing.T) {
	for _, kind := range []string{"bytes", "paths"} {
		t.Run(kind, func(t *testing.T) {
			j, h, proof := sourceHandoffFixture(t)
			d := openSourceTransfer(t, j, h)
			defer d.Close()
			usage, e := d.Usage()
			if e != nil {
				t.Fatal(e)
			}
			ceiling := CustodyJournalLimits{MaximumBytes: MaximumCustodyJournalBytes, MaximumPaths: MaximumCustodyJournalPaths}
			if kind == "bytes" {
				ceiling.MaximumBytes = usage.Bytes + CustodySourceHandoffBytes + uint64(len(proof)) - 1
			} else {
				ceiling.MaximumPaths = usage.Paths + 1
			}
			if _, e := d.sealSourceHandoffWithLimits(t.Context(), proof, nil, ceiling); !errors.Is(e, ErrCustodyJournalBudget) {
				t.Fatal("capacity was not reserved", e)
			}
			for _, name := range []string{custodySourceHandoffName, custodySourceHandoffProofName} {
				if _, e := os.Lstat(filepath.Join(j.path, name)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("irreversible partial capacity failure", name, e)
				}
			}
			if e := d.CheckAccess(); e != nil {
				t.Fatal("preflight failure poisoned unchanged source", e)
			}
		})
	}
}
func TestSourceHandoffRefusesRetainedPendingJournalEvidence(t *testing.T) {
	j, h, proof := sourceHandoffFixture(t)
	path := filepath.Join(j.path, custodyJournalPendingName, ".outcomemesh-custody-journal-unresolved")
	if e := os.WriteFile(path, []byte("retained unresolved publication"), 0600); e != nil {
		t.Fatal(e)
	}
	// Ordinary replay deliberately preserves pending files. Handoff eligibility
	// has the stricter requirement that no such original attempt is unresolved.
	d := openSourceTransfer(t, j, h)
	defer d.Close()
	if _, e := d.SealSourceHandoff(t.Context(), proof); !errors.Is(e, ErrCustodySourceHandoff) {
		t.Fatal("pending source handed off", e)
	}
	if _, e := os.Lstat(filepath.Join(j.path, custodySourceHandoffName)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("sealed unresolved source", e)
	}
	if raw, e := os.ReadFile(path); e != nil || string(raw) != "retained unresolved publication" {
		t.Fatal("pending evidence changed", e)
	}
}
func TestSourceHandoffRefusesUndecidedOrphanBodies(t *testing.T) {
	j, h, proof := sourceHandoffFixture(t)
	entry, e := j.loadSequence(1)
	if e != nil {
		t.Fatal(e)
	}
	entry.Sequence = 2
	entry.PreviousEntryID = h.SourceHeadID
	raw, e := entry.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	id, _ := entry.ID()
	if e := j.publishBody(id, raw); e != nil {
		t.Fatal(e)
	}
	if state, e := j.State(); e != nil || state.Sequence != 1 {
		t.Fatal("ordinary replay must retain orphan evidence", e)
	}
	d := openSourceTransfer(t, j, h)
	defer d.Close()
	if _, e := d.SealSourceHandoff(t.Context(), proof); !errors.Is(e, ErrCustodySourceHandoff) {
		t.Fatal("undecided body handed off", e)
	}
	if _, e := os.Lstat(filepath.Join(j.path, custodySourceHandoffName)); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("sealed unresolved source", e)
	}
	if _, found, e := j.findBody(id); e != nil || !found {
		t.Fatal("orphan evidence lost", e)
	}
}
