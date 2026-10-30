package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

// PruneClaimCollector may contact only the independently configured witnesses.
// It signs the exact draft with the policy owner key and returns a quorum. It
// receives no session key, cannot substitute the candidate and grants no effect.
type PruneClaimCollector func(context.Context, custodyfence.Scope, custodyfence.Command) (custodyfence.Certificate, error)

func pruneRecordLimit(request PruneRequest) int {
	if request.FencePolicyID.IsZero() {
		return workchain.MaximumCanonicalPruneEffectBytes
	}
	return maximumPruneRecordBytes
}

func pruneFenceOperation(s PruneExecution) (workchain.CanonicalPruneOperation, error) {
	if s.Admission == nil {
		return workchain.CanonicalPruneOperation{}, prunefence.ErrFence
	}
	ticket, err := s.Admission.ID()
	if err != nil {
		return workchain.CanonicalPruneOperation{}, err
	}
	return workchain.CanonicalPruneOperation{AssignmentID: s.Request.AssignmentID, TicketID: ticket, StorageID: s.Request.StorageID, ScheduleID: s.Request.ScheduleID, Boundary: s.Request.Boundary}, nil
}
func verifyPruneFenceCandidate(s PruneExecution, c prunefence.Candidate) error {
	if _, err := c.CanonicalBytes(); err != nil {
		return err
	}
	op, err := pruneFenceOperation(s)
	if err != nil {
		return err
	}
	id, err := op.FenceOperationID()
	if err != nil {
		return err
	}
	policy, err := c.Policy.ID()
	if err != nil || s.Request.FencePolicyID.IsZero() || policy != s.Request.FencePolicyID || c.Policy.Owner != s.Request.ConsumerPublicKey || c.Policy.Controller != s.Admission.AuthorityPublicKey || c.Binding.RequestID != s.RequestID || c.Binding.AssignmentID != s.Request.AssignmentID || c.Binding.OperationID != id {
		return prunefence.ErrFence
	}
	return nil
}
func decodePruneFenceStart(s PruneExecution, raw []byte) (*prunefence.Claim, error) {
	if len(raw) < 10 || !bytes.HasPrefix(raw, []byte("OMCPSTRT\x00\x02")) {
		return nil, prunefence.ErrFence
	}
	claim, err := prunefence.DecodeClaim(raw[10:])
	if err != nil {
		return nil, err
	}
	if err := verifyPruneFenceCandidate(s, claim.Candidate); err != nil {
		return nil, err
	}
	return &claim, nil
}
func encodePruneFenceResult(effect workchain.CanonicalPruneEffect, proof prunefence.Result) ([]byte, error) {
	id, err := effect.ID()
	if err != nil || id != proof.EffectID {
		return nil, prunefence.ErrFence
	}
	a, _ := effect.CanonicalBytes()
	b, err := proof.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	e := codec.NewEncoder(maximumPruneRecordBytes)
	e.Fixed([]byte("OMCPFR00"))
	e.U16(0)
	e.BytesField(a)
	e.BytesField(b)
	return e.Bytes(), nil
}
func decodePruneFenceResult(s PruneExecution, raw []byte) (workchain.CanonicalPruneEffect, *prunefence.Result, error) {
	var zero workchain.CanonicalPruneEffect
	if s.FenceClaim == nil || len(raw) > maximumPruneRecordBytes {
		return zero, nil, prunefence.ErrFence
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	v, _ := d.U16()
	if string(m) != "OMCPFR00" || v != 0 {
		return zero, nil, prunefence.ErrFence
	}
	a, err := d.BytesField(workchain.MaximumCanonicalPruneEffectBytes)
	if err != nil {
		return zero, nil, err
	}
	effect, err := workchain.DecodeCanonicalPruneEffect(a)
	if err != nil {
		return zero, nil, err
	}
	b, err := d.BytesField(prunefence.MaximumResultBytes)
	if err != nil {
		return zero, nil, err
	}
	proof, err := prunefence.DecodeResult(b)
	if err != nil {
		return zero, nil, err
	}
	have, _ := proof.Claim.CanonicalBytes()
	want, _ := s.FenceClaim.CanonicalBytes()
	encoded, err := encodePruneFenceResult(effect, proof)
	if err != nil || d.Finish() != nil || !bytes.Equal(encoded, raw) || !bytes.Equal(have, want) || !pruneEffectMatches(s.Request, *s.Admission, effect) {
		return zero, nil, prunefence.ErrFence
	}
	return effect, &proof, nil
}

func (e *PruneExecutor) loadFenceCandidate(binding types.Hash) error {
	_, present := e.identity["fence"]
	if present != !e.request.FencePolicyID.IsZero() {
		return prunefence.ErrFence
	}
	if !present {
		return nil
	}
	names, err := boundedNames(filepath.Join(e.path, "fence"), 1)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		if e.fenceClaim != nil {
			return prunefence.ErrFence
		}
		return nil
	}
	if names[0] != "candidate" {
		return prunefence.ErrFence
	}
	raw, err := readRegular(filepath.Join(e.path, "fence", "candidate"), prunefence.MaximumCandidateBytes)
	if err != nil {
		return err
	}
	c, err := prunefence.DecodeCandidate(raw)
	if err != nil {
		return err
	}
	if err := verifyPruneFenceCandidate(e.execution(), c); err != nil {
		return err
	}
	if c.Binding.ExecutorBindingID != binding {
		return prunefence.ErrFence
	}
	if e.fenceClaim != nil {
		want, _ := e.fenceClaim.Candidate.CanonicalBytes()
		if !bytes.Equal(raw, want) {
			return prunefence.ErrFence
		}
	}
	e.fenceCandidate = &c
	info, err := os.Lstat(filepath.Join(e.path, "fence", "candidate"))
	if err != nil {
		return err
	}
	e.identity[filepath.Join("fence", "candidate")] = info
	if err := syncPath(filepath.Join(e.path, "fence", "candidate")); err != nil {
		return err
	}
	return syncDirectory(filepath.Join(e.path, "fence"))
}
func (e *PruneExecutor) checkFenceCandidate() error {
	if e.request.FencePolicyID.IsZero() {
		return nil
	}
	names, err := boundedNames(filepath.Join(e.path, "fence"), 1)
	if err != nil {
		return err
	}
	if e.fenceCandidate == nil {
		if len(names) != 0 {
			return prunefence.ErrFence
		}
		return nil
	}
	if len(names) != 1 || names[0] != "candidate" {
		return prunefence.ErrFence
	}
	raw, err := readRegular(filepath.Join(e.path, "fence", "candidate"), prunefence.MaximumCandidateBytes)
	want, we := e.fenceCandidate.CanonicalBytes()
	if err != nil || we != nil || !bytes.Equal(raw, want) {
		return prunefence.ErrFence
	}
	if e.fenceClaim != nil {
		claim, _ := e.fenceClaim.Candidate.CanonicalBytes()
		if !bytes.Equal(raw, claim) {
			return prunefence.ErrFence
		}
	}
	return nil
}

func (e *PruneExecutor) executeFencedInventory(ctx context.Context, chain *workchain.Store, v ScheduledPruneInventory, inventoryID types.Hash, authorize func() (uint64, error), collect PruneClaimCollector) (workchain.CanonicalPruneCommit, error) {
	var zero workchain.CanonicalPruneCommit
	if collect == nil || v.FencePolicy == nil || e.fenceCandidate != nil {
		return zero, prunefence.ErrFence
	}
	op, err := pruneFenceOperation(e.execution())
	if err != nil {
		return zero, err
	}
	operationID, err := op.FenceOperationID()
	if err != nil {
		return zero, err
	}
	session, err := prunefence.NewSession(*v.FencePolicy, prunefence.Binding{RequestID: e.id, AssignmentID: e.request.AssignmentID, OperationID: operationID, InventoryID: inventoryID, ExecutorBindingID: e.pins.binding, StoragePairID: v.StoragePairID})
	if err != nil {
		return zero, err
	}
	defer session.Close()
	c, err := session.Candidate()
	if err != nil {
		return zero, err
	}
	raw, _ := c.CanonicalBytes()
	if err := writeExclusive(filepath.Join(e.path, "fence", "candidate"), raw); err != nil {
		return zero, e.poison(err)
	}
	if err := syncDirectory(filepath.Join(e.path, "fence")); err != nil {
		return zero, e.poison(err)
	}
	if err := e.loadFenceCandidate(e.pins.binding); err != nil {
		return zero, e.poison(err)
	}
	if err := e.hooks.reach("prune-fence-candidate-synced"); err != nil {
		return zero, err
	}
	scope, draft, err := c.Draft()
	if err != nil {
		return zero, err
	}
	certificate, err := collect(ctx, scope, draft)
	if err != nil {
		return zero, err
	}
	permit, claim, err := session.Authorize(certificate)
	if err != nil {
		return zero, err
	}
	if err := e.hooks.reach("prune-fence-quorum-before-start"); err != nil {
		return zero, err
	}
	if err := e.operationCheck(); err != nil {
		return zero, err
	}
	if _, err := authorize(); err != nil {
		return zero, err
	}
	claimRaw, _ := claim.CanonicalBytes()
	start := append([]byte("OMCPSTRT\x00\x02"), claimRaw...)
	if err := e.publish(ctx, 1, start, "prune-start"); err != nil {
		return zero, err
	}
	e.stage = PruneStarted
	e.archiveInventoryID = inventoryID
	e.fenceClaim = &claim
	if err := e.applied("prune-start"); err != nil {
		return zero, err
	}
	if err := e.hooks.reach("prune-before-effect"); err != nil {
		return zero, errors.Join(ErrPruneOutcome, err)
	}
	commit, err := chain.PruneCanonicalPrefixFenced(op, func() (uint64, error) {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return authorize()
	}, permit)
	if err != nil || !commit.Applied {
		return zero, errors.Join(ErrPruneOutcome, err)
	}
	if err := e.hooks.reach("prune-after-effect"); err != nil {
		return zero, errors.Join(ErrPruneOutcome, err)
	}
	id, err := commit.Effect.ID()
	if err != nil {
		return zero, err
	}
	proof, err := permit.Seal(id)
	if err != nil {
		return zero, err
	}
	result, err := encodePruneFenceResult(commit.Effect, proof)
	if err != nil {
		return zero, err
	}
	if err := e.publish(context.Background(), 2, result, "prune-result"); err != nil {
		return zero, err
	}
	owned, err := advancePruneExecution(e.assignment, e.execution(), result)
	if err != nil {
		return zero, err
	}
	e.installExecution(owned)
	if err := e.applied("prune-result"); err != nil {
		return zero, err
	}
	return commit, nil
}
