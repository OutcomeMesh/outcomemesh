package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const CustodySourceHandoffBytes = 10 + 3 + 10*32 + 16 + 4
const MaximumCustodySourceHandoffProofBytes = 9 << 20
const custodySourceHandoffName = "source-handoff.omcsh"
const custodySourceHandoffProofName = "source-handoff-proof.omcsh"

var ErrCustodySourceHandedOff = errors.New("custody source was handed off; legacy access is forbidden")
var ErrCustodySourceHandoff = errors.New("invalid or incomplete custody source handoff; exact recovery required")

// CustodySourceHandoff permanently seals the original journal for one selected
// successor. It is local version exclusion, not activation or hardware fencing.
// ProofID commits the complete selected import proof, retained beside this record.
type CustodySourceHandoff struct {
	Version, TargetVersion                                                  uint16
	Role                                                                    uint8
	RegistryID, RegistryDescriptorID, GenesisID, GenesisDescriptorID        types.Hash
	EnrollmentID, ProposalID, PlacementID, ProofID, SourceHeadID, ReceiptID types.Hash
	SourceSequence, RetainUntil                                             uint64
	SpentOperations                                                         uint32
}

func (h CustodySourceHandoff) CanonicalBytes() ([]byte, error) {
	if h.Version != 1 || h.TargetVersion != 5 || (h.Role != 1 && h.Role != 2) || h.RetainUntil == 0 || (h.SourceSequence == 0) != h.SourceHeadID.IsZero() {
		return nil, ErrCustodySourceHandoff
	}
	e := codec.NewEncoder(CustodySourceHandoffBytes)
	e.Fixed([]byte("OMCSHOF1"))
	e.U16(h.Version)
	e.U16(h.TargetVersion)
	e.U8(h.Role)
	for _, id := range []types.Hash{h.RegistryID, h.RegistryDescriptorID, h.GenesisID, h.GenesisDescriptorID, h.EnrollmentID, h.ProposalID, h.PlacementID, h.ProofID, h.SourceHeadID, h.ReceiptID} {
		e.Fixed(id[:])
	}
	// Check zero identities independently: SourceHeadID alone may be zero.
	for _, id := range []types.Hash{h.RegistryID, h.RegistryDescriptorID, h.GenesisID, h.GenesisDescriptorID, h.EnrollmentID, h.ProposalID, h.PlacementID, h.ProofID, h.ReceiptID} {
		if id.IsZero() {
			return nil, ErrCustodySourceHandoff
		}
	}
	e.U64(h.SourceSequence)
	e.U64(h.RetainUntil)
	e.U32(h.SpentOperations)
	return e.Bytes(), nil
}
func DecodeCustodySourceHandoff(raw []byte) (CustodySourceHandoff, error) {
	var h CustodySourceHandoff
	if len(raw) != CustodySourceHandoffBytes {
		return h, ErrCustodySourceHandoff
	}
	d := codec.NewDecoder(raw)
	m, _ := d.Fixed(8)
	h.Version, _ = d.U16()
	h.TargetVersion, _ = d.U16()
	h.Role, _ = d.U8()
	for _, id := range []*types.Hash{&h.RegistryID, &h.RegistryDescriptorID, &h.GenesisID, &h.GenesisDescriptorID, &h.EnrollmentID, &h.ProposalID, &h.PlacementID, &h.ProofID, &h.SourceHeadID, &h.ReceiptID} {
		v, _ := d.Fixed(32)
		copy(id[:], v)
	}
	h.SourceSequence, _ = d.U64()
	h.RetainUntil, _ = d.U64()
	h.SpentOperations, _ = d.U32()
	again, err := h.CanonicalBytes()
	if err != nil || d.Finish() != nil || string(m) != "OMCSHOF1" || !bytes.Equal(raw, again) {
		return CustodySourceHandoff{}, ErrCustodySourceHandoff
	}
	return h, nil
}
func (h CustodySourceHandoff) ID() (types.Hash, error) {
	raw, e := h.CanonicalBytes()
	if e != nil {
		return types.Hash{}, e
	}
	return types.DomainHash("OMESH/custody-source-handoff/v1/id", raw), nil
}
func CustodySourceHandoffProofID(raw []byte) types.Hash {
	return types.DomainHash("OMESH/custody-source-handoff/v1/selected-proof", raw)
}

func requireCustodySourceAccess(root string, expected *CustodySourceHandoff) error {
	if _, e := os.Lstat(filepath.Join(root, custodyRetirementFileName)); e == nil {
		return ErrCustodyJournalRetired
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	marker := filepath.Join(root, custodySourceHandoffName)
	proof := filepath.Join(root, custodySourceHandoffProofName)
	_, me := os.Lstat(marker)
	_, pe := os.Lstat(proof)
	if expected == nil {
		if me == nil || pe == nil {
			return ErrCustodySourceHandedOff
		}
		if !errors.Is(me, os.ErrNotExist) {
			return me
		}
		if !errors.Is(pe, os.ErrNotExist) {
			return pe
		}
		return nil
	}
	want, e := expected.CanonicalBytes()
	if e != nil {
		return e
	}
	if errors.Is(me, os.ErrNotExist) {
		if !errors.Is(pe, os.ErrNotExist) {
			return ErrCustodySourceHandoff
		}
		return nil
	}
	got, e := readRegularArchiveFile(marker, CustodySourceHandoffBytes)
	if e != nil || !bytes.Equal(got, want) {
		return errors.Join(ErrCustodySourceHandoff, e)
	}
	if errors.Is(pe, os.ErrNotExist) {
		return nil
	}
	raw, e := readRegularArchiveFile(proof, MaximumCustodySourceHandoffProofBytes)
	if e != nil || CustodySourceHandoffProofID(raw) != expected.ProofID {
		return errors.Join(ErrCustodySourceHandoff, e)
	}
	return nil
}

// OpenCustodySourceHandoff acquires the ORIGINAL journal for one exact sealing
// attempt or its recovery. The returned decision cannot append or rotate even
// before sealing. Complete proof and original-owner checks belong to the caller.
func OpenCustodySourceHandoff(ctx context.Context, path string, manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy, h CustodySourceHandoff) (*CustodyJournalDecision, error) {
	if _, e := h.CanonicalBytes(); e != nil {
		return nil, e
	}
	j, _, e := openExistingCustodyJournal(ctx, path, manifest, initial, policy, DefaultCustodyJournalLimits(), &h)
	if e != nil {
		return nil, e
	}
	return j.acquireDecision(&h)
}

func (d *CustodyJournalDecision) SealSourceHandoff(ctx context.Context, proof []byte) (bool, error) {
	return d.sealSourceHandoff(ctx, proof, nil)
}
func (d *CustodyJournalDecision) sealSourceHandoff(ctx context.Context, proof []byte, hook func(string) error) (changed bool, err error) {
	return d.sealSourceHandoffWithLimits(ctx, proof, hook, CustodyJournalLimits{MaximumBytes: MaximumCustodyJournalBytes, MaximumPaths: MaximumCustodyJournalPaths})
}

// A private tighter ceiling lets fault tests exercise the real preflight without
// constructing a terabyte file or a million paths. Public use fixes hard bounds.
func (d *CustodyJournalDecision) sealSourceHandoffWithLimits(ctx context.Context, proof []byte, hook func(string) error, ceiling CustodyJournalLimits) (changed bool, err error) {
	if d == nil || ctx == nil {
		return false, ErrCustodySourceHandoff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handoff == nil || len(proof) == 0 || len(proof) > MaximumCustodySourceHandoffProofBytes {
		return false, ErrCustodySourceHandoff
	}
	proof = append([]byte(nil), proof...)
	if e := d.check(); e != nil {
		return false, e
	}
	h := *d.handoff
	if CustodySourceHandoffProofID(proof) != h.ProofID {
		return false, ErrCustodySourceHandoff
	}
	state, e := d.journal.handoffState()
	if e != nil {
		return false, e
	}
	rid, _ := state.CurrentReceipt.ID()
	if state.Sequence != h.SourceSequence || state.HeadEntryID != h.SourceHeadID || rid != h.ReceiptID || state.CurrentReceipt.RetainUntil > h.RetainUntil {
		return false, ErrCustodySourceHandoff
	}
	raw, _ := h.CanonicalBytes()

	// Reserve both immutable additions before the irreversible first seal. A
	// reduced local growth budget does not prevent drain, but hard replay bounds
	// must still admit the complete retained evidence after an interrupted write.
	usage, e := inventoryCustodyJournal(d.journal.path)
	if e != nil {
		return false, e
	}
	if usage.PendingFiles != 0 || usage.PendingBytes != 0 {
		return false, ErrCustodySourceHandoff
	}
	var addBytes, addPaths uint64
	for _, item := range []struct {
		name string
		size int
	}{{custodySourceHandoffName, len(raw)}, {custodySourceHandoffProofName, len(proof)}} {
		if _, e := os.Lstat(filepath.Join(d.journal.path, item.name)); errors.Is(e, os.ErrNotExist) {
			addBytes += uint64(item.size)
			addPaths++
		} else if e != nil {
			return false, e
		}
	}
	if e := usage.admit(ceiling, addBytes, addPaths); e != nil {
		return false, e
	}
	defer func() {
		if err != nil {
			d.failed = true
		}
	}()
	for _, item := range []struct {
		name string
		raw  []byte
	}{{custodySourceHandoffName, raw}, {custodySourceHandoffProofName, proof}} {
		if e := ctx.Err(); e != nil {
			return changed, e
		}
		one, e := publishSourceHandoff(ctx, d.journal.path, item.name, item.raw, hook)
		changed = changed || one
		if e != nil {
			return changed, errors.Join(ErrCustodySourceHandoff, e)
		}
	}
	if e := d.check(); e != nil {
		return changed, e
	}
	return changed, ctx.Err()
}

// InspectSourceHandoff succeeds only for the complete exact retained pair.
func (d *CustodyJournalDecision) InspectSourceHandoff() (CustodySourceHandoff, error) {
	if d == nil {
		return CustodySourceHandoff{}, ErrCustodySourceHandoff
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handoff == nil {
		return CustodySourceHandoff{}, ErrCustodySourceHandoff
	}
	if e := d.check(); e != nil {
		return CustodySourceHandoff{}, e
	}
	raw, e := readRegularArchiveFile(filepath.Join(d.journal.path, custodySourceHandoffProofName), MaximumCustodySourceHandoffProofBytes)
	if e != nil || CustodySourceHandoffProofID(raw) != d.handoff.ProofID {
		return CustodySourceHandoff{}, errors.Join(ErrCustodySourceHandoff, e)
	}
	// Proof-only roots never satisfy requireCustodySourceAccess; require marker too.
	raw, e = readRegularArchiveFile(filepath.Join(d.journal.path, custodySourceHandoffName), CustodySourceHandoffBytes)
	if e != nil {
		return CustodySourceHandoff{}, e
	}
	return DecodeCustodySourceHandoff(raw)
}
func publishSourceHandoff(ctx context.Context, root, name string, raw []byte, hook func(string) error) (bool, error) {
	run := func(stage string) error {
		if hook != nil {
			return hook(name + "-" + stage)
		}
		return nil
	}
	path := filepath.Join(root, name)
	if got, e := readRegularArchiveFile(path, len(raw)); e == nil {
		if !bytes.Equal(got, raw) {
			return false, ErrCustodySourceHandoff
		}
		f, e := os.Open(path)
		if e != nil {
			return false, e
		}
		return false, errors.Join(f.Sync(), f.Close(), syncDirectory(root))
	} else if !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	temp, e := writeCustodyTransferTemporary(ctx, filepath.Dir(root), raw)
	if e != nil {
		return false, e
	}
	if e := run("before-link"); e != nil {
		return false, e
	}
	if e := ctx.Err(); e != nil {
		return false, e
	}
	if e := os.Link(temp, path); e != nil {
		return false, e
	}
	if e := run("after-link"); e != nil {
		return true, e
	}
	if e := syncDirectory(root); e != nil {
		return true, e
	}
	if e := run("durable"); e != nil {
		return true, e
	}
	if e := os.Remove(temp); e != nil {
		return true, e
	}
	return true, syncDirectory(filepath.Dir(root))
}

func requireNoCustodyHandoff(root string) error {
	for _, name := range []string{custodySourceHandoffName, custodySourceHandoffProofName} {
		if _, e := os.Lstat(filepath.Join(root, name)); e == nil {
			return ErrCustodySourceHandedOff
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	return nil
}

// Ordinary replay retains losing/uncommitted bodies for forensic recovery.
// Source transfer requires a clean decided prefix and no unresolved publication.
func (j *CustodyJournal) handoffState() (CustodyJournalState, error) {
	state, e := j.scan()
	if e != nil {
		return CustodyJournalState{}, e
	}
	usage, e := inventoryCustodyJournal(j.path)
	if e != nil {
		return CustodyJournalState{}, e
	}
	bodies, e := j.scanBodyPaths()
	if e != nil {
		return CustodyJournalState{}, e
	}
	if usage.PendingFiles != 0 || usage.PendingBytes != 0 || uint64(len(bodies)) != state.Sequence {
		return CustodyJournalState{}, ErrCustodySourceHandoff
	}
	return state, nil
}
