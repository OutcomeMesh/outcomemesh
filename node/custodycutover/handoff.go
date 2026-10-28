package custodycutover

import (
	"bytes"
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

// SourceHandoffPins must be retained outside the source participant backup.
// They identify the complete import, original location and selected proof.
type SourceHandoffPins struct{ GenesisID, GenesisDescriptorID, EnrollmentID, PlacementID types.Hash }

// ReviewSourceHandoff verifies public consent and selection, without opening any
// owner or claiming that this local location is a protected hardware identity.
func ReviewSourceHandoff(g v2.AdmissionGenesis, b v2.EnrollmentBinding, pins SourceHandoffPins, role Role) (workarchive.CustodySourceHandoff, error) {
	var h workarchive.CustodySourceHandoff
	if g.Version != v2.PolicyVersionImported || g.Import == nil || (role != Authority && role != Target) || pins.PlacementID.IsZero() {
		return h, ErrPreparation
	}
	if e := b.VerifyImported(g); e != nil {
		return h, e
	}
	gid, e := g.ID()
	if e != nil || gid != pins.GenesisID {
		return h, ErrPreparation
	}
	did, e := g.DescriptorID()
	if e != nil || did != pins.GenesisDescriptorID {
		return h, ErrPreparation
	}
	bid, e := b.ID()
	if e != nil || bid != pins.EnrollmentID {
		return h, ErrPreparation
	}
	p := *g.Import
	observation := p.A
	if role == Target {
		observation = p.B
	}
	commitment := types.DomainHash(domain+"source-placement/commitment", observation.Nonce[:], pins.PlacementID[:])
	if observation.Role != role || observation.PlacementCommitment != commitment {
		return h, ErrPreparation
	}
	lid, _ := p.Evidence.Assignment.ID()
	old, e := p.Evidence.Verify(lid, p.Evidence.End)
	if e != nil {
		return h, e
	}
	raw, e := b.CanonicalBytes()
	if e != nil {
		return h, e
	}
	pid, _ := p.ID()
	h = workarchive.CustodySourceHandoff{Version: 1, TargetVersion: 5, Role: uint8(role), GenesisID: gid, GenesisDescriptorID: did, EnrollmentID: bid, ProposalID: pid, PlacementID: pins.PlacementID, ProofID: workarchive.CustodySourceHandoffProofID(raw), SourceHeadID: old.SourceHeadID, ReceiptID: old.ReceiptID, SourceSequence: old.SourceSequence, RetainUntil: old.MinimumRetainUntil, SpentOperations: old.SpentOperations}
	h.RegistryID, _ = p.Anchor.ID()
	h.RegistryDescriptorID, _ = p.Anchor.DescriptorID()
	_, e = h.CanonicalBytes()
	return h, e
}

// TransferSourceHandoff seals one ORIGINAL A or B journal for its selected
// successor while original authority/worker and source guards are held. Retry
// completes only the same record/proof; no journal copy, append or time refresh.
func TransferSourceHandoff(ctx context.Context, g v2.AdmissionGenesis, b v2.EnrollmentBinding, pins SourceHandoffPins, l SourceLocation) (workarchive.CustodySourceHandoff, bool, error) {
	return sourceHandoff(ctx, g, b, pins, l, true, nil)
}
func InspectSourceHandoff(ctx context.Context, g v2.AdmissionGenesis, b v2.EnrollmentBinding, pins SourceHandoffPins, l SourceLocation) (workarchive.CustodySourceHandoff, error) {
	h, _, e := sourceHandoff(ctx, g, b, pins, l, false, nil)
	return h, e
}

// InspectSourceHandoffChunk reads one manifest-bound original object while the
// original retirement/worker and source-journal guards remain held. It publishes
// no receipt and does not enable imported job execution.
func InspectSourceHandoffChunk(ctx context.Context, g v2.AdmissionGenesis, b v2.EnrollmentBinding, pins SourceHandoffPins, l SourceLocation, objects string, id types.Hash) (workarchive.CustodySourceHandoff, []byte, error) {
	if l.Role != Target || objects == "" || id.IsZero() {
		return workarchive.CustodySourceHandoff{}, nil, ErrPreparation
	}
	read := &sourceChunkRead{objects: objects, id: id}
	h, _, err := sourceHandoff(ctx, g, b, pins, l, false, read)
	if err != nil {
		return workarchive.CustodySourceHandoff{}, nil, err
	}
	return h, read.data, nil
}

type sourceChunkRead struct {
	objects string
	id      types.Hash
	data    []byte
}

func sourceHandoff(ctx context.Context, g v2.AdmissionGenesis, b v2.EnrollmentBinding, pins SourceHandoffPins, l SourceLocation, transfer bool, read *sourceChunkRead) (result workarchive.CustodySourceHandoff, changed bool, returnErr error) {
	if ctx == nil {
		return result, false, ErrPreparation
	}
	h, e := ReviewSourceHandoff(g, b, pins, l.Role)
	if e != nil {
		return result, false, e
	}
	// Detach all caller-owned slices before locks or publication.
	raw, e := b.CanonicalBytes()
	if e != nil {
		return result, false, e
	}
	b, e = v2.DecodeEnrollmentBinding(raw)
	if e != nil {
		return result, false, e
	}
	gb, e := g.CanonicalBytes()
	if e != nil {
		return result, false, e
	}
	g, e = v2.DecodeAdmissionGenesis(gb)
	if e != nil {
		return result, false, e
	}
	l.Workers = append([]string(nil), l.Workers...)
	check := func() error {
		actual, e := l.LocationID()
		if e != nil || actual != pins.PlacementID {
			return errors.Join(ErrPreparation, e)
		}
		return ctx.Err()
	}
	if e := check(); e != nil {
		return result, false, e
	}
	p := *g.Import
	lid, _ := p.Evidence.Assignment.ID()
	returnErr = withSourceOwners(ctx, p.Evidence, l, lid, func() (err error) {
		if e := check(); e != nil {
			return e
		}
		d, e := workarchive.OpenCustodySourceHandoff(ctx, l.Journal, g.Manifest, g.Initial, g.CustodyPolicy, h)
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, d.Close()) }()
		if e := check(); e != nil {
			return e
		}
		state, e := d.State()
		if e != nil {
			return e
		}
		usage, e := d.Usage()
		if e != nil {
			return e
		}
		if usage.PendingFiles != 0 || usage.PendingBytes != 0 {
			return ErrBlocked
		}
		receiptID, _ := state.CurrentReceipt.ID()
		if state.Sequence != h.SourceSequence || state.HeadEntryID != h.SourceHeadID || receiptID != h.ReceiptID || state.InitialReceipt != g.Initial {
			return ErrEvidence
		}
		if len(p.Evidence.Cycles) > 0 {
			head, exists, e := d.Head()
			if e != nil || !exists {
				return errors.Join(ErrEvidence, e)
			}
			want, _ := p.Evidence.Cycles[len(p.Evidence.Cycles)-1].Terminal.Entry.CanonicalBytes()
			actual, _ := head.CanonicalBytes()
			if !bytes.Equal(want, actual) {
				return ErrEvidence
			}
		}
		if transfer {
			changed, e = d.SealSourceHandoff(ctx, raw)
			if e != nil {
				return e
			}
		}
		result, e = d.InspectSourceHandoff()
		if e != nil {
			return e
		}
		if read != nil {
			if e := check(); e != nil {
				return e
			}
			store, e := workarchive.OpenExistingObjectStoreContext(ctx, read.objects, workarchive.DefaultObjectStorePolicy())
			if e != nil {
				return e
			}
			mid, e := g.Manifest.ID()
			if e != nil {
				return e
			}
			batch, e := workarchive.ServeChunkRequest(store, g.Manifest, workarchive.ChunkRequest{Version: workarchive.ObjectExchangeVersion0, ManifestID: mid, IDs: []types.Hash{read.id}})
			if e != nil || len(batch.Objects) != 1 {
				return errors.Join(ErrEvidence, e)
			}
			read.data = batch.Objects[0].Encoded
		}
		return check()
	})
	return result, changed, returnErr
}
