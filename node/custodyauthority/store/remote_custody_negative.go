package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type RemoteCustodyNegativeKind uint8

const (
	RemoteCustodyUnseen RemoteCustodyNegativeKind = 1 + iota
	RemoteCustodyUnknown
	RemoteCustodyUnverifiedResult
	RemoteCustodyUnacceptedResult
	RemoteCustodyNegativeVersion0     uint16 = 0
	MaximumRemoteCustodyNegativeBytes        = MaximumRemoteCustodyTerminalBytes + 512
)

// RemoteCustodyNegative is an authority-signed historical observation of the
// original A source after a confirmed Drain. It never proves successful custody
// or grants execution. Unknown and unaccepted results retain ordinary tickets.
type RemoteCustodyNegative struct {
	Version                       uint16
	Kind                          RemoteCustodyNegativeKind
	PlanID, BeginID               types.Hash
	AuditAdmission                custodyauthority.Entry
	Intent                        workarchive.CustodyAuditIntent
	Seal                          remoteworker.Seal
	Drained                       custodyauthority.Entry
	SourceSequence                uint64
	SourceHeadID, SourceReceiptID types.Hash
	RemoteEntry                   *workarchive.CustodyJournalEntry
	Signature                     [ed25519.SignatureSize]byte
}

func (n RemoteCustodyNegative) unsignedBytes() ([]byte, error) {
	if n.Version != RemoteCustodyNegativeVersion0 || n.PlanID.IsZero() || n.BeginID.IsZero() ||
		n.Seal.PlanID != n.PlanID || n.Seal.BeginID != n.BeginID || n.SourceSequence != n.Intent.PriorSequence ||
		n.SourceHeadID != n.Intent.PriorHeadID || n.SourceReceiptID != n.Intent.PriorReceiptID || n.SourceReceiptID.IsZero() ||
		n.AuditAdmission.Version != custodyauthority.Version1 || n.Drained.Version != custodyauthority.Version1 ||
		n.AuditAdmission.AuthorityPublicKey != n.Drained.AuthorityPublicKey {
		return nil, ErrRemoteCustody
	}
	switch n.Kind {
	case RemoteCustodyUnseen:
		if n.Seal.Disposition != remoteworker.Unseen || n.RemoteEntry != nil {
			return nil, ErrRemoteCustody
		}
	case RemoteCustodyUnknown:
		if n.Seal.Disposition != remoteworker.NoResult || n.RemoteEntry != nil {
			return nil, ErrRemoteCustody
		}
	case RemoteCustodyUnverifiedResult:
		if n.Seal.Disposition != remoteworker.RetainedResult || n.RemoteEntry != nil {
			return nil, ErrRemoteCustody
		}
	case RemoteCustodyUnacceptedResult:
		if n.Seal.Disposition != remoteworker.RetainedResult || n.RemoteEntry == nil {
			return nil, ErrRemoteCustody
		}
	default:
		return nil, ErrRemoteCustody
	}
	intentID, err := n.Intent.ID()
	if err != nil {
		return nil, err
	}
	sealID, err := n.Seal.ID()
	if err != nil {
		return nil, err
	}
	a, d := n.AuditAdmission.Command, n.Drained.Command
	if a.Kind != custodyauthority.Admit || a.Purpose != custodyauthority.Audit || a.AssignmentID != n.Intent.AssignmentID ||
		a.OperationID != intentID || a.ActorPublicKey != n.Intent.ConsumerPublicKey || d.Kind != custodyauthority.RemoteDrained ||
		d.AssignmentID != a.AssignmentID || d.OperationID != n.BeginID || d.EvidenceID != sealID {
		return nil, ErrRemoteCustody
	}
	fields := make([][]byte, 0, 5)
	for _, v := range []interface{ CanonicalBytes() ([]byte, error) }{n.AuditAdmission, n.Intent, n.Seal, n.Drained} {
		b, err := v.CanonicalBytes()
		if err != nil {
			return nil, err
		}
		fields = append(fields, b)
	}
	var remote []byte
	if n.RemoteEntry != nil {
		remote, err = n.RemoteEntry.CanonicalBytes()
		id, idErr := n.RemoteEntry.ID()
		if err != nil || idErr != nil || id != n.Seal.ResultID {
			return nil, ErrRemoteCustody
		}
	}
	fields = append(fields, remote)
	e := codec.NewEncoder(2048)
	e.Fixed([]byte("OMCRNEG0"))
	e.U16(n.Version)
	e.U8(uint8(n.Kind))
	for _, id := range []types.Hash{n.PlanID, n.BeginID, n.SourceHeadID, n.SourceReceiptID} {
		e.Fixed(id[:])
	}
	e.U64(n.SourceSequence)
	for _, field := range fields {
		e.BytesField(field)
	}
	b := e.Bytes()
	if len(b)+ed25519.SignatureSize > MaximumRemoteCustodyNegativeBytes {
		return nil, ErrRemoteCustody
	}
	return b, nil
}

func (n RemoteCustodyNegative) CanonicalBytes() ([]byte, error) {
	b, err := n.unsignedBytes()
	if err != nil {
		return nil, err
	}
	id := types.DomainHash("OMESH/custody-authority/remote-negative/signature/v0", b)
	if !ed25519.Verify(n.Drained.AuthorityPublicKey[:], id[:], n.Signature[:]) {
		return nil, ErrRemoteCustody
	}
	return append(b, n.Signature[:]...), nil
}

func (n RemoteCustodyNegative) ID() (types.Hash, error) {
	b, err := n.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/custody-authority/remote-negative/id/v0", b), nil
}

func DecodeRemoteCustodyNegative(input []byte) (RemoteCustodyNegative, error) {
	bad := func() (RemoteCustodyNegative, error) { return RemoteCustodyNegative{}, ErrRemoteCustody }
	if len(input) < ed25519.SignatureSize || len(input) > MaximumRemoteCustodyNegativeBytes {
		return bad()
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCRNEG0")) {
		return bad()
	}
	var n RemoteCustodyNegative
	if n.Version, err = d.U16(); err != nil {
		return bad()
	}
	kind, err := d.U8()
	if err != nil {
		return bad()
	}
	n.Kind = RemoteCustodyNegativeKind(kind)
	for _, id := range []*types.Hash{&n.PlanID, &n.BeginID, &n.SourceHeadID, &n.SourceReceiptID} {
		b, err := d.Fixed(types.HashSize)
		if err != nil {
			return bad()
		}
		copy(id[:], b)
	}
	if n.SourceSequence, err = d.U64(); err != nil {
		return bad()
	}
	b, err := d.BytesField(custodyauthority.MaximumEntryBytes)
	if err != nil {
		return bad()
	}
	if n.AuditAdmission, err = custodyauthority.DecodeEntry(b); err != nil {
		return bad()
	}
	b, err = d.BytesField(workarchive.MaximumCustodyAuditIntentBytes)
	if err != nil {
		return bad()
	}
	if n.Intent, err = workarchive.DecodeCustodyAuditIntent(b); err != nil {
		return bad()
	}
	b, err = d.BytesField(remoteworker.SealBytes)
	if err != nil {
		return bad()
	}
	if n.Seal, err = remoteworker.DecodeSeal(b); err != nil {
		return bad()
	}
	b, err = d.BytesField(custodyauthority.MaximumEntryBytes)
	if err != nil {
		return bad()
	}
	if n.Drained, err = custodyauthority.DecodeEntry(b); err != nil {
		return bad()
	}
	b, err = d.BytesField(workarchive.MaximumCustodyJournalEntryBytes)
	if err != nil {
		return bad()
	}
	if len(b) != 0 {
		entry, err := workarchive.DecodeCustodyJournalEntry(b)
		if err != nil {
			return bad()
		}
		n.RemoteEntry = &entry
	}
	b, err = d.Fixed(ed25519.SignatureSize)
	if err != nil {
		return bad()
	}
	copy(n.Signature[:], b)
	if d.Finish() != nil {
		return bad()
	}
	if _, err := n.CanonicalBytes(); err != nil {
		return bad()
	}
	return n, nil
}

func (n RemoteCustodyNegative) Validate(scope RemoteCustodyScope) error {
	if err := validateRemoteAuditScope(scope, n.Intent, n.AuditAdmission); err != nil {
		return err
	}
	if _, err := n.CanonicalBytes(); err != nil {
		return err
	}
	if n.PlanID != scope.Worker.PlanID || n.BeginID != scope.Worker.BeginID || n.Drained.AuthorityPublicKey != scope.Worker.Assignment.AuthorityPublicKey {
		return ErrRemoteCustody
	}
	if err := ValidateRemoteCustodyDrain(scope, n.Seal, n.Drained.Command); err != nil {
		return err
	}
	if n.RemoteEntry != nil {
		if err := n.RemoteEntry.Verify(scope.Manifest, scope.CustodyPolicy, scope.Worker.Plan.PriorSequence+1, scope.Worker.Plan.PriorHeadID, scope.PreviousReceipt); err != nil {
			return err
		}
		cid, _ := n.RemoteEntry.Record.Challenge.ID()
		if cid != scope.Worker.Plan.Admission.Command.OperationID {
			return ErrRemoteCustody
		}
	}
	return nil
}

func LoadRemoteCustodyNegative(path string, pin types.Hash) (RemoteCustodyNegative, error) {
	if pin.IsZero() {
		return RemoteCustodyNegative{}, ErrRemoteCustody
	}
	b, err := readRegular(path, MaximumRemoteCustodyNegativeBytes)
	if err != nil {
		return RemoteCustodyNegative{}, err
	}
	n, err := DecodeRemoteCustodyNegative(b)
	if err != nil {
		return RemoteCustodyNegative{}, err
	}
	id, err := n.ID()
	if err != nil || id != pin {
		return RemoteCustodyNegative{}, ErrRemoteCustody
	}
	return n, nil
}

func (r *RemoteCustodyAuditRuntime) checkNegativeLocked(n RemoteCustodyNegative, decision *workarchive.CustodyJournalDecision) error {
	if err := n.Validate(r.scope); err != nil {
		return err
	}
	return r.checkNegativeStateLocked(n, decision)
}

func (r *RemoteCustodyAuditRuntime) checkNegativeStateLocked(n RemoteCustodyNegative, decision *workarchive.CustodyJournalDecision) error {
	if n.Intent != r.intent || n.AuditAdmission != r.admission {
		return ErrRemoteCustody
	}
	current, err := r.life.owner.snapshot()
	if err != nil {
		return err
	}
	if err := r.pendingTicketsLocked(current); err != nil {
		return err
	}
	if current.Authority.Remote != nil {
		return custodyauthority.ErrRemoteActive
	}
	drainID, _ := n.Drained.ID()
	sealID, _ := n.Seal.ID()
	serveID, _ := r.scope.Worker.Plan.Admission.ID()
	matched := false
	for _, op := range current.Authority.Operations {
		if op.TicketID == serveID {
			matched = op.RemoteBeginID == n.BeginID && op.RemotePlanID == n.PlanID && op.RemoteDrainID == drainID && op.RemoteTombstoneID == sealID
		}
	}
	if !matched || current.Confirmed.Sequence < n.Drained.Command.ExpectedSequence+1 {
		return ErrRemoteCustody
	}
	source, err := decision.State()
	if err != nil {
		return err
	}
	rid, err := source.CurrentReceipt.ID()
	if err != nil || source.InitialReceipt != r.scope.InitialReceipt || source.Sequence != n.SourceSequence || source.HeadEntryID != n.SourceHeadID || rid != n.SourceReceiptID {
		return ErrRemoteCustody
	}
	return r.checkSourceIdentity()
}

// CaptureNegativeToFile never completes tickets or imports B's historical data.
// A nil remote entry retains only B's signed commitment, explicitly unverified.
func (r *RemoteCustodyAuditRuntime) CaptureNegativeToFile(ctx context.Context, response remotewire.Response, remote *workarchive.CustodyJournalEntry, path string) (n RemoteCustodyNegative, returnErr error) {
	if path == "" {
		return n, ErrRemoteCustody
	}
	// Freeze caller-owned slice-bearing data before waiting for the owner.
	if remote != nil {
		b, err := remote.CanonicalBytes()
		if err != nil {
			return n, err
		}
		entry, err := workarchive.DecodeCustodyJournalEntry(b)
		if err != nil {
			return n, err
		}
		remote = &entry
	}
	err := r.action(ctx, func(run context.Context) (returnErr error) {
		if _, err := response.CanonicalBytes(); err != nil {
			return err
		}
		if response.Status != remotewire.StatusDrained || response.PlanID != r.scope.Worker.PlanID || response.BeginID != r.scope.Worker.BeginID {
			return ErrRemoteCustody
		}
		if err := ValidateRemoteCustodyDrain(r.scope, response.Seal, response.Drain); err != nil {
			return err
		}
		drained, err := custodyauthority.SignEntry(response.Drain, r.authorityKey)
		if err != nil {
			return err
		}
		kind := RemoteCustodyUnseen
		switch response.Seal.Disposition {
		case remoteworker.NoResult:
			kind = RemoteCustodyUnknown
		case remoteworker.RetainedResult:
			kind = RemoteCustodyUnverifiedResult
			if remote != nil {
				kind = RemoteCustodyUnacceptedResult
			}
		}
		n = RemoteCustodyNegative{Version: RemoteCustodyNegativeVersion0, Kind: kind, PlanID: r.scope.Worker.PlanID, BeginID: r.scope.Worker.BeginID, AuditAdmission: r.admission, Intent: r.intent, Seal: response.Seal, Drained: drained,
			SourceSequence: r.intent.PriorSequence, SourceHeadID: r.intent.PriorHeadID, SourceReceiptID: r.intent.PriorReceiptID, RemoteEntry: remote}
		unsigned, err := n.unsignedBytes()
		if err != nil {
			return err
		}
		decision, err := r.journal.AcquireDecision()
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
		if err := r.checkNegativeStateLocked(n, decision); err != nil {
			return err
		}
		if remote != nil {
			if err := remote.Verify(r.scope.Manifest, r.scope.CustodyPolicy, r.scope.Worker.Plan.PriorSequence+1, r.scope.Worker.Plan.PriorHeadID, r.scope.PreviousReceipt); err != nil {
				return err
			}
			cid, _ := remote.Record.Challenge.ID()
			if cid != r.scope.Worker.Plan.Admission.Command.OperationID {
				return ErrRemoteCustody
			}
		}
		message := types.DomainHash("OMESH/custody-authority/remote-negative/signature/v0", unsigned)
		copy(n.Signature[:], ed25519.Sign(r.authorityKey, message[:]))
		if err := r.checkNegativeLocked(n, decision); err != nil {
			return err
		}
		if err := r.remoteOutputPath(path); err != nil {
			return err
		}
		b, err := n.CanonicalBytes()
		if err != nil {
			return err
		}
		return publishCustodyArtifactBytes(run, path, b)
	})
	if err != nil {
		return RemoteCustodyNegative{}, err
	}
	return n, nil
}

func (r *RemoteCustodyAuditRuntime) VerifyNegative(ctx context.Context, n RemoteCustodyNegative) error {
	b, err := n.CanonicalBytes()
	if err != nil {
		return err
	}
	n, err = DecodeRemoteCustodyNegative(b)
	if err != nil {
		return err
	}
	return r.action(ctx, func(_ context.Context) (returnErr error) {
		d, err := r.journal.AcquireDecision()
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, d.Close()) }()
		return r.checkNegativeLocked(n, d)
	})
}
