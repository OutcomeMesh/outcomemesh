package custodycutover

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	w "github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	s "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type SourceLocation struct {
	Role                              Role
	Journal, Authority, AuthorityPins string
	Workers                           []string
}

func canonicalPath(path string) (string, error) {
	if !utf8.ValidString(path) || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrPreparation
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return "", errors.Join(ErrPreparation, e)
	}
	return path, nil
}

// LocationID is a local metadata candidate. It is not independent enrollment,
// hardware attestation, proof of no copies or a portable activation grant.
func (l SourceLocation) LocationID() (types.Hash, error) {
	if l.Role != Authority && l.Role != Target || len(l.Workers) > MaximumCycles {
		return types.Hash{}, ErrPreparation
	}
	if l.Role == Authority && (l.Authority == "" || l.AuthorityPins == "" || len(l.Workers) != 0) || l.Role == Target && (l.Authority != "" || l.AuthorityPins != "") {
		return types.Hash{}, ErrPreparation
	}
	paths := map[string]string{"journal": l.Journal, "journal-lock": filepath.Join(l.Journal, "journal.lock")}
	if l.Role == Authority {
		paths["authority"] = l.Authority
		paths["authority-lock"] = filepath.Join(l.Authority, "authority.lock")
		paths["authority-pins"] = l.AuthorityPins
		paths["intent-lock"] = filepath.Join(l.AuthorityPins, "intent.lock")
	}
	for i, path := range l.Workers {
		label := string(rune('a' + i))
		paths["worker-"+label] = path
		paths["worker-lock-"+label] = filepath.Join(path, "worker.lock")
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	enc := codec.NewEncoder(1024)
	enc.U8(uint8(l.Role))
	for _, name := range names {
		path, e := canonicalPath(paths[name])
		if e != nil {
			return types.Hash{}, e
		}
		info, e := os.Lstat(path)
		if e != nil || (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().Perm()&0077 != 0 {
			return types.Hash{}, ErrPreparation
		}
		dev, ino, uid, e := fileIdentity(info)
		if e != nil || uid != uint64(os.Geteuid()) || ino == 0 {
			return types.Hash{}, ErrPreparation
		}
		enc.BytesField([]byte(name))
		enc.BytesField([]byte(path))
		enc.U64(dev)
		enc.U64(ino)
		enc.U64(uid)
		enc.U32(uint32(info.Mode()))
		var changeSec, changeNS int64
		if info.Mode().IsRegular() {
			enc.U64(uint64(info.Size()))
			changeSec, changeNS, e = lockChangeIdentity(info)
			if e != nil {
				return types.Hash{}, e
			}
		} else {
			enc.U64(0)
		}
		enc.U64(uint64(changeSec))
		enc.U64(uint64(changeNS))
	}
	return types.DomainHash(domain+"local-source-location/id", enc.Bytes()), nil
}
func compareHistory(e Evidence, assignment a.Assignment, history []a.Entry) error {
	expected, _ := e.Assignment.CanonicalBytes()
	actual, _ := assignment.CanonicalBytes()
	if !bytes.Equal(expected, actual) || len(history) != len(e.History) {
		return ErrEvidence
	}
	for i, v := range history {
		if v != e.History[i] {
			return ErrEvidence
		}
	}
	return nil
}

// ExportEvidence requires an original confirmed retirement, not a supplied
// snapshot. The callback can retain the exact public bytes while that guard is
// held. Unavailable/unresolved original state is never repaired or skipped.
func ExportEvidence(ctx context.Context, owner *s.Coordinator, template Evidence, legacyID types.Hash, pin a.Position, retain func(Evidence) error) error {
	if ctx == nil || owner == nil || retain == nil || len(template.History) != 0 || template.End != (a.Position{}) {
		return ErrEvidence
	}
	return owner.WithConfirmedRetirement(ctx, pin, MaximumHistoryEntries, func(assignment a.Assignment, history []a.Entry) error {
		want, _ := template.Assignment.ID()
		actual, _ := assignment.ID()
		if want != legacyID || actual != legacyID {
			return ErrEvidence
		}
		template.History = history
		template.End = pin
		if _, e := template.Verify(legacyID, pin); e != nil {
			return e
		}
		return retain(template)
	})
}

// CaptureSource signs historical current-source agreement under original local
// guards. Its location pin and nonce must be independently selected inputs.
// For B every original worker must be sealed with no pending write. This API
// neither starts workers nor drains, seals, retires or imports a journal.
func CaptureSource(ctx context.Context, e Evidence, legacyID, anchorID types.Hash, end a.Position, l SourceLocation, placementID, nonce types.Hash, key ed25519.PrivateKey, retain func(Observation) error) (observation Observation, returnErr error) {
	if ctx == nil || retain == nil || placementID.IsZero() || nonce.IsZero() || anchorID.IsZero() {
		return observation, ErrPreparation
	}
	raw, err := e.CanonicalBytes()
	if err != nil {
		return observation, err
	}
	e, err = DecodeEvidence(raw)
	if err != nil {
		return observation, err
	}
	assess, err := e.Verify(legacyID, end)
	if err != nil {
		return observation, err
	}
	pub := e.Assignment.AuthorityPublicKey
	if l.Role == Target {
		pub = e.Assignment.RemoteControlPublicKey
	}
	if !validKey(key, pub) {
		return observation, ErrPreparation
	}
	check := func() error {
		actual, err := l.LocationID()
		if err != nil || actual != placementID {
			return errors.Join(ErrPreparation, err)
		}
		return ctx.Err()
	}
	if err := check(); err != nil {
		return observation, err
	}
	capture := func() (captureErr error) {
		journal, _, err := workarchive.OpenExistingCustodyJournalWithLimits(ctx, l.Journal, e.Manifest, e.Initial, e.Policy, workarchive.DefaultCustodyJournalLimits())
		if err != nil {
			return err
		}
		decision, err := journal.AcquireDecision()
		if err != nil {
			return err
		}
		defer func() { captureErr = errors.Join(captureErr, decision.Close()) }()
		if err := check(); err != nil {
			return err
		}
		state, err := decision.State()
		if err != nil {
			return err
		}
		rid, _ := state.CurrentReceipt.ID()
		if state.Sequence != assess.SourceSequence || state.HeadEntryID != assess.SourceHeadID || rid != assess.ReceiptID || state.InitialReceipt != e.Initial || state.CurrentReceipt != assess.CurrentReceipt {
			return ErrEvidence
		}
		if len(e.Cycles) > 0 {
			head, exists, err := decision.Head()
			if err != nil || !exists {
				return errors.Join(ErrEvidence, err)
			}
			want, _ := e.Cycles[len(e.Cycles)-1].Terminal.Entry.CanonicalBytes()
			actual, _ := head.CanonicalBytes()
			if !bytes.Equal(want, actual) {
				return ErrEvidence
			}
		}
		eid, _ := e.ID()
		observation = Observation{Version: Version1, EvidenceID: eid, AssignmentID: legacyID, RetirementID: assess.RetirementID, SourceHeadID: assess.SourceHeadID, SourceSequence: assess.SourceSequence, ReceiptID: assess.ReceiptID, MinimumRetainUntil: assess.MinimumRetainUntil, Nonce: nonce, Role: l.Role, AnchorID: anchorID, PlacementCommitment: types.DomainHash(domain+"source-placement/commitment", nonce[:], placementID[:])}
		observation, err = observation.Sign(e, anchorID, key)
		if err != nil {
			return err
		}
		if err := check(); err != nil {
			return err
		}
		if err := retain(observation); err != nil {
			return err
		}
		return check()
	}
	returnErr = withSourceOwners(ctx, e, l, legacyID, capture)
	return observation, returnErr
}
func withSourceOwners(ctx context.Context, e Evidence, l SourceLocation, legacyID types.Hash, capture func() error) (returnErr error) {

	if l.Role == Authority {
		owner, err := s.OpenCoordinator(l.Authority, l.AuthorityPins, e.Assignment, legacyID)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
		returnErr = owner.WithConfirmedRetirement(ctx, e.End, MaximumHistoryEntries, func(assignment a.Assignment, history []a.Entry) error {
			if err := compareHistory(e, assignment, history); err != nil {
				return err
			}
			return capture()
		})
		return returnErr
	}
	if l.Role != Target || len(l.Workers) != len(e.Cycles) {
		return ErrPreparation
	}
	// The same fixed source order is used by every capture. Live B services own
	// worker before source; capture follows that order and exposes no callbacks
	// until all workers are validated and the original source decision is held.
	for i, path := range l.Workers {
		worker, err := w.Open(ctx, path, e.Scope(e.Cycles[i]).Worker)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, worker.Close()) }()
		state, err := worker.Snapshot(ctx)
		if err != nil {
			return err
		}
		if state.Stage != w.Sealed || state.Pending != 0 || state.Seal == nil || *state.Seal != e.Cycles[i].Terminal.Seal {
			return ErrBlocked
		}
	}
	returnErr = capture()
	return returnErr
}
