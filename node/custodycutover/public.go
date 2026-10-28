// Package custodycutover retains original-source observations and disabled preparations.
// Public encodings live in review so accounting can verify them without owner dependencies.
package custodycutover

import (
	"bytes"
	"crypto/ed25519"
	r "github.com/outcomemesh/outcomemesh/node/custodycutover/review"
)

const (
	Version1              = r.Version1
	MaximumCycles         = r.MaximumCycles
	MaximumHistoryEntries = r.MaximumHistoryEntries
	MaximumEvidenceBytes  = r.MaximumEvidenceBytes
	ObservationBytes      = r.ObservationBytes
	MaximumBlueprintBytes = r.MaximumBlueprintBytes
	MaximumProposalBytes  = r.MaximumProposalBytes
	Authority             = r.Authority
	Target                = r.Target
	domain                = "OMESH/custody-cutover-review/v1/"
)

var (
	ErrEvidence    = r.ErrEvidence
	ErrBlocked     = r.ErrBlocked
	ErrBudget      = r.ErrBudget
	ErrPreparation = r.ErrPreparation
)

type Cycle = r.Cycle
type Evidence = r.Evidence
type Assessment = r.Assessment
type Observation = r.Observation
type Role = r.Role
type Blueprint = r.Blueprint
type Proposal = r.Proposal
type Bridge = r.Bridge

func DecodeEvidence(b []byte) (Evidence, error)       { return r.DecodeEvidence(b) }
func DecodeObservation(b []byte) (Observation, error) { return r.DecodeObservation(b) }
func DecodeBlueprint(b []byte) (Blueprint, error)     { return r.DecodeBlueprint(b) }
func DecodeProposal(b []byte) (Proposal, error)       { return r.DecodeProposal(b) }
func validKey(k ed25519.PrivateKey, p [32]byte) bool {
	if len(k) != ed25519.PrivateKeySize {
		return false
	}
	d := ed25519.NewKeyFromSeed(k[:32])
	defer clear(d)
	return bytes.Equal(k, d) && bytes.Equal(p[:], d[32:])
}
