package workarchive

import (
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// CreateCustodyAuthorityAssignment binds the reference admission machine to
// one exact archive/initial receipt and its verified custody policy. Consumer
// control keys must be separate from all evidence keys and the authority key.
// It creates no store, service, current-authority proof, receipt or activation.
// The caller must independently review/pin the assignment's ID and consumer list;
// this constructor cannot establish deployment-wide consumer completeness.
func CreateCustodyAuthorityAssignment(manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
	incarnationID types.Hash, authority [ed25519.PublicKeySize]byte, consumers []custodyauthority.Consumer,
	maximumOperations uint32, maximumPending uint16,
) (custodyauthority.Assignment, error) {
	if err := validateCustodySessionInputs(manifest, initial, policy, DefaultCustodySessionConfig()); err != nil {
		return custodyauthority.Assignment{}, err
	}
	manifestID, err := manifest.ID()
	if err != nil {
		return custodyauthority.Assignment{}, err
	}
	receiptID, err := initial.ID()
	if err != nil {
		return custodyauthority.Assignment{}, err
	}
	policyID, err := custodyJournalPolicyID(policy)
	if err != nil {
		return custodyauthority.Assignment{}, err
	}
	binding := initial.Binding
	assignment := custodyauthority.Assignment{Version: custodyauthority.Version0, NetworkID: binding.NetworkID,
		GenesisID: binding.GenesisID, ActivationHeight: binding.ActivationHeight, BaseID: binding.BaseID,
		ManifestID: manifestID, StatementID: initial.StatementID, InitialReceiptID: receiptID, CustodyPolicyID: policyID,
		IncarnationID: incarnationID, AuthorityPublicKey: authority, ReplicaPublicKey: initial.ReplicaPublicKey,
		Auditors:  append([][ed25519.PublicKeySize]byte(nil), policy.TrustedAuditors...),
		Consumers: append([]custodyauthority.Consumer(nil), consumers...), MaximumOperations: maximumOperations, MaximumPending: maximumPending}
	if _, err := assignment.ID(); err != nil {
		return custodyauthority.Assignment{}, err
	}
	return assignment, nil
}
