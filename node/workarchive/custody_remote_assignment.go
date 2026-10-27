package workarchive

import (
	"crypto/ed25519"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// CreateRemoteCustodyAuthorityAssignment explicitly selects a fresh version-1
// operational assignment. Its separately pinned remote control and transport
// keys do not alter the replica's receipt/proof identity. This creates no owner,
// enrollment, execution permission, network session or successor to a used
// version-0 assignment. Operators must retain the resulting new assignment ID.
func CreateRemoteCustodyAuthorityAssignment(manifest Manifest, initial ReplicaReceipt, policy CustodyPolicy,
	incarnationID types.Hash, authority [ed25519.PublicKeySize]byte, consumers []custodyauthority.Consumer,
	maximumOperations uint32, maximumPending uint16,
	remoteControl, remoteTransport [ed25519.PublicKeySize]byte,
) (custodyauthority.Assignment, error) {
	local, err := CreateCustodyAuthorityAssignment(manifest, initial, policy, incarnationID, authority, consumers,
		maximumOperations, maximumPending)
	if err != nil {
		return custodyauthority.Assignment{}, err
	}
	return custodyauthority.WithRemoteParticipant(local, remoteControl, remoteTransport)
}
