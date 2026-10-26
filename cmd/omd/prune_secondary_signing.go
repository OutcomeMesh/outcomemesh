package main

import (
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

// Offline signing precedes inventory assembly: a prepared inventory already
// contains the co-signed candidates. Independently pin both original assignments
// and retain the PRIMARY request bytes/ID while choosing the secondary consumer
// operation. This checks historical scope, never admission or complete-set policy.
func validatePruneSecondarySigningScope(primary, secondary custodyauthority.Assignment,
	request authoritystore.PruneRequest, requestID types.Hash,
) error {
	if err := validatePruneOfflineRequest(primary, request, requestID); err != nil {
		return err
	}
	primaryID, err := primary.ID()
	if err != nil {
		return err
	}
	secondaryID, err := secondary.ID()
	if err != nil || primaryID == secondaryID || primary.ReplicaPublicKey == secondary.ReplicaPublicKey || primary.NetworkID != secondary.NetworkID ||
		primary.GenesisID != secondary.GenesisID || primary.ActivationHeight != secondary.ActivationHeight ||
		primary.BaseID != secondary.BaseID || primary.ManifestID != secondary.ManifestID || primary.StatementID != secondary.StatementID {
		return errors.Join(custodyauthority.ErrAssignment, err)
	}
	for _, consumer := range secondary.Consumers {
		if consumer.PublicKey == request.ConsumerPublicKey && consumer.Purposes&custodyauthority.Prune != 0 {
			return nil
		}
	}
	return custodyauthority.ErrActor
}

func validatePruneSecondarySigningAdmission(assignment custodyauthority.Assignment, request authoritystore.PruneRequest,
	requestID types.Hash, admission custodyauthority.Entry, expectedID types.Hash,
) error {
	aid, err := assignment.ID()
	if err != nil {
		return err
	}
	id, err := admission.ID()
	c := admission.Command
	if err != nil || expectedID.IsZero() || id != expectedID || admission.AuthorityPublicKey != assignment.AuthorityPublicKey ||
		c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Prune || c.AssignmentID != aid ||
		c.ActorPublicKey != request.ConsumerPublicKey || c.OperationID != requestID {
		return errors.Join(custodyauthority.ErrOperation, err)
	}
	_, err = custodyauthority.PruneEntryReviewID(assignment, c)
	return err
}
