package store

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

// ValidatePruneRequest checks canonical request/assignment bindings and an
// externally retained ID. It performs no I/O and cannot attest availability,
// current authority, physical storage identity or actual executor preparation.
func ValidatePruneRequest(assignment custodyauthority.Assignment, request PruneRequest, expectedID types.Hash) error {
	return validatePruneRequest(assignment, request, expectedID)
}

// ValidatePruneRuntimePeers checks the command runtime's transport/control-key
// role separation without opening a host. It does not fence copied identities.
func ValidatePruneRuntimePeers(assignment custodyauthority.Assignment, self, remote types.Hash) error {
	return validatePruneRuntimePeers(assignment, self, remote)
}

// ValidateAdmissionIntent applies the same bounded static checks as outbox
// creation, without creating a journal or delivering the command. A caller that
// derives expectedID from these same bytes has checked consistency, not a pin.
func ValidateAdmissionIntent(assignment custodyauthority.Assignment, intent AdmissionIntent, expectedID types.Hash) error {
	return validateAdmissionIntent(assignment, intent, expectedID)
}

// ValidateCompletionIntent checks a supplied signed delivery intent, not the
// existence of its claimed terminal evidence or a current admission ticket.
func ValidateCompletionIntent(assignment custodyauthority.Assignment, intent CompletionIntent, expectedID types.Hash) error {
	return validateCompletionIntent(assignment, intent, expectedID)
}
