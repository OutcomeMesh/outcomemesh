package pruneservice

import "github.com/outcomemesh/outcomemesh/core/types"

// SettlementInput selects public evidence only. Original private placements
// always come from the immutable owner configuration.
type SettlementInput struct {
	PlanPath     string
	PlanID       types.Hash
	DecisionPath string
	DecisionID   types.Hash
}
