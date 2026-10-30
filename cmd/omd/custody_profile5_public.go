package main

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func profile5PublicCommand(p v2.ProtectedCommand) any {
	var sid, bid, did types.Hash
	if p.Kind != v2.ProtectedEndorse && len(p.Admission.Chain) > 0 {
		c := p.Admission.Chain[len(p.Admission.Chain)-1].Entry.Context
		scope, _ := c.Scope()
		sid, _ = scope.ID()
		bid, _ = p.Admission.ID()
		if c.Plan.Deployment != nil {
			did, _ = c.Plan.Deployment.ID()
		}
	}
	return struct {
		Kind                             uint8
		ScopeID, BindingID, DeploymentID types.Hash
		RequestTime                      uint64
		ServerClockAuthoritative         bool
		EvidenceReadOnly                 bool
	}{p.Kind, sid, bid, did, p.Now, true, v2.ProtectedEvidenceRead(p.Kind)}
}
