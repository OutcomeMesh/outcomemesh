package main

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func runPruneServiceSettlement(ctx context.Context, a pruneServiceCLIFlags, did types.Hash, p wire.Position, q wire.Request) (_ []byte, returnErr error) {
	planID, err := pruneExternalID("plan-id", a.PlanID)
	if err != nil {
		return nil, err
	}
	in := service.SettlementInput{PlanPath: a.Plan, PlanID: planID, DecisionPath: a.Settlement}
	if a.Settlement != "" {
		in.DecisionID, err = pruneExternalID("settlement-id", a.SettlementID)
		if err != nil {
			return nil, err
		}
	}
	owner, err := service.Open(ctx, a.Root, did, p, &q)
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
	if a.Action == "settlement-review" {
		r, e := owner.ReviewSettlement(ctx, q, in)
		if e != nil {
			return nil, e
		}
		if a.ProposalOut != "" {
			if r.Proposal == nil {
				return nil, service.ErrHeld
			}
			raw, e := r.Proposal.CanonicalBytes()
			if e != nil {
				return nil, e
			}
			if e = publishCustodyCommandArtifact(a.ProposalOut, raw); e != nil {
				return nil, e
			}
		}
		return json.Marshal(r)
	}
	expected, err := pruneExternalID("settlement-review-id", a.SettlementReviewID)
	if err != nil {
		return nil, err
	}
	r, err := owner.Settle(ctx, q, in, expected)
	if err != nil {
		return nil, err
	}
	return r.CanonicalBytes()
}
