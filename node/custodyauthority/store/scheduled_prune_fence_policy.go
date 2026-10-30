package store

import (
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
)

func scheduledPruneArtifactID(raw []byte, plan bool) types.Hash {
	name, version := "inventory", "v0"
	if plan {
		name = "plan"
	}
	if len(raw) >= 10 && raw[8] == 0 && raw[9] == 1 {
		version = "v1"
	}
	return types.DomainHash("OMESH/custody-prune/scheduled-"+name+"/id/"+version, raw)
}

func (v ScheduledPruneInventory) validateFencePolicy() error {
	if (v.FencePolicy == nil) != v.Request.FencePolicyID.IsZero() {
		return prunefence.ErrFence
	}
	if v.FencePolicy == nil {
		return nil
	}
	p := v.FencePolicy
	id, err := p.ID()
	if err != nil || id != v.Request.FencePolicyID || p.Owner != v.Request.ConsumerPublicKey {
		return prunefence.ErrFence
	}
	keys := append([][32]byte(nil), v.OriginalPolicy.TrustedAttestors...)
	keys = append(keys, v.ReplicaPolicy.TrustedReplicas...)
	for _, r := range v.Replicas {
		a := r.Assignment
		aid, err := a.ID()
		if err != nil {
			return err
		}
		if aid == v.Request.AssignmentID && p.Controller != a.AuthorityPublicKey {
			return prunefence.ErrFence
		}
		keys = append(keys, a.AuthorityPublicKey, a.ReplicaPublicKey, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
		keys = append(keys, a.Auditors...)
		for _, c := range a.Consumers {
			keys = append(keys, c.PublicKey)
		}
	}
	independent := append([][32]byte(nil), p.Witnesses...)
	if p.Guard != ([32]byte{}) {
		independent = append(independent, p.Guard)
	}
	for _, witness := range independent {
		for _, key := range keys {
			if witness == key {
				return prunefence.ErrFence
			}
		}
	}
	return nil
}

// WithFence selects the policy in a new plan before any admission. It cannot
// modify an inventory, a retained request or an already admitted operation.
func (p ScheduledPrunePlan) WithFence(policy prunefence.Policy) (ScheduledPrunePlan, error) {
	if _, err := p.ID(); err != nil {
		return ScheduledPrunePlan{}, err
	}
	if p.FencePolicy != nil {
		return ScheduledPrunePlan{}, prunefence.ErrFence
	}
	raw, err := policy.CanonicalBytes()
	if err != nil {
		return ScheduledPrunePlan{}, err
	}
	owned, err := prunefence.DecodePolicy(raw)
	if err != nil {
		return ScheduledPrunePlan{}, err
	}
	p.FencePolicy = &owned
	p.Request.FencePolicyID, _ = owned.ID()
	raw, err = p.CanonicalBytes()
	if err != nil {
		return ScheduledPrunePlan{}, err
	}
	return DecodeScheduledPrunePlan(raw)
}

func (p ScheduledPrunePlan) FenceScope() (custodyfence.Scope, error) {
	if _, err := p.ID(); err != nil {
		return custodyfence.Scope{}, err
	}
	if p.FencePolicy == nil {
		return custodyfence.Scope{}, prunefence.ErrFence
	}
	id, _ := p.Request.ID()
	return p.FencePolicy.Scope(p.Request.AssignmentID, id)
}
