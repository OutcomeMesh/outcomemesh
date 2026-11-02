//go:build linux || darwin

package pruneservice

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func (o *Owner) settlementConfig(ctx context.Context, q wire.Request, in SettlementInput) (store.ScheduledPruneCommandConfig, error) {
	var c store.ScheduledPruneCommandConfig
	if ctx == nil {
		return c, ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return c, err
	}
	if err := o.check(); err != nil {
		return c, err
	}
	if q.Authorize(o.descriptor) != nil || o.intent == nil || q != *o.intent {
		return c, ErrPosition
	}
	if in.PlanID.IsZero() || (in.DecisionPath == "") != in.DecisionID.IsZero() {
		return c, ErrPosition
	}
	for _, path := range []string{in.PlanPath, in.DecisionPath} {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || workarchive.CustodyEvidencePathsOverlap(o.root, path) {
			return c, ErrOwner
		}
	}
	plan, err := store.LoadScheduledPrunePlan(in.PlanPath, in.PlanID)
	if err != nil {
		return c, err
	}
	if err = plan.BindInventory(o.inventory); err != nil {
		return c, err
	}
	r := o.config.Runtime
	c = store.ScheduledPruneCommandConfig{PlanPath: in.PlanPath, PlanID: in.PlanID, AssignmentID: o.descriptor.Binding.AssignmentID, ExecutorPath: r.ExecutorPath, ExecutorPinsPath: r.ExecutorPinsPath, InventoryPath: filepath.Join(o.root, "inventory"), InventoryID: o.descriptor.Binding.InventoryID, PrepareSettlement: in.DecisionPath == "", SettlementPath: in.DecisionPath, SettlementID: in.DecisionID, Storage: &store.PruneRecoveryStorage{ChainPath: r.ChainPath, ChainPinsPath: r.ChainPinsPath, MigrationID: r.StorageMigrationID, Base: r.Base, Parameters: r.Parameters, Policy: r.StoragePolicy}}
	for _, a := range r.Authorities {
		if a.AssignmentID == c.AssignmentID {
			c.AuthorityPath, c.AuthorityPinsPath = a.AuthorityPath, a.AuthorityPinsPath
		}
	}
	for _, p := range []string{c.ExecutorPath, c.ExecutorPinsPath, c.AuthorityPath, c.AuthorityPinsPath, c.Storage.ChainPath, c.Storage.ChainPinsPath} {
		if err = privateTreeContext(ctx, p); err != nil {
			return c, err
		}
	}
	return c, nil
}

// ReviewSettlement opens original owners and observes the committed effect. It
// neither signs a proposal nor converts an unconfirmed transition into success.
func (o *Owner) ReviewSettlement(ctx context.Context, q wire.Request, in SettlementInput) (store.ScheduledPruneCommandResult, error) {
	if o == nil {
		return store.ScheduledPruneCommandResult{}, ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	c, err := o.settlementConfig(ctx, q, in)
	if err != nil {
		return store.ScheduledPruneCommandResult{}, err
	}
	return store.RunScheduledPruneCommand(ctx, c, "review", types.Hash{})
}

// Settle applies a full co-signed original-witness decision, then publishes the
// original confirmed settlement response. It cannot execute deletion or complete
// replica obligations. Interrupted core publication still requires its separate
// exact original-journal continuation before this method can succeed.
func (o *Owner) Settle(ctx context.Context, q wire.Request, in SettlementInput, expected types.Hash) (wire.Response, error) {
	if o == nil {
		return wire.Response{}, ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if in.DecisionID.IsZero() || expected.IsZero() {
		return wire.Response{}, ErrPosition
	}
	c, err := o.settlementConfig(ctx, q, in)
	if err != nil {
		return wire.Response{}, err
	}
	if _, err = store.RunScheduledPruneCommand(ctx, c, "settle-effect", expected); err != nil {
		return wire.Response{}, errors.Join(ErrHeld, err)
	}
	if err = o.hooks.reach("settlement-confirmed"); err != nil {
		return wire.Response{}, errors.Join(ErrHeld, err)
	}
	return o.withRetainedResponse(ctx, q, func(r wire.Response) (wire.Response, error) {
		if r.Settlement == nil {
			return wire.Response{}, ErrHeld
		}
		id, e := r.Settlement.ID()
		if e != nil || id != in.DecisionID {
			return wire.Response{}, ErrHeld
		}
		if len(o.response) > 0 {
			prior, e := wire.DecodeResponse(o.response)
			if e != nil || prior.Settlement == nil {
				return wire.Response{}, ErrHeld
			}
			pid, e := prior.Settlement.ID()
			if e != nil || pid != in.DecisionID {
				return wire.Response{}, ErrHeld
			}
			return prior, nil
		}
		return o.finish(q, r)
	})
}
