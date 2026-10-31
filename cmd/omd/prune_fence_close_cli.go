package main

import (
	"context"
	"flag"
	"io"
	"os"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
)

const pruneFenceCloseCommand = "work-prune-fence-close"

type pruneFenceCloseReport struct {
	PlanID              types.Hash `json:"plan_id"`
	IntentID            types.Hash `json:"intent_id"`
	ScopeID             types.Hash `json:"scope_id"`
	ClosureID           types.Hash `json:"closure_id"`
	ClosureVerified     bool       `json:"closure_verified"`
	ExecutionAuthorized bool       `json:"execution_authorized"`
	AccountingChanged   bool       `json:"accounting_changed"`
}

func runPruneFenceCloseCLI(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || out == nil {
		return prunefence.ErrFence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f := flag.NewFlagSet(pruneFenceCloseCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review, collect a closure quorum, or verify an existing artifact")
	planPath := f.String("plan", "", "original fenced scheduled plan")
	planID := f.String("plan-id", "", "independently retained plan ID")
	expected := f.String("expected-intent-id", "", "collect: previously reviewed closure intent ID")
	network := f.String("fence-network", "", "collect: original witness endpoints and transport pins")
	controller := f.String("controller-key", "", "collect: original policy controller seed")
	transport := f.String("fence-transport-key", "", "collect: client transport seed")
	timeout := f.Duration("fence-timeout", 5*time.Second, "collect: bounded time per witness exchange")
	destination := f.String("out", "", "collect: immutable closure artifact")
	closurePath := f.String("closure", "", "verify: existing closure artifact")
	closurePin := f.String("closure-id", "", "verify: independently retained closure ID")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	present := custodyCommandPresence(f)
	switch *mode {
	case "review":
		if err := custodyCommandForbid(present, "expected-intent-id", "fence-network", "controller-key", "fence-transport-key", "fence-timeout", "out", "closure", "closure-id"); err != nil {
			return err
		}
	case "collect":
		if err := custodyCommandForbid(present, "closure", "closure-id"); err != nil {
			return err
		}
	case "verify":
		if err := custodyCommandForbid(present, "expected-intent-id", "fence-network", "controller-key", "fence-transport-key", "fence-timeout", "out"); err != nil {
			return err
		}
	default:
		return prunefence.ErrFence
	}
	pin, err := pruneExternalID("plan-id", *planID)
	if err != nil {
		return err
	}
	plan, err := store.LoadScheduledPrunePlan(*planPath, pin)
	if err != nil {
		return err
	}
	scope, err := plan.FenceScope()
	if err != nil {
		return err
	}
	requestID, err := plan.Request.ID()
	if err != nil {
		return err
	}
	intent := prunefence.ClosureIntent{Policy: *plan.FencePolicy, AssignmentID: plan.Request.AssignmentID, RequestID: requestID}
	intentID, err := intent.ID()
	if err != nil {
		return err
	}
	scopeID, _ := scope.ID()
	report := pruneFenceCloseReport{PlanID: pin, IntentID: intentID, ScopeID: scopeID}
	verify := func(raw []byte) error {
		closure, err := prunefence.DecodeClosure(raw)
		if err != nil {
			return err
		}
		id, err := closure.Intent.ID()
		if err != nil || id != intentID {
			return prunefence.ErrFence
		}
		report.ClosureID, err = closure.ID()
		if err != nil {
			return err
		}
		report.ClosureVerified = true
		return nil
	}
	switch *mode {
	case "verify":
		expectedID, err := pruneExternalID("closure-id", *closurePin)
		if err != nil {
			return err
		}
		raw, err := readRegularArtifact(*closurePath, prunefence.MaximumClosureBytes)
		if err != nil {
			return err
		}
		if err := verify(raw); err != nil {
			return err
		}
		if report.ClosureID != expectedID {
			return prunefence.ErrFence
		}
	case "collect":
		expectedID, err := pruneExternalID("expected-intent-id", *expected)
		if err != nil || expectedID != intentID {
			return prunefence.ErrFence
		}
		if err := scheduledOperatorOutput(*destination, []string{*planPath, *network, *controller, *transport}, nil); err != nil {
			return err
		}
		// A retained matching artifact is an offline exact retry. No key or witness
		// is opened, and a different quorum cannot overwrite its original bytes.
		raw, err := readRegularArtifact(*destination, prunefence.MaximumClosureBytes)
		if err == nil {
			if err := verify(raw); err != nil {
				return err
			}
		} else {
			if !os.IsNotExist(err) {
				return err
			}
			client, err := openPruneFenceNetwork(ctx, scope, plan.FencePolicy.Controller, *network, *controller, *transport, *timeout)
			if err != nil {
				return err
			}
			defer client.close()
			proof, err := prunenet.CollectClosure(ctx, client.host, client.key, client.local, client.endpoints, client.timeout, intent)
			if err != nil {
				return err
			}
			raw, err = proof.CanonicalBytes()
			if err != nil {
				return err
			}
			if err := verify(raw); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := publishCustodyCommandArtifact(*destination, raw); err != nil {
				return err
			}
		}
	}
	return scheduledOperatorReport(ctx, out, report)
}
