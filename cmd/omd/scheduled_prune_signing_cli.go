package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

// This boundary reads pinned artifacts and an explicit position. It never opens
// an owner, discovers a newer head, grants work or refreshes a receipt.
func runScheduledPruneSigningCLI(ctx context.Context, args []string, out io.Writer) error {
	cosign := args[0] == scheduledCosignCommand
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review or sign")
	planPath := f.String("plan", "", "canonical scheduled plan")
	planText := f.String("plan-id", "", "independently retained plan ID")
	assignmentText := f.String("assignment-id", "", "selected original assignment")
	kind := f.String("kind", "", "admit or complete")
	sequence := f.String("expected-sequence", "", "explicit reviewed sequence")
	headText := f.String("expected-head", "", "explicit reviewed head")
	inventoryPath := f.String("inventory", "", "Complete only: canonical inventory")
	inventoryText := f.String("inventory-id", "", "Complete only: independently retained inventory ID")
	effectPath := f.String("effect", "", "Complete only: exported canonical effect")
	effectText := f.String("effect-id", "", "Complete only: independently retained effect ID")
	cancellationPath := f.String("cancellation", "", "Complete only: exported pre-start cancellation")
	cancellationText := f.String("cancellation-id", "", "Complete only: independently retained cancellation ID")
	expected := f.String("expected-review-id", "", "sign mode: exact signature review ID")
	destination := f.String("out", "", "sign mode: immutable output artifact")
	keyName := "consumer-key"
	if cosign {
		keyName = "authority-key"
	}
	keyPath := f.String(keyName, "", "existing role-specific 32-byte seed")
	var commandPath string
	if cosign {
		f.StringVar(&commandPath, "command", "", "exact consumer-signed command")
	}
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	present := custodyCommandPresence(f)
	if *mode != "review" && *mode != "sign" {
		return store.ErrScheduledPrune
	}
	if *mode == "review" {
		if err := custodyCommandForbid(present, keyName, "expected-review-id", "out"); err != nil {
			return err
		}
	}
	if *mode == "sign" && (*keyPath == "" || *destination == "" || *expected == "") {
		return store.ErrScheduledPrune
	}
	planID, err := pruneExternalID("plan-id", *planText)
	if err != nil {
		return err
	}
	p, err := store.LoadScheduledPrunePlan(*planPath, planID)
	if err != nil {
		return err
	}
	aid, err := pruneExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	s, err := p.Replica(aid)
	if err != nil {
		return err
	}
	n, err := scheduledOperatorNumber(*sequence)
	if err != nil {
		return err
	}
	head, err := pruneExternalID("expected-head", *headText)
	if err != nil {
		return err
	}
	position := custodyauthority.Position{Sequence: n, HeadID: head}
	var draft custodyauthority.Command
	inputs := []string{*planPath, commandPath, *keyPath}
	switch *kind {
	case "admit":
		if err := custodyCommandForbid(present, "inventory", "inventory-id", "effect", "effect-id", "cancellation", "cancellation-id"); err != nil {
			return err
		}
		draft, err = store.BuildScheduledPruneAdmission(s.Assignment, s.Proof, p.OriginalPolicy, p.Request, position)
	case "complete":
		iid, e := pruneExternalID("inventory-id", *inventoryText)
		if e != nil {
			return e
		}
		inventory, e := store.LoadScheduledPruneInventory(*inventoryPath, iid)
		if e != nil {
			return e
		}
		path, idText, label, outcomeKind := *effectPath, *effectText, "effect-id", "effect"
		if present["cancellation"] || present["cancellation-id"] {
			if err := custodyCommandForbid(present, "effect", "effect-id"); err != nil {
				return err
			}
			path, idText, label, outcomeKind = *cancellationPath, *cancellationText, "cancellation-id", "cancellation"
		}
		eid, e := pruneExternalID(label, idText)
		if e != nil {
			return e
		}
		outcome, e := store.LoadScheduledPruneOutcome(path, outcomeKind, eid)
		if e != nil {
			return e
		}
		draft, err = store.BuildScheduledPruneOutcomeCompletion(p, inventory, outcome, aid, position)
		inputs = append(inputs, *inventoryPath, path)
	default:
		return store.ErrScheduledPrune
	}
	if err != nil {
		return err
	}
	review, err := custodyauthority.ScheduledPruneCommandReviewID(s.Assignment, draft)
	if err != nil {
		return err
	}
	command := draft
	if cosign {
		raw, err := readRegularArtifact(commandPath, custodyauthority.MaximumCommandBytes)
		if err != nil {
			return err
		}
		command, err = custodyauthority.DecodeCommand(raw)
		if err != nil {
			return err
		}
		unsigned := command
		unsigned.Signature = [64]byte{}
		if unsigned != draft {
			return custodyauthority.ErrPruneReview
		}
		review, err = custodyauthority.ScheduledPruneEntryReviewID(s.Assignment, command)
		if err != nil {
			return err
		}
	}
	var entryID types.Hash
	if *mode == "sign" {
		id, err := pruneExternalID("expected-review-id", *expected)
		if err != nil || id != review {
			return errors.Join(custodyauthority.ErrPruneReview, err)
		}
		if err := scheduledOperatorOutput(*destination, inputs, nil); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := loadPruneOfflineKey(*keyPath)
		if err != nil {
			return err
		}
		defer clear(key)
		var raw []byte
		if cosign {
			entry, err := custodyauthority.CosignReviewedScheduledPruneCommand(s.Assignment, command, review, key)
			if err != nil {
				return err
			}
			entryID, _ = entry.ID()
			raw, err = entry.CanonicalBytes()
			if err != nil {
				return err
			}
		} else {
			command, err = custodyauthority.SignReviewedScheduledPruneCommand(s.Assignment, draft, review, key)
			if err != nil {
				return err
			}
			raw, err = command.CanonicalBytes()
			if err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publishImmutableArtifact(*destination, raw); err != nil {
			return err
		}
		retained, err := readRegularArtifact(*destination, custodyauthority.MaximumEntryBytes)
		if err != nil || !bytes.Equal(retained, raw) {
			return errors.Join(store.ErrScheduledPrune, err)
		}
	}
	return scheduledOperatorReport(ctx, out, struct {
		PlanID, AssignmentID, ReviewID, EntryID types.Hash
		Draft                                   custodyauthority.Command
		Published                               bool
		ReviewIDText                            string `json:"review_id"`
		EntryIDText                             string `json:"entry_id"`
	}{planID, aid, review, entryID, draft, *mode == "sign", review.String(), entryID.String()})
}
