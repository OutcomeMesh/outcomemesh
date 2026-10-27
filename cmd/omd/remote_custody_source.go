package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func runRemoteCustodySource(ctx context.Context, args []string, output io.Writer) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review placement (default), create NEW local roots, or verify existing roots")
	role := f.String("role", "", "audit (A journal and artifacts) or serve (B journal only)")
	assignmentPath := f.String("assignment", "", "canonical V1 assignment")
	assignmentPin := f.String("assignment-id", "", "independent assignment ID")
	manifestPath := f.String("manifest", "", "canonical manifest")
	receiptPath := f.String("receipt", "", "initial receipt")
	journalPath := f.String("journal", "", "dedicated local source journal root with existing parent")
	artifactsPath := f.String("artifacts", "", "A only: dedicated local artifact root with existing parent")
	expected := f.String("expected-review-id", "", "create only: reviewed assignment, role, paths and limits")
	policyFlags := addArchiveCustodyPolicyFlags(f)
	limitFlags := addArchiveCustodyJournalLimitFlags(f)
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if *mode != "review" && *mode != "create" && *mode != "verify" {
		return errors.New("source mode must be review, create or verify")
	}
	if *role != "audit" && *role != "serve" {
		return errors.New("source role must be audit or serve")
	}
	if *role == "serve" && custodyCommandPresence(f)["artifacts"] {
		return errors.New("B source preparation cannot select A artifacts")
	}
	if *mode != "create" {
		if err := custodyCommandForbid(custodyCommandPresence(f), "expected-review-id"); err != nil {
			return err
		}
	}
	if err := errors.Join(policyFlags.validate(), limitFlags.limits().Validate()); err != nil {
		return err
	}
	id, err := managedCustodyExternalID("assignment-id", *assignmentPin)
	if err != nil {
		return err
	}
	files := []*string{assignmentPath, manifestPath, receiptPath}
	for _, p := range files {
		*p, err = custodyCommandFile(*p)
		if err != nil {
			return err
		}
	}
	a, err := loadPruneOfflineAssignment(*assignmentPath, id)
	if err != nil || a.Version != custodyauthority.Version1 {
		return errors.Join(errors.New("source requires a separately pinned V1 assignment"), err)
	}
	m, err := loadArchiveManifest(*manifestPath)
	if err != nil {
		return err
	}
	r, err := loadArchiveReplicaReceipt(*receiptPath)
	if err != nil {
		return err
	}
	policy := workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), a.Auditors...), MaximumChallengeLifetime: *policyFlags.challengeLifetime, MaximumProofAge: *policyFlags.proofAge, MaximumRenewalTerm: *policyFlags.renewalTerm}
	derived, err := workarchive.CreateRemoteCustodyAuthorityAssignment(m, r, policy, a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
	if err != nil {
		return err
	}
	actual, err := derived.ID()
	if err != nil || actual != id {
		return errors.Join(errors.New("source archive or policy differs from assignment"), err)
	}
	roots := []*string{journalPath}
	if *role == "audit" {
		roots = append(roots, artifactsPath)
	}
	for _, p := range roots {
		*p, err = remoteBootstrapRoot(*p)
		if err != nil {
			return err
		}
		for _, file := range files {
			if err := store.ValidateBootstrapPaths(*p, filepath.Dir(*file)); err != nil {
				return err
			}
		}
	}
	if len(roots) == 2 {
		if err := store.ValidateBootstrapPaths(*journalPath, *artifactsPath); err != nil {
			return err
		}
	}
	// Fixed path order and explicit limits are part of the creation comparison.
	review, err := remoteBootstrapReviewID("source/"+*role, id, types.Hash{}, types.Hash{}, []string{*journalPath, *artifactsPath, fmt.Sprintf("%d/%d", limitFlags.limits().MaximumBytes, limitFlags.limits().MaximumPaths)})
	if err != nil {
		return err
	}
	var state workarchive.CustodyJournalState
	if *mode != "review" {
		if err := ctx.Err(); err != nil {
			return err
		}
		if *mode == "create" {
			if err := remoteBootstrapExpected(*expected, review); err != nil {
				return err
			}
			// Preflight every selected destination before mutating any root.
			for _, p := range roots {
				if _, err := os.Lstat(*p); err == nil {
					return os.ErrExist
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			_, state, err = workarchive.CreateCustodyJournalWithLimits(ctx, *journalPath, m, r, policy, limitFlags.limits())
		} else {
			_, state, err = workarchive.OpenExistingCustodyJournalWithLimits(ctx, *journalPath, m, r, policy, limitFlags.limits())
		}
		if err != nil {
			return err
		}
		if *role == "audit" {
			var lock *os.File
			if *mode == "create" {
				lock, err = workarchive.CreateCustodyArtifacts(ctx, *artifactsPath)
			} else {
				lock, err = workarchive.OpenExistingCustodyArtifacts(ctx, *artifactsPath)
			}
			if err != nil {
				return err
			}
			if err := lock.Close(); err != nil {
				return err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var receiptID types.Hash
	if *mode != "review" {
		receiptID, err = state.CurrentReceipt.ID()
		if err != nil {
			return err
		}
	}
	return writePruneOutputLine(output, fmt.Sprintf("remote_custody_source mode=%s role=%s assignment_id=%s review_id=%s journal=%q artifacts=%q sequence=%d head_id=%s receipt_id=%s roots_inspected=%t owners_closed=true execution_authorized=false automatic_resume=false\n", *mode, *role, id, review, *journalPath, *artifactsPath, state.Sequence, state.HeadEntryID, receiptID, *mode != "review"))
}
