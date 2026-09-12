package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

const (
	pruneSigningCommand   = "work-prune-command-sign"
	pruneCosigningCommand = "work-prune-command-cosign"
)

// runPruneSigning only reads explicitly pinned historical artifacts and signs
// one reviewed message. It never opens an authority journal, executor, WorkChain
// or network host, and never determines or refreshes the authority's current head.
func runPruneSigning(ctx context.Context, arguments []string, output io.Writer) (err error) {
	if ctx == nil || output == nil || len(arguments) == 0 {
		return errors.New("prune signing needs context, output and an explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name := arguments[0]
	cosigning := name == pruneCosigningCommand
	if !cosigning && name != pruneSigningCommand {
		return errors.New("unsupported prune signing command")
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review (default) or sign")
	assignmentPath := flags.String("assignment", "", "canonical assignment file")
	assignmentText := flags.String("assignment-id", "", "independently retained assignment ID")
	requestPath := flags.String("request", "", "canonical storage-bound prune request file")
	requestText := flags.String("request-id", "", "independently retained request ID")
	kindText := flags.String("kind", "", "admit or complete")
	sequenceText := flags.String("expected-sequence", "", "explicit reviewed sequence, including zero")
	headText := flags.String("expected-head", "", "explicit reviewed history head, never refreshed")
	admissionPath := flags.String("admission", "", "Complete only: canonical co-signed admission")
	admissionText := flags.String("admission-id", "", "Complete only: independently retained admission entry ID")
	terminalPath := flags.String("terminal", "", "Complete only: canonical cancellation or effect")
	terminalText := flags.String("terminal-id", "", "Complete only: independently retained evidence ID")
	expectedReviewText := flags.String("expected-review-id", "", "sign mode only: independently reviewed signature message ID")
	outPath := flags.String("out", "", "sign mode only: immutable canonical output artifact")
	keyName := "consumer-key"
	if cosigning {
		keyName = "authority-key"
	}
	keyPath := flags.String(keyName, "", "sign mode only: existing 32-byte Ed25519 seed")
	var commandPath string
	if cosigning {
		flags.StringVar(&commandPath, "command", "", "exact consumer-signed canonical command")
	}
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	present := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { present[f.Name] = true })
	if *mode != "review" && *mode != "sign" {
		return errors.New("prune signing mode must be review or sign")
	}
	if *mode == "review" && (present[keyName] || present["out"] || present["expected-review-id"]) {
		return errors.New("review mode forbids key, output and expected-review-id flags, including empty values")
	}
	if *mode == "sign" && (*keyPath == "" || *outPath == "" || *expectedReviewText == "") {
		return errors.New("sign mode requires a role-specific key, expected-review-id and immutable output path")
	}
	if *assignmentPath == "" || *requestPath == "" || *sequenceText == "" || (cosigning && commandPath == "") {
		return errors.New("assignment, request, explicit sequence and (for co-signing) command are required")
	}
	assignmentID, err := pruneExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	requestID, err := pruneExternalID("request-id", *requestText)
	if err != nil {
		return err
	}
	headID, err := pruneExternalID("expected-head", *headText)
	if err != nil {
		return err
	}
	sequence, err := strconv.ParseUint(*sequenceText, 10, 64)
	if err != nil || strconv.FormatUint(sequence, 10) != *sequenceText {
		return errors.New("expected-sequence must be an explicit canonical nonnegative decimal integer")
	}
	assignment, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return err
	}
	encoded, err := readRegularArtifact(*requestPath, authoritystore.MaximumPruneRequestBytes)
	if err != nil {
		return fmt.Errorf("read prune request: %w", err)
	}
	request, err := authoritystore.DecodePruneRequest(encoded)
	if err != nil {
		return err
	}
	if err := validatePruneOfflineRequest(assignment, request, requestID); err != nil {
		return err
	}
	draft := custodyauthority.Command{Version: custodyauthority.Version0, AssignmentID: assignmentID,
		ExpectedSequence: sequence, ExpectedHead: headID, ActorPublicKey: request.ConsumerPublicKey}
	terminalKind := "none"
	var terminalBinding types.Hash
	switch *kindText {
	case "admit":
		for _, name := range []string{"admission", "admission-id", "terminal", "terminal-id"} {
			if present[name] {
				return errors.New("admit forbids completion evidence flags, including empty values")
			}
		}
		draft.Kind, draft.Purpose, draft.OperationID = custodyauthority.Admit, custodyauthority.Prune, requestID
	case "complete":
		admissionID, err := pruneExternalID("admission-id", *admissionText)
		if err != nil {
			return err
		}
		terminalID, err := pruneExternalID("terminal-id", *terminalText)
		if err != nil {
			return err
		}
		if *admissionPath == "" || *terminalPath == "" {
			return errors.New("complete requires independently pinned admission and terminal artifacts")
		}
		admissionBytes, err := readRegularArtifact(*admissionPath, custodyauthority.MaximumEntryBytes)
		if err != nil {
			return err
		}
		admission, err := custodyauthority.DecodeEntry(admissionBytes)
		if err != nil {
			return err
		}
		if err := validatePruneSigningAdmission(assignment, request, requestID, admission, admissionID); err != nil {
			return err
		}
		// If this completion immediately follows its admission, only that
		// ticket can be the head. A later sequence cannot reuse the old head.
		if sequence <= admission.Command.ExpectedSequence ||
			(sequence == admission.Command.ExpectedSequence+1) != (headID == admissionID) {
			return custodyauthority.ErrHead
		}
		terminalBytes, err := readRegularArtifact(*terminalPath, workchain.MaximumCanonicalPruneEffectBytes)
		if err != nil {
			return err
		}
		terminalKind, terminalBinding, err = validatePruneSigningTerminal(request, requestID, admissionID, terminalID, terminalBytes)
		if err != nil {
			return err
		}
		draft.Kind, draft.TicketID, draft.EvidenceID = custodyauthority.Complete, admissionID, terminalID
	default:
		return errors.New("prune signing kind must be admit or complete")
	}
	commandReviewID, err := custodyauthority.PruneCommandReviewID(assignment, draft)
	if err != nil {
		return err
	}
	reviewID := commandReviewID
	command := draft
	if cosigning {
		commandBytes, err := readRegularArtifact(commandPath, custodyauthority.MaximumCommandBytes)
		if err != nil {
			return err
		}
		command, err = custodyauthority.DecodeCommand(commandBytes)
		if err != nil {
			return err
		}
		unsigned := command
		unsigned.Signature = [64]byte{}
		if unsigned != draft {
			return custodyauthority.ErrPruneReview
		}
		reviewID, err = custodyauthority.PruneEntryReviewID(assignment, command)
		if err != nil {
			return err
		}
	}
	var entryID types.Hash
	if *mode == "sign" {
		expectedReviewID, err := pruneExternalID("expected-review-id", *expectedReviewText)
		if err != nil || expectedReviewID != reviewID {
			return errors.Join(custodyauthority.ErrPruneReview, err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// All artifact/pin/role/evidence checks precede the first key read.
		key, err := loadPruneOfflineKey(*keyPath)
		if err != nil {
			return err
		}
		var signed []byte
		if cosigning {
			entry, err := custodyauthority.CosignReviewedPruneCommand(assignment, command, expectedReviewID, key)
			if err != nil {
				return err
			}
			signed, err = entry.CanonicalBytes()
			if err != nil {
				return err
			}
			entryID, err = entry.ID()
			if err != nil {
				return err
			}
		} else {
			command, err = custodyauthority.SignReviewedPruneCommand(assignment, draft, expectedReviewID, key)
			if err != nil {
				return err
			}
			signed, err = command.CanonicalBytes()
			if err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publishImmutableArtifact(*outPath, signed); err != nil {
			return err
		}
	}
	// An output error after publication never erases the artifact or signs a
	// replacement. Repeating this exact review can recover identical bytes.
	_, err = fmt.Fprintf(output, "work_prune_signing command=%s mode=%s kind=%s assignment_id=%s request_id=%s storage_id=%s expected_sequence=%d expected_head=%s purpose=%d operation_id=%s ticket_id=%s evidence_id=%s actor_public_key=%x authority_public_key=%x terminal_kind=%s terminal_binding_id=%s command_review_id=%s review_id=%s entry_id=%s artifact_published=%t historical_only=true terminal_durability_proven=false execution_authorized=false\n",
		name, *mode, *kindText, assignmentID, requestID, request.StorageID, sequence, headID, draft.Purpose, draft.OperationID, draft.TicketID,
		draft.EvidenceID, draft.ActorPublicKey, assignment.AuthorityPublicKey, terminalKind, terminalBinding, commandReviewID, reviewID, entryID, *mode == "sign")
	return err
}

func validatePruneSigningAdmission(assignment custodyauthority.Assignment, request authoritystore.PruneRequest, requestID types.Hash, admission custodyauthority.Entry, expectedID types.Hash) error {
	id, err := admission.ID()
	c := admission.Command
	if err != nil || expectedID.IsZero() || id != expectedID || admission.AuthorityPublicKey != assignment.AuthorityPublicKey ||
		c.Kind != custodyauthority.Admit || c.Purpose != custodyauthority.Prune || c.AssignmentID != request.AssignmentID ||
		c.ActorPublicKey != request.ConsumerPublicKey || c.OperationID != requestID {
		return errors.Join(custodyauthority.ErrOperation, err)
	}
	_, err = custodyauthority.PruneEntryReviewID(assignment, c)
	return err
}

func validatePruneSigningTerminal(request authoritystore.PruneRequest, requestID, ticketID, expectedID types.Hash, encoded []byte) (string, types.Hash, error) {
	if cancellation, err := authoritystore.DecodePruneCancellation(encoded); err == nil {
		id, err := cancellation.ID()
		if err != nil || id != expectedID || cancellation.AssignmentID != request.AssignmentID ||
			cancellation.RequestID != requestID || cancellation.TicketID != ticketID {
			return "", types.Hash{}, custodyauthority.ErrOperation
		}
		// BindingID is committed by the independent terminal ID, but these
		// supplied bytes do not prove the executor durably chose cancellation.
		return "cancelled", cancellation.BindingID, nil
	}
	effect, err := workchain.DecodeCanonicalPruneEffect(encoded)
	if err != nil {
		return "", types.Hash{}, err
	}
	id, err := effect.ID()
	left, leftErr := request.Boundary.CanonicalBytes()
	right, rightErr := effect.Operation.Boundary.CanonicalBytes()
	if err != nil || id != expectedID || effect.Operation.AssignmentID != request.AssignmentID ||
		effect.Operation.TicketID != ticketID || effect.Operation.StorageID != request.StorageID ||
		leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
		return "", types.Hash{}, custodyauthority.ErrOperation
	}
	return "succeeded", types.Hash{}, nil
}
