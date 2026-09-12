package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

const (
	pruneAdmissionPrepareCommand  = "work-prune-admission-prepare"
	pruneCompletionPrepareCommand = "work-prune-completion-prepare"
)

// Preparation never owns a signer, transport or server journal. A reviewed
// command is historical input, not proof that a server can accept or execute it.
func runPruneOutboxPrepare(ctx context.Context, arguments []string, output io.Writer) (err error) {
	if ctx == nil || output == nil || len(arguments) == 0 {
		return errors.New("outbox preparation needs a context, output and explicit command")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	name := arguments[0]
	admission := name == pruneAdmissionPrepareCommand
	if !admission && name != pruneCompletionPrepareCommand {
		return errors.New("unsupported outbox preparation command")
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review without writes, create a new outbox, or verify an existing outbox")
	assignmentPath := flags.String("assignment", "", "trusted canonical assignment file (required)")
	assignmentText := flags.String("assignment-id", "", "independently retained assignment ID (required)")
	entryPath := flags.String("entry", "", "canonical already co-signed entry file (required)")
	entryText := flags.String("entry-id", "", "independently retained co-signed entry ID (required)")
	clientText := flags.String("client-peer-id", "", "independently pinned client transport identity (required)")
	serverText := flags.String("server-peer-id", "", "independently pinned server transport identity (required)")
	outboxPath := flags.String("outbox", "", "typed outbox path, only for create or verify")
	intentText := flags.String("intent-id", "", "independently reviewed intent ID, required for create or verify")
	if err := parsePruneFlags(flags, arguments[1:]); err != nil {
		return err
	}
	if *mode != "review" && *mode != "create" && *mode != "verify" {
		return errors.New("outbox mode must be review, create or verify")
	}
	if *mode == "review" {
		writeFlags := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "outbox" || f.Name == "intent-id" {
				writeFlags = true
			}
		})
		if writeFlags {
			return errors.New("review does not accept outbox or intent-id; retain the reviewed ID independently before create or verify")
		}
	} else if *outboxPath == "" || *intentText == "" {
		return errors.New("create and verify require an outbox path and independently reviewed intent-id")
	}
	if *assignmentPath == "" || *entryPath == "" {
		return errors.New("assignment and co-signed entry files are required")
	}
	assignmentID, err := pruneExternalID("assignment-id", *assignmentText)
	if err != nil {
		return err
	}
	entryID, err := pruneExternalID("entry-id", *entryText)
	if err != nil {
		return err
	}
	clientID, err := pruneExternalID("client-peer-id", *clientText)
	if err != nil {
		return err
	}
	serverID, err := pruneExternalID("server-peer-id", *serverText)
	if err != nil {
		return err
	}
	assignment, err := loadPruneOfflineAssignment(*assignmentPath, assignmentID)
	if err != nil {
		return err
	}
	if err := validatePruneOfflinePeers(assignment, clientID, serverID); err != nil {
		return err
	}
	encoded, err := readRegularArtifact(*entryPath, custodyauthority.MaximumEntryBytes)
	if err != nil {
		return fmt.Errorf("read co-signed entry: %w", err)
	}
	entry, err := custodyauthority.DecodeEntry(encoded)
	if err != nil {
		return err
	}
	if actualID, err := entry.ID(); err != nil || actualID != entryID {
		return errors.Join(custodyauthority.ErrEntry, err)
	}
	admitIntent := authoritystore.AdmissionIntent{ClientPeerID: clientID, ServerPeerID: serverID, Entry: entry}
	completeIntent := authoritystore.CompletionIntent{ClientPeerID: clientID, ServerPeerID: serverID, Entry: entry}
	var intentID types.Hash
	if admission {
		intentID, err = admitIntent.ID()
	} else {
		intentID, err = completeIntent.ID()
	}
	if err != nil {
		return err
	}
	if admission {
		err = authoritystore.ValidateAdmissionIntent(assignment, admitIntent, intentID)
	} else {
		err = authoritystore.ValidateCompletionIntent(assignment, completeIntent, intentID)
	}
	if err != nil {
		return err
	}
	if *mode != "review" {
		expectedID, err := pruneExternalID("intent-id", *intentText)
		if err != nil {
			return err
		}
		if expectedID != intentID {
			return errors.New("intent-id does not match the exact reviewed entry and transport pins")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var receipt bool
	var nonce types.Hash
	if *mode != "review" {
		if admission {
			receipt, nonce, err = retainPreparedAdmission(*mode, *outboxPath, assignment, admitIntent, intentID)
		} else {
			receipt, nonce, err = retainPreparedCompletion(*mode, *outboxPath, assignment, completeIntent, intentID)
		}
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err // a retained outbox is preserved for explicit verification
	}
	// All owned journals are closed before printing. A failed stdout write can
	// follow committed creation; leave that root intact for explicit verify.
	c := entry.Command
	_, err = fmt.Fprintf(output, "work_prune_outbox command=%s mode=%s assignment_id=%s network_id=%d genesis_id=%s activation_height=%d base_id=%s manifest_id=%s statement_id=%s initial_receipt_id=%s custody_policy_id=%s incarnation_id=%s entry_id=%s intent_id=%s client_peer_id=%s server_peer_id=%s kind=%d purpose=%d expected_sequence=%d expected_head=%s operation_id=%s ticket_id=%s evidence_id=%s actor_public_key=%x authority_public_key=%x outbox_created=%t outbox_verified=%t receipt_present=%t receipt_nonce=%s historical_only=true sent=false execution_authorized=false terminal_state_verified=false current_head_verified=false automatic_retry=false\n",
		name, *mode, assignmentID, assignment.NetworkID, assignment.GenesisID, assignment.ActivationHeight, assignment.BaseID, assignment.ManifestID, assignment.StatementID, assignment.InitialReceiptID, assignment.CustodyPolicyID, assignment.IncarnationID,
		entryID, intentID, clientID, serverID, c.Kind, c.Purpose, c.ExpectedSequence, c.ExpectedHead, c.OperationID, c.TicketID, c.EvidenceID, c.ActorPublicKey, entry.AuthorityPublicKey,
		*mode == "create", *mode != "review", receipt, nonce)
	return err
}

func retainPreparedAdmission(mode, path string, assignment custodyauthority.Assignment, intent authoritystore.AdmissionIntent, id types.Hash) (receipt bool, nonce types.Hash, err error) {
	var outbox *authoritystore.AdmissionOutbox
	if mode == "create" {
		outbox, err = authoritystore.CreateAdmissionOutbox(path, assignment, intent, id)
	} else {
		outbox, err = authoritystore.OpenAdmissionOutbox(path, assignment, id)
	}
	if err != nil {
		return false, types.Hash{}, err
	}
	defer func() { err = errors.Join(err, outbox.Close()) }()
	snapshot, err := outbox.Snapshot()
	if err != nil {
		return false, types.Hash{}, err
	}
	if snapshot.IntentID != id || snapshot.Intent != intent {
		return false, types.Hash{}, authoritystore.ErrAdmissionIntent
	}
	if snapshot.Acknowledgement != nil {
		return true, snapshot.Acknowledgement.Nonce, nil
	}
	return false, types.Hash{}, nil
}

func retainPreparedCompletion(mode, path string, assignment custodyauthority.Assignment, intent authoritystore.CompletionIntent, id types.Hash) (receipt bool, nonce types.Hash, err error) {
	var outbox *authoritystore.CompletionOutbox
	if mode == "create" {
		outbox, err = authoritystore.CreateCompletionOutbox(path, assignment, intent, id)
	} else {
		outbox, err = authoritystore.OpenCompletionOutbox(path, assignment, id)
	}
	if err != nil {
		return false, types.Hash{}, err
	}
	defer func() { err = errors.Join(err, outbox.Close()) }()
	snapshot, err := outbox.Snapshot()
	if err != nil {
		return false, types.Hash{}, err
	}
	if snapshot.IntentID != id || snapshot.Intent != intent {
		return false, types.Hash{}, authoritystore.ErrCompletionIntent
	}
	if snapshot.Acknowledgement != nil {
		return true, snapshot.Acknowledgement.Nonce, nil
	}
	return false, types.Hash{}, nil
}
