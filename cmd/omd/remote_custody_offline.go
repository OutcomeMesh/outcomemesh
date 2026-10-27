package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remoteworker"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const (
	remoteCustodyAssignmentCommand         = "work-archive-custody-remote-assignment"
	remoteCustodyPlanCommand               = "work-archive-custody-remote-plan"
	remoteCustodySignCommand               = "work-archive-custody-remote-command-sign"
	remoteCustodyCosignCommand             = "work-archive-custody-remote-command-cosign"
	remoteCustodyWorkerPrepareCommand      = "work-archive-custody-remote-worker-prepare"
	remoteCustodyAuthorityBootstrapCommand = "work-archive-custody-remote-authority-bootstrap"
)

func runRemoteCustodyOffline(ctx context.Context, args []string, output io.Writer) error {
	switch args[0] {
	case remoteCustodyAssignmentCommand:
		return runRemoteCustodyAssignment(ctx, args, output)
	case remoteCustodyPlanCommand, remoteCustodyWorkerPrepareCommand:
		return runRemoteCustodyPreparation(ctx, args, output)
	case remoteCustodySignCommand, remoteCustodyCosignCommand:
		return runRemoteCustodySigning(ctx, args, output)
	case remoteCustodyAuthorityBootstrapCommand:
		return runRemoteCustodyAuthorityBootstrap(ctx, args, output)
	}
	return errors.New("unsupported remote offline command")
}

func remoteOfflinePosition(sequence, head string) (custodyauthority.Position, error) {
	n, err := strconv.ParseUint(sequence, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != sequence {
		return custodyauthority.Position{}, errors.New("expected-sequence requires an explicit canonical nonnegative decimal")
	}
	h, err := managedCustodyExternalID("expected-head", head)
	return custodyauthority.Position{Sequence: n, HeadID: h}, err
}

func remoteOfflinePlan(path, pin string) (remoteworker.Plan, string, error) {
	var p remoteworker.Plan
	id, err := managedCustodyExternalID("plan-id", pin)
	if err != nil {
		return p, "", err
	}
	file, err := custodyCommandFile(path)
	if err != nil {
		return p, "", err
	}
	b, err := readRegularArtifact(file, remoteworker.MaximumPlanBytes)
	if err != nil {
		return p, "", err
	}
	p, err = remoteworker.DecodePlan(b)
	if err != nil {
		return p, "", err
	}
	actual, err := p.ID()
	if err != nil || actual != id {
		return p, "", errors.Join(errors.New("plan differs from its independently retained ID"), err)
	}
	return p, file, nil
}

func remoteOfflineScope(scope store.CustodyCommandScope, plan remoteworker.Plan, begin custodyauthority.Entry, challenge workarchive.CustodyChallenge) (store.RemoteCustodyScope, error) {
	if err := store.ValidateRemoteCustodyPlan(scope, plan, challenge); err != nil {
		return store.RemoteCustodyScope{}, err
	}
	pid, _ := plan.ID()
	bid, err := begin.ID()
	if err != nil {
		return store.RemoteCustodyScope{}, err
	}
	s := store.RemoteCustodyScope{Worker: remoteworker.Config{Assignment: scope.Assignment, Plan: plan, PlanID: pid, Begin: begin, BeginID: bid},
		Manifest: scope.Manifest, InitialReceipt: scope.InitialReceipt, PreviousReceipt: scope.PreviousReceipt,
		CustodyPolicy: scope.CustodyPolicy, Challenge: challenge}
	return s, store.ValidateRemoteCustodyScope(s)
}

func runRemoteCustodySigning(ctx context.Context, args []string, output io.Writer) error {
	cosign := args[0] == remoteCustodyCosignCommand
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	common := addCustodyCommandScopeFlags(f)
	mode := f.String("mode", "review", "review (default), or sign")
	kind := f.String("kind", "", "admit, begin, or complete; Drained is emitted only by the live sealed B runtime")
	purposeText := f.String("purpose", "", "audit or serve; Begin requires serve")
	sequence := f.String("expected-sequence", "", "explicit fixed authority sequence")
	head := f.String("expected-head", "", "independently retained fixed authority head")
	actor := f.String("consumer-public-key", "", "Admit only: selected consumer control public key")
	challengePath := f.String("challenge", "", "signed challenge, required except for Audit Admit")
	challengePin := f.String("challenge-id", "", "independent signed challenge ID")
	planPath := f.String("plan", "", "Begin/Complete: immutable plan")
	planPin := f.String("plan-id", "", "independent plan ID")
	beginPath := f.String("begin", "", "Complete only: original co-signed Begin")
	beginPin := f.String("begin-id", "", "independent Begin ID")
	admissionPath := f.String("admission", "", "Complete only: selected Audit or Serve admission")
	admissionPin := f.String("admission-id", "", "independent selected ticket ID")
	terminalPath := f.String("terminal", "", "Complete only: accepted remote terminal")
	terminalPin := f.String("terminal-id", "", "independent accepted terminal ID")
	commandPath := f.String("command", "", "co-sign only: exact actor-signed canonical command")
	reviewPin := f.String("expected-review-id", "", "sign only: exact reviewed signature message")
	outPath := f.String("out", "", "sign only: immutable output in an existing parent")
	keyName := "actor-key"
	if cosign {
		keyName = "authority-key"
	}
	keyPath := f.String(keyName, "", "sign only: existing role-specific 32-byte seed file")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	present := custodyCommandPresence(f)
	if *mode != "review" && *mode != "sign" {
		return errors.New("mode must be review or sign")
	}
	if *mode == "review" {
		if err := custodyCommandForbid(present, keyName, "out", "expected-review-id"); err != nil {
			return err
		}
	} else if *keyPath == "" || *reviewPin == "" || *outPath == "" {
		return errors.New("sign requires a role seed file, expected-review-id and out")
	}
	if !cosign {
		if err := custodyCommandForbid(present, "command"); err != nil {
			return err
		}
	}
	scope, sources, err := common.loadVersion(custodyauthority.Version1)
	if err != nil {
		return err
	}
	purpose, err := custodyCommandPurpose(*purposeText)
	if err != nil {
		return err
	}
	position, err := remoteOfflinePosition(*sequence, *head)
	if err != nil {
		return err
	}
	inputs := []string{sources.Assignment, sources.Manifest, sources.InitialReceipt, sources.Intent, sources.PreviousReceipt}
	var challenge workarchive.CustodyChallenge
	if *kind != "admit" || purpose == custodyauthority.Serve {
		var file string
		challenge, file, err = custodyCommandChallenge(*challengePath, *challengePin)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
	} else if err := custodyCommandForbid(present, "challenge", "challenge-id"); err != nil {
		return err
	}
	var draft custodyauthority.Command
	switch *kind {
	case "admit":
		if err := custodyCommandForbid(present, "plan", "plan-id", "begin", "begin-id", "admission", "admission-id", "terminal", "terminal-id"); err != nil {
			return err
		}
		public, err := managedCustodyExternalID("consumer-public-key", *actor)
		if err != nil {
			return err
		}
		draft, err = store.BuildRemoteCustodyAdmitCommand(scope, purpose, [32]byte(public), position, challenge)
		if err != nil {
			return err
		}
	case "begin", "complete":
		if err := custodyCommandForbid(present, "consumer-public-key"); err != nil {
			return err
		}
		plan, file, err := remoteOfflinePlan(*planPath, *planPin)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		if err := store.ValidateRemoteCustodyPlan(scope, plan, challenge); err != nil {
			return err
		}
		if *kind == "begin" {
			if err := custodyCommandForbid(present, "begin", "begin-id", "admission", "admission-id", "terminal", "terminal-id"); err != nil {
				return err
			}
			if purpose != custodyauthority.Serve {
				return errors.New("Begin requires purpose serve")
			}
			pid, _ := plan.ID()
			draft, err = custodyauthority.BuildRemoteBeginCommand(scope.Assignment, plan.Admission, pid, position)
		} else {
			begin, beginFile, e := custodyCommandEntry(*beginPath, *beginPin)
			if e != nil {
				return e
			}
			remote, e := remoteOfflineScope(scope, plan, begin, challenge)
			if e != nil {
				return e
			}
			admission, admissionFile, e := custodyCommandEntry(*admissionPath, *admissionPin)
			if e != nil {
				return e
			}
			if admission.Command.Purpose != purpose {
				return errors.New("selected completion purpose differs from admission")
			}
			tid, e := managedCustodyExternalID("terminal-id", *terminalPin)
			if e != nil {
				return e
			}
			terminalFile, e := custodyCommandFile(*terminalPath)
			if e != nil {
				return e
			}
			terminal, e := store.LoadRemoteCustodyTerminal(terminalFile, tid)
			if e != nil {
				return e
			}
			intentID, _ := scope.Intent.ID()
			terminalIntentID, _ := terminal.Intent.ID()
			if intentID != terminalIntentID || (admission != terminal.AuditAdmission && admission != plan.Admission) {
				return errors.New("terminal or admission differs from the selected intent and session")
			}
			ticket, _ := admission.ID()
			draft, err = store.BuildRemoteCustodyCompleteCommand(remote, terminal, ticket, position)
			inputs = append(inputs, beginFile, admissionFile, terminalFile)
		}
		if err != nil {
			return err
		}
	default:
		return errors.New("kind must be admit, begin or complete; offline Drained signing is unavailable")
	}
	command := draft
	if cosign {
		file, err := custodyCommandFile(*commandPath)
		if err != nil {
			return err
		}
		b, err := readRegularArtifact(file, custodyauthority.MaximumCommandBytes)
		if err != nil {
			return err
		}
		command, err = custodyauthority.DecodeCommand(b)
		if err != nil {
			return err
		}
		unsigned := command
		unsigned.Signature = [64]byte{}
		if unsigned != draft {
			return errors.New("signed command differs from the full reviewed V1 scope")
		}
		inputs = append(inputs, file)
	}
	review, err := remoteOfflineReview(scope.Assignment, command, purpose, cosign)
	if err != nil {
		return err
	}
	var entryID types.Hash
	reused := false
	if *mode == "sign" {
		expected, err := managedCustodyExternalID("expected-review-id", *reviewPin)
		if err != nil || expected != review {
			return errors.Join(errors.New("signature requires the exact reviewed V1 message"), err)
		}
		out, err := custodyCommandOutput(*outPath)
		if err != nil {
			return err
		}
		if err := rejectPruneLineageOutputAlias(out, inputs); err != nil {
			return err
		}
		entryID, reused, err = publishRemoteOfflineSignature(ctx, scope.Assignment, command, purpose, review, cosign, out, *keyPath)
		if err != nil {
			return err
		}
	}
	public, err := json.MarshalIndent(struct {
		Scope  custodyCommandPublicScope `json:"scope"`
		Draft  custodyauthority.Command  `json:"unsigned_command"`
		Inputs []string                  `json:"verified_input_files"`
	}{custodyCommandPublic(scope, sources), draft, inputs}, "", "  ")
	if err != nil {
		return err
	}
	return writePruneOutputLine(output, fmt.Sprintf("remote_custody_signing command=%s mode=%s kind=%s purpose=%s assignment_id=%s review_id=%s entry_id=%s artifact_published=%t artifact_reused=%t owners_opened=false execution_authorized=false\nscope:\n%s\nremote_custody_signing_scope_end\n", args[0], *mode, *kind, *purposeText, scope.AssignmentID, review, entryID, *mode == "sign", reused, public))
}

func remoteOfflineReview(a custodyauthority.Assignment, c custodyauthority.Command, purpose custodyauthority.Purpose, cosign bool) (types.Hash, error) {
	if c.Kind == custodyauthority.RemoteBegin {
		if cosign {
			return custodyauthority.RemoteEntryReviewID(a, c)
		}
		return custodyauthority.RemoteCommandReviewID(a, c)
	}
	if cosign {
		return custodyauthority.V1CustodyEntryReviewID(a, c, purpose)
	}
	return custodyauthority.V1CustodyCommandReviewID(a, c, purpose)
}

func publishRemoteOfflineSignature(ctx context.Context, a custodyauthority.Assignment, command custodyauthority.Command, purpose custodyauthority.Purpose, review types.Hash, cosign bool, out, keyPath string) (types.Hash, bool, error) {
	var id types.Hash
	maximum := custodyauthority.MaximumCommandBytes
	if cosign {
		maximum = custodyauthority.MaximumEntryBytes
	}
	if err := ctx.Err(); err != nil {
		return id, false, err
	}
	b, err := readRegularArtifact(out, maximum)
	if err == nil {
		if cosign {
			e, err := custodyauthority.DecodeEntry(b)
			if err != nil || e.Command != command || e.AuthorityPublicKey != a.AuthorityPublicKey {
				return id, false, errors.Join(errors.New("existing output differs from reviewed co-signature"), err)
			}
			id, _ = e.ID()
		} else {
			c, err := custodyauthority.DecodeCommand(b)
			c.Signature = [64]byte{}
			if err != nil || c != command {
				return id, false, errors.Join(errors.New("existing output differs from reviewed command"), err)
			}
		}
		return id, true, publishCustodyCommandArtifact(out, b)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return id, false, err
	}
	key, err := loadPruneOfflineKey(keyPath)
	if err != nil {
		return id, false, err
	}
	if cosign {
		var e custodyauthority.Entry
		if command.Kind == custodyauthority.RemoteBegin {
			e, err = custodyauthority.CosignReviewedRemoteCommand(a, command, review, key)
		} else {
			e, err = custodyauthority.CosignReviewedV1CustodyCommand(a, command, purpose, review, key)
		}
		if err == nil {
			b, err = e.CanonicalBytes()
			id, _ = e.ID()
		}
	} else {
		var c custodyauthority.Command
		if command.Kind == custodyauthority.RemoteBegin {
			c, err = custodyauthority.SignReviewedRemoteCommand(a, command, review, key)
		} else {
			c, err = custodyauthority.SignReviewedV1CustodyCommand(a, command, purpose, review, key)
		}
		if err == nil {
			b, err = c.CanonicalBytes()
		}
	}
	if err != nil {
		return id, false, err
	}
	if err := ctx.Err(); err != nil {
		return id, false, err
	}
	return id, false, publishCustodyCommandArtifact(out, b)
}
