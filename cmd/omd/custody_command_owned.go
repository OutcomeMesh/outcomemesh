package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

var errCustodyCommandUnobserved = errors.New("custody action result was not observed; inspect the retained canonical artifact and original journals before an explicit retry")

type custodyCommandOwnedOptions struct {
	name, mode, out  string
	scope            authoritystore.CustodyCommandScope
	sources          custodyCommandSources
	purpose          custodyauthority.Purpose
	apply            authoritystore.ManagedCustodyCommandServiceConfig
	capture          authoritystore.ManagedCustodyTerminalCaptureServiceConfig
	artifacts, nonce string
	auditorKey       ed25519.PrivateKey
}

func loadCustodyCommandOwnedOptions(ctx context.Context, args []string) (custodyCommandOwnedOptions, error) {
	o := custodyCommandOwnedOptions{name: args[0]}
	capture := o.name == custodyTerminalCommand
	prepare := o.name == remoteCustodyChallengeCommand
	remote := prepare || o.name == remoteCustodyAdmissionApplyCommand
	f := flag.NewFlagSet(o.name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	common := addCustodyCommandScopeFlags(f)
	mode := f.String("mode", "review", "review (default), or supervised control")
	purposeText := f.String("purpose", "", "selected audit or serve purpose")
	authority := f.String("authority", "", "existing original authority root")
	pins := f.String("authority-pins", "", "existing original authority pins")
	journal := f.String("journal", "", "existing active selected custody journal")
	admissionPath := f.String("admission", "", "exact co-signed admission")
	admissionText := f.String("admission-id", "", "independently retained admission ID")
	limits := addArchiveCustodyJournalLimitFlags(f)
	var artifacts, auditorKey string
	if prepare {
		f.StringVar(&artifacts, "artifacts", "", "existing original A artifact root")
		f.StringVar(&auditorKey, "auditor-key", "", "control only: existing auditor evidence seed file")
	}
	var entryPath, entryText, challengePath, challengeText, terminalPath, terminalText, out string
	if capture {
		f.StringVar(&out, "out", "", "control only: immutable captured terminal envelope")
	} else {
		f.StringVar(&entryPath, "entry", "", "exact already co-signed entry; no signing occurs")
		f.StringVar(&entryText, "entry-id", "", "independently retained entry ID")
		f.StringVar(&challengePath, "challenge", "", "Serve Admit only: exact signed challenge")
		f.StringVar(&challengeText, "challenge-id", "", "Serve Admit only: independently retained challenge ID")
		f.StringVar(&terminalPath, "terminal", "", "Complete only: captured terminal envelope")
		f.StringVar(&terminalText, "terminal-id", "", "Complete only: independently retained terminal envelope ID")
	}
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return o, err
	}
	present := custodyCommandPresence(f)
	if *mode != "review" && *mode != "control" {
		return o, errors.New("owned custody mode must be review or control")
	}
	o.mode = *mode
	if capture && o.mode == "review" {
		if err := custodyCommandForbid(present, "out"); err != nil {
			return o, err
		}
	}
	var err error
	if remote {
		o.scope, o.sources, err = common.loadVersion(custodyauthority.Version1)
	} else {
		o.scope, o.sources, err = common.load()
	}
	if err != nil {
		return o, err
	}
	o.purpose, err = custodyCommandPurpose(*purposeText)
	if err != nil {
		return o, err
	}
	for _, root := range []*string{authority, pins, journal} {
		*root, err = managedCustodyCanonicalDirectory(*root)
		if err != nil {
			return o, err
		}
	}
	if err := limits.limits().Validate(); err != nil {
		return o, err
	}
	if capture {
		admission, path, err := custodyCommandEntry(*admissionPath, *admissionText)
		if err != nil {
			return o, err
		}
		if admission.Command.Kind != custodyauthority.Admit || admission.Command.Purpose != o.purpose {
			return o, errors.New("capture selected purpose differs from admission")
		}
		id, _ := admission.ID()
		o.capture = authoritystore.ManagedCustodyTerminalCaptureServiceConfig{AuthorityPath: *authority, AuthorityPinsPath: *pins, Scope: o.scope, Admission: admission, AdmissionID: id, IntentPath: o.sources.Intent, AdmissionPath: path, JournalPath: *journal, JournalLimits: limits.limits()}
		if o.mode == "control" {
			o.out, err = custodyCommandOutput(out)
			if err != nil {
				return o, err
			}
			if err := rejectPruneLineageOutputAlias(o.out, []string{o.sources.Assignment, o.sources.Manifest, o.sources.InitialReceipt, o.sources.Intent, o.sources.PreviousReceipt, path}); err != nil {
				return o, err
			}
			// The output is evidence, never a file inside an owned live root.
			for _, root := range []string{*authority, *pins, *journal} {
				if workarchive.CustodyEvidencePathsOverlap(root, o.out) {
					return o, errors.New("terminal output must be separate from every original live root")
				}
			}
		}
	} else {
		entry, path, err := custodyCommandEntry(entryPath, entryText)
		if err != nil {
			return o, err
		}
		id, _ := entry.ID()
		if remote && entry.Command.Kind != custodyauthority.Admit {
			return o, errors.New("V1 preparation applies only ordinary admissions; Begin/Drain/Complete use the remote operator")
		}
		o.apply = authoritystore.ManagedCustodyCommandServiceConfig{AuthorityPath: *authority, AuthorityPinsPath: *pins, Scope: o.scope, Entry: entry, EntryID: id, JournalPath: *journal, JournalLimits: limits.limits(), IntentPath: o.sources.Intent, EntryPath: path}
		switch entry.Command.Kind {
		case custodyauthority.Admit:
			if entry.Command.Purpose != o.purpose {
				return o, errors.New("selected purpose differs from admitted command")
			}
			if err := custodyCommandForbid(present, "admission", "admission-id", "terminal", "terminal-id"); err != nil {
				return o, err
			}
			if o.purpose == custodyauthority.Serve {
				o.apply.Challenge, o.apply.ChallengePath, err = custodyCommandChallenge(challengePath, challengeText)
				if err != nil {
					return o, err
				}
			} else if err := custodyCommandForbid(present, "challenge", "challenge-id"); err != nil {
				return o, err
			}
		case custodyauthority.Complete:
			if err := custodyCommandForbid(present, "challenge", "challenge-id"); err != nil {
				return o, err
			}
			admission, _, err := custodyCommandEntry(*admissionPath, *admissionText)
			if err != nil {
				return o, err
			}
			if admission.Command.Purpose != o.purpose {
				return o, errors.New("selected purpose differs from completion admission")
			}
			o.apply.Terminal, o.apply.TerminalPath, err = custodyCommandTerminal(terminalPath, terminalText)
			if err != nil {
				return o, err
			}
			if o.apply.Terminal.Admission != admission {
				return o, errors.New("terminal envelope differs from selected admission")
			}
		default:
			return o, errors.New("local custody apply accepts only Audit/Serve Admit or Complete")
		}
	}
	if prepare {
		if o.purpose != custodyauthority.Audit {
			return o, errors.New("challenge preparation requires the Audit admission")
		}
		o.artifacts, err = managedCustodyCanonicalDirectory(artifacts)
		if err != nil {
			return o, err
		}
		for _, root := range []string{*authority, *pins, *journal, filepath.Dir(o.sources.Intent), filepath.Dir(o.apply.EntryPath)} {
			if err := authoritystore.ValidateBootstrapPaths(o.artifacts, root); err != nil {
				return o, err
			}
		}
		if o.mode == "review" {
			if err := custodyCommandForbid(present, "auditor-key"); err != nil {
				return o, err
			}
		} else {
			o.auditorKey, err = loadPruneOfflineKey(auditorKey)
			if err != nil {
				return o, err
			}
			if [32]byte(o.auditorKey.Public().(ed25519.PublicKey)) != o.scope.Intent.AuditorPublicKey {
				return o, errors.New("auditor seed does not match the pinned intent")
			}
		}
	}
	if remote && o.mode == "control" {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return o, err
		}
		o.nonce = fmt.Sprintf("%x", nonce)
	}
	return o, ctx.Err()
}

type custodyCommandOwner struct {
	review func(context.Context) (any, types.Hash, error)
	action func(context.Context, string, types.Hash) (string, error)
	close  func() error
}

func openCustodyCommandOwner(ctx context.Context, o custodyCommandOwnedOptions) (custodyCommandOwner, error) {
	if o.name == remoteCustodyChallengeCommand {
		s, err := authoritystore.OpenRemoteCustodyChallengeService(ctx, authoritystore.RemoteCustodyChallengeConfig{Admission: o.apply, ArtifactsPath: o.artifacts, SessionConfig: workarchive.DefaultCustodySessionConfig()})
		if err != nil {
			return custodyCommandOwner{}, err
		}
		return custodyCommandOwner{
			review: func(ctx context.Context) (any, types.Hash, error) {
				r, err := s.Review(ctx)
				if err != nil {
					return nil, types.Hash{}, err
				}
				id, err := r.ID()
				return r, id, err
			},
			action: func(ctx context.Context, action string, id types.Hash) (string, error) {
				if action != "prepare" {
					return "", errors.New("challenge control requires prepare")
				}
				challenge, err := s.Prepare(ctx, id, o.auditorKey)
				if err != nil {
					return "", err
				}
				cid, err := challenge.ID()
				if err != nil {
					return "", errors.Join(errCustodyCommandUnobserved, err)
				}
				return fmt.Sprintf("challenge_id=%s challenge_published=true execution_started=false", cid), nil
			}, close: s.Close}, nil
	}
	if o.name == custodyTerminalCommand {
		s, err := authoritystore.OpenManagedCustodyTerminalCaptureService(ctx, o.capture)
		if err != nil {
			return custodyCommandOwner{}, err
		}
		return custodyCommandOwner{
			review: func(ctx context.Context) (any, types.Hash, error) {
				r, err := s.Review(ctx)
				if err != nil {
					return nil, types.Hash{}, err
				}
				id, err := r.ID()
				return r, id, err
			},
			action: func(ctx context.Context, action string, id types.Hash) (string, error) {
				if action != "capture" {
					return "", errors.New("terminal control requires capture")
				}
				t, err := s.CaptureToFile(ctx, id, o.out)
				if err != nil {
					return "", err
				}
				tid, err := t.ID()
				if err != nil {
					return "", errors.Join(errCustodyCommandUnobserved, err)
				}
				return fmt.Sprintf("terminal_id=%s artifact_published=true completion_submitted=false", tid), nil
			}, close: s.Close}, nil
	}
	var s *authoritystore.ManagedCustodyCommandService
	var err error
	if o.name == remoteCustodyAdmissionApplyCommand {
		s, err = authoritystore.OpenRemoteCustodyAdmissionService(ctx, o.apply)
	} else {
		s, err = authoritystore.OpenManagedCustodyCommandService(ctx, o.apply)
	}
	if err != nil {
		return custodyCommandOwner{}, err
	}
	return custodyCommandOwner{
		review: func(ctx context.Context) (any, types.Hash, error) {
			r, err := s.Review(ctx)
			if err != nil {
				return nil, types.Hash{}, err
			}
			id, err := r.ID()
			return r, id, err
		},
		action: func(ctx context.Context, action string, id types.Hash) (string, error) {
			var commit authoritystore.Commit
			var err error
			if action == "apply" {
				commit, err = s.Apply(ctx, id)
			} else if action == "resume" {
				commit, err = s.Resume(ctx, id)
			} else {
				return "", errors.New("application control requires apply or explicit resume")
			}
			if err != nil {
				return "", err
			}
			b, err := json.Marshal(commit)
			if err != nil {
				return "", errors.Join(errCustodyCommandUnobserved, err)
			}
			return fmt.Sprintf("entry_id=%s commit=%s execution_started=false", o.apply.EntryID, b), nil
		}, close: s.Close}, nil
}

func custodyCommandOwnedScope(o custodyCommandOwnedOptions, review any, base types.Hash) ([]byte, types.Hash, error) {
	var confirmed, observed custodyauthority.Position
	var head, receipt, entry, admission, terminal types.Hash
	var sequence uint64
	switch r := review.(type) {
	case authoritystore.ManagedCustodyCommandReview:
		confirmed, observed = r.AuthorityPosition, r.ObservedAuthorityPosition
		head, receipt, entry, sequence = r.JournalHeadID, r.CurrentReceiptID, r.EntryID, r.JournalSequence
	case authoritystore.ManagedCustodyCaptureReview:
		confirmed, observed = r.AuthorityPosition, r.AuthorityPosition
		head, receipt, admission, terminal, sequence = r.JournalHeadID, r.CurrentReceiptID, r.AdmissionID, r.TerminalID, r.JournalSequence
	case authoritystore.RemoteCustodyChallengeReview:
		a := r.Admission
		confirmed, observed = a.AuthorityPosition, a.ObservedAuthorityPosition
		head, receipt, admission, sequence = a.JournalHeadID, a.CurrentReceiptID, a.EntryID, a.JournalSequence
	default:
		return nil, types.Hash{}, errors.New("unsupported custody review type")
	}
	b, err := json.MarshalIndent(struct {
		Scope                     custodyCommandPublicScope `json:"scope"`
		ControlNonce              string                    `json:"control_nonce,omitempty"`
		Review                    any                       `json:"owned_review"`
		BaseID                    string                    `json:"base_review_id"`
		Purpose                   custodyauthority.Purpose  `json:"selected_purpose"`
		Output                    string                    `json:"terminal_output"`
		AuthoritySequence         uint64                    `json:"confirmed_authority_sequence"`
		AuthorityHeadID           string                    `json:"confirmed_authority_head_id"`
		ObservedAuthoritySequence uint64                    `json:"observed_authority_sequence"`
		ObservedAuthorityHeadID   string                    `json:"observed_authority_head_id"`
		JournalSequence           uint64                    `json:"journal_sequence"`
		JournalHeadID             string                    `json:"journal_head_id"`
		CurrentReceiptID          string                    `json:"current_receipt_id"`
		EntryID                   string                    `json:"entry_id"`
		AdmissionID               string                    `json:"admission_id"`
		TerminalID                string                    `json:"terminal_id"`
	}{custodyCommandPublic(o.scope, o.sources), o.nonce, review, base.String(), o.purpose, o.out, confirmed.Sequence, confirmed.HeadID.String(), observed.Sequence, observed.HeadID.String(), sequence, head.String(), receipt.String(), entry.String(), admission.String(), terminal.String()}, "", "  ")
	return b, types.DomainHash("OMESH/local/custody-command-cli-review/v0", b), err
}

func writeCustodyCommandOwnedReview(output io.Writer, o custodyCommandOwnedOptions, review any, base types.Hash, retained bool) (types.Hash, error) {
	b, id, err := custodyCommandOwnedScope(o, review, base)
	if err != nil {
		return types.Hash{}, err
	}
	err = writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_command_review command=%s review_id=%s assignment_id=%s owners_retained=%t execution_authorized=false\nscope:\n%s\nwork_archive_custody_command_scope_end\n", o.name, id, o.scope.AssignmentID, retained, b))
	return id, err
}

func runCustodyCommandOwned(ctx context.Context, args []string, input io.ReadCloser, output io.Writer) (resultErr error) {
	o, err := loadCustodyCommandOwnedOptions(ctx, args)
	if err != nil {
		return err
	}
	if o.mode == "review" {
		s, err := openCustodyCommandOwner(ctx, o)
		if err != nil {
			return err
		}
		review, base, reviewErr := s.review(ctx)
		if err := errors.Join(reviewErr, s.close()); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		// A stalled report can never retain the authority or active journal.
		if file, ok := output.(*os.File); ok {
			info, err := file.Stat()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeNamedPipe != 0 && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
				w, err := ownPruneEffectOutput(output)
				if err != nil {
					return err
				}
				defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
				done := make(chan struct{})
				stop := context.AfterFunc(ctx, func() { defer close(done); _ = w.Close() })
				defer func() {
					if !stop() {
						<-done
					}
				}()
				output = w
			}
		}
		_, err = writeCustodyCommandOwnedReview(output, o, review, base, false)
		return err
	}
	control, err := ownPruneControlInput(input)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, control.Close()) }()
	w, err := ownPruneEffectOutput(output)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, w.Close()) }()
	return runCustodyCommandControl(ctx, o, control, w)
}

func runCustodyCommandControl(parent context.Context, o custodyCommandOwnedOptions, input *pruneControlInput, output *pruneEffectOutput) (returnErr error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	lines, terminal := make(chan string, 1), make(chan error, 1)
	readerDone, ioDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(readerDone); readManagedCustodyAuditControl(ctx, input, lines, terminal, cancel) }()
	go func() { defer close(ioDone); <-ctx.Done(); _ = input.Close(); _ = output.Close() }()
	defer func() { cancel(); <-readerDone; <-ioDone }()
	s, err := openCustodyCommandOwner(ctx, o)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, s.close()) }()
	if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_command_ready command=%s assignment_id=%s owners_retained=true automatic_admission=false automatic_completion=false\n", o.name, o.scope.AssignmentID)); err != nil {
		return err
	}
	var reported, baseID types.Hash
	for {
		select {
		case <-ctx.Done():
			select {
			case err := <-terminal:
				if err == io.EOF {
					return nil
				}
				return err
			default:
				return ctx.Err()
			}
		case err := <-terminal:
			if err == io.EOF {
				return nil
			}
			return err
		case line := <-lines:
			if err := ctx.Err(); err != nil {
				return err
			}
			if line == "close" {
				return nil
			}
			if line == "review" {
				review, base, err := s.review(ctx)
				if err != nil {
					return err
				}
				id, err := writeCustodyCommandOwnedReview(output, o, review, base, true)
				if err != nil {
					return err
				}
				reported, baseID = id, base
				continue
			}
			action, text, ok := strings.Cut(line, " ")
			valid := action == "apply" || action == "resume"
			if o.name == custodyTerminalCommand {
				valid = action == "capture"
			}
			if o.name == remoteCustodyChallengeCommand {
				valid = action == "prepare"
			}
			if !ok || !valid {
				return errors.New("control accepts review, the selected action with its review ID, or close")
			}
			id, err := managedCustodyExternalID("review-id", text)
			if err != nil || reported.IsZero() || id != reported {
				return errors.Join(errors.New("action requires the exact same-session fully reported review ID"), err)
			}
			reported = types.Hash{}
			underlying := baseID
			baseID = types.Hash{}
			result, err := s.action(ctx, action, underlying)
			if err != nil {
				return err
			}
			if err := writePruneOutputLine(output, fmt.Sprintf("work_archive_custody_command_result action=%s expected_review_id=%s %s owners_retained=true\n", action, id, result)); err != nil {
				return errors.Join(errCustodyCommandUnobserved, err)
			}
		}
	}
}
