package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const custodyScheduleCommand = "work-archive-custody-migrate-radix"

type custodyScheduleFlags struct {
	proof, id *string
	keys      *string
	quorum    *uint
}

func addCustodyScheduleFlags(f *flag.FlagSet) *custodyScheduleFlags {
	s := &custodyScheduleFlags{proof: f.String("schedule-proof", "", "canonical custody schedule proof"), id: f.String("schedule-id", "", "independently reviewed schedule proof ID"), quorum: f.Uint("schedule-quorum", workarchive.MinimumAttestors, "original archive attestor quorum")}
	s.keys = f.String("schedule-attestors", "", "comma-separated independently trusted original attestor public keys")
	return s
}
func (s *custodyScheduleFlags) policy(binding workarchive.Binding) (workarchive.Policy, error) {
	p := workarchive.Policy{Binding: binding}
	keys := strings.Split(*s.keys, ",")
	if len(keys) < workarchive.MinimumAttestors || len(keys) > workarchive.MaximumAttestors || *s.quorum < workarchive.MinimumAttestors || *s.quorum > uint(len(keys)) {
		return p, errors.New("original schedule attestors and bounded quorum are required")
	}
	p.RequiredAttestations = uint16(*s.quorum)
	for _, value := range keys {
		k, e := parseArchivePublicKey(value)
		if e != nil {
			return p, e
		}
		p.TrustedAttestors = append(p.TrustedAttestors, k)
	}
	sort.Slice(p.TrustedAttestors, func(i, j int) bool {
		return types.CompareHash(types.Hash(p.TrustedAttestors[i]), types.Hash(p.TrustedAttestors[j])) < 0
	})
	return p, nil
}
func (s *custodyScheduleFlags) load(a custodyauthority.Assignment) (*store.CustodyScheduleContext, error) {
	if *s.proof == "" && *s.id == "" && *s.keys == "" && *s.quorum == workarchive.MinimumAttestors {
		return nil, nil
	}
	id, e := managedCustodyExternalID("schedule-id", *s.id)
	if e != nil {
		return nil, e
	}
	b, e := readRegularArtifact(*s.proof, workarchive.MaximumCustodyScheduleBytes)
	if e != nil {
		return nil, e
	}
	p, e := workarchive.DecodeCustodyScheduleProof(b)
	if e != nil {
		return nil, e
	}
	actual, e := p.ID()
	if e != nil || actual != id {
		return nil, workarchive.ErrCustodySchedule
	}
	m, e := workarchive.DecodeManifest(p.OriginalManifest)
	if e != nil {
		return nil, e
	}
	policy, e := s.policy(m.Binding)
	if e != nil {
		return nil, e
	}
	if e = p.Verify(a, policy); e != nil {
		return nil, e
	}
	return &store.CustodyScheduleContext{Proof: p, Policy: policy, ExpectedID: id}, nil
}
func runCustodyScheduleCLI(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runCustodySchedule(ctx, args, os.Stdout)
}

// Preparation and signing never discover a newer authority position. Application
// uses the original two owners and only the explicitly co-signed command.
func runCustodySchedule(ctx context.Context, args []string, out io.Writer) (returnErr error) {
	f := flag.NewFlagSet(custodyScheduleCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "prepare, review, sign, cosign, receipt, apply, inspect or resume")
	sf := addCustodyScheduleFlags(f)
	ap := f.String("assignment", "", "original immutable assignment")
	aid := f.String("assignment-id", "", "independently retained assignment ID")
	manifest := f.String("manifest", "", "original manifest (prepare)")
	checkpoint := f.String("checkpoint", "", "original signed checkpoint (prepare)")
	nextManifest := f.String("new-manifest", "", "signed same-prefix radix manifest (prepare)")
	nextCheckpoint := f.String("new-checkpoint", "", "signed radix checkpoint (prepare)")
	selectedReceipt := f.String("selected-receipt-id", "", "exact original receipt to wrap (receipt mode)")
	receipt := f.String("receipt", "", "original initial receipt (prepare)")
	journal := f.String("journal", "", "original custody journal")
	policyFlags := addArchiveCustodyPolicyFlags(f)
	authority := f.String("authority", "", "original authority directory")
	pins := f.String("authority-pins", "", "original independent intent directory")
	seq := f.String("expected-sequence", "", "explicit authority sequence for signing")
	head := f.String("expected-head", "", "explicit authority head for signing")
	commandFile := f.String("command", "", "replica-signed migration command (cosign)")
	entryFile := f.String("entry", "", "co-signed migration entry (apply/resume)")
	entryPin := f.String("entry-id", "", "independently retained entry ID (apply/resume)")
	keyFile := f.String("key", "", "original replica key (sign) or authority key (cosign)")
	password := f.String("key-password-file", "", "password file for an encrypted key")
	output := f.String("out", "", "new immutable artifact file")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	if ctx == nil || out == nil {
		return errors.New("context and output are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	allowed := map[string]bool{"prepare": true, "review": true, "sign": true, "cosign": true, "receipt": true, "apply": true, "inspect": true, "resume": true}
	if !allowed[*mode] {
		return errors.New("unsupported schedule mode")
	}
	accepted := map[string]bool{"mode": true, "assignment": true, "assignment-id": true, "schedule-attestors": true, "schedule-quorum": true, "max-challenge-lifetime-seconds": true, "max-proof-age-seconds": true, "max-renewal-term-seconds": true}
	if *mode != "prepare" {
		accepted["schedule-proof"] = true
		accepted["schedule-id"] = true
	}
	modeFlags := map[string][]string{
		"prepare": {"manifest", "checkpoint", "new-manifest", "new-checkpoint", "receipt", "journal", "out"},
		"sign":    {"expected-sequence", "expected-head", "key", "key-password-file", "out"},
		"cosign":  {"command", "key", "key-password-file", "out"},
		"receipt": {"journal", "selected-receipt-id", "key", "key-password-file", "out"},
		"apply":   {"authority", "authority-pins", "journal", "entry", "entry-id"},
		"inspect": {"authority", "authority-pins"},
		"resume":  {"authority", "authority-pins", "entry", "entry-id"},
	}
	for _, name := range modeFlags[*mode] {
		accepted[name] = true
	}
	var flagErr error
	f.Visit(func(v *flag.Flag) {
		if !accepted[v.Name] && flagErr == nil {
			flagErr = fmt.Errorf("flag %s is not used by mode %s", v.Name, *mode)
		}
	})
	if flagErr != nil {
		return flagErr
	}

	if (*mode != "sign" && *mode != "cosign" && *mode != "receipt") && (*keyFile != "" || *password != "") {
		return errors.New("keys are only accepted by explicit signing modes")
	}
	writes := *mode == "prepare" || *mode == "sign" || *mode == "cosign" || *mode == "receipt"
	if writes != (*output != "") {
		return errors.New("prepare/sign/cosign/receipt require out; other modes forbid it")
	}
	id, err := managedCustodyExternalID("assignment-id", *aid)
	if err != nil {
		return err
	}
	a, err := loadPruneOfflineAssignment(*ap, id)
	if err != nil {
		return err
	}
	if a.Version != custodyauthority.Version0 {
		return workarchive.ErrCustodySchedule
	}
	if err = policyFlags.validate(); err != nil {
		return err
	}
	custodyPolicy := workarchive.CustodyPolicy{TrustedAuditors: a.Auditors, MaximumChallengeLifetime: *policyFlags.challengeLifetime, MaximumProofAge: *policyFlags.proofAge, MaximumRenewalTerm: *policyFlags.renewalTerm}
	var scope *store.CustodyScheduleContext
	var artifactID types.Hash
	var heldDecision *workarchive.CustodyJournalDecision
	if *mode == "prepare" {
		if *sf.proof != "" || *sf.id != "" {
			return errors.New("prepare does not consume another schedule proof")
		}
		m, e := loadArchiveManifest(*manifest)
		if e != nil {
			return e
		}
		n, e := loadArchiveManifest(*nextManifest)
		if e != nil {
			return e
		}
		cp, e := loadArchiveCheckpoint(*checkpoint)
		if e != nil {
			return e
		}
		nc, e := loadArchiveCheckpoint(*nextCheckpoint)
		if e != nil {
			return e
		}
		initial, e := loadArchiveReplicaReceipt(*receipt)
		if e != nil {
			return e
		}
		p, e := sf.policy(m.Binding)
		if e != nil {
			return e
		}
		mb, _ := m.CanonicalBytes()
		nb, _ := n.CanonicalBytes()
		j, _, e := workarchive.OpenExistingCustodyJournalWithLimits(ctx, *journal, m, initial, custodyPolicy, workarchive.DefaultCustodyJournalLimits())
		if e != nil {
			return e
		}
		d, e := j.AcquireDecision()
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, d.Close()) }()
		heldDecision = d
		state, e := d.State()
		if e != nil {
			return e
		}
		proof := workarchive.CustodyScheduleProof{AssignmentID: id, OriginalManifest: mb, TargetManifest: nb, OriginalCheckpoint: cp, TargetCheckpoint: nc, InitialReceipt: initial, SelectedReceipt: state.CurrentReceipt, JournalSequence: state.Sequence, JournalHeadID: state.HeadEntryID}
		if e = proof.Verify(a, p); e != nil {
			return e
		}
		// Pin the custody policy as well as the archive before publishing any proof.
		derived, e := workarchive.CreateCustodyAuthorityAssignment(m, initial, custodyPolicy, a.IncarnationID, a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending)
		if e != nil {
			return e
		}
		derivedID, _ := derived.ID()
		if derivedID != id {
			return workarchive.ErrCustodySchedule
		}
		proofID, _ := proof.ID()
		scope = &store.CustodyScheduleContext{Proof: proof, Policy: p, ExpectedID: proofID}
	} else {
		scope, err = sf.load(a)
		if err != nil {
			return err
		}
		if scope == nil {
			return errors.New("schedule-proof and independently reviewed schedule-id are required")
		}
	}
	reportedReceipt := scope.Proof.SelectedReceipt
	if writes {
		// Published artifacts must never be placed inside the live journal or either
		// authority owner, even when the caller supplies an alias of those paths.
		destination, e := canonicalPruneLineageOutput(*output)
		if e != nil {
			return e
		}
		for _, root := range []string{*journal, *authority, *pins} {
			if root == "" {
				continue
			}
			r, e := canonicalPruneLineageDirectory(root)
			if e != nil {
				return e
			}
			if pruneEffectPathsOverlap(r, destination) {
				return errors.New("output must be outside original owner roots")
			}
		}
		var encoded []byte
		maximum := workarchive.MaximumCustodyScheduleBytes
		if *mode == "prepare" {
			encoded, err = scope.Proof.CanonicalBytes()
			artifactID = scope.ExpectedID
		} else if *mode == "receipt" {
			pin, e := managedCustodyExternalID("selected-receipt-id", *selectedReceipt)
			if e != nil {
				return e
			}
			j, _, e := workarchive.OpenScheduledCustodyJournal(ctx, *journal, scope.Proof, a, scope.Policy, custodyPolicy, workarchive.DefaultCustodyJournalLimits())
			if e != nil {
				return e
			}
			d, e := j.AcquireDecision()
			if e != nil {
				return e
			}
			defer func() { returnErr = errors.Join(returnErr, d.Close()) }()
			heldDecision = d
			lineage, selected, e := d.ScheduleLineage(ctx, scope.Proof, a, scope.Policy)
			if e != nil {
				return e
			}
			actual, _ := selected.ID()
			if actual != pin {
				return workarchive.ErrCustodySchedule
			}
			key, e := loadWalletPrivateKey(*keyFile, *password)
			if e != nil {
				return e
			}
			defer clear(key)
			wrapped, e := workarchive.CreateScheduledReplicaReceipt(ctx, scope.Proof, a, scope.Policy, lineage, selected, key)
			if e != nil {
				return e
			}
			if e = d.CheckAccess(); e != nil {
				return e
			}
			encoded, err = wrapped.CanonicalBytes()
			artifactID, _ = wrapped.ID()
			reportedReceipt = selected
			maximum = workarchive.MaximumScheduledReceiptBytes
		} else {
			if *keyFile == "" {
				return errors.New("signing requires the original role key")
			}
			var command custodyauthority.Command
			if *mode == "sign" {
				sequence, e := strconv.ParseUint(*seq, 10, 64)
				if e != nil || strconv.FormatUint(sequence, 10) != *seq {
					return errors.New("expected-sequence must be explicit canonical decimal")
				}
				h, e := managedCustodyExternalID("expected-head", *head)
				if e != nil {
					return e
				}
				if (sequence == 0) != (h == id) || sequence >= custodyauthority.MaximumEntries(a) {
					return custodyauthority.ErrHead
				}
				command = custodyauthority.Command{Version: custodyauthority.ScheduleVersion2, ScheduleID: scope.ExpectedID, AssignmentID: id, ExpectedSequence: sequence, ExpectedHead: h, Kind: custodyauthority.MigrateSchedule, ActorPublicKey: a.ReplicaPublicKey}
			} else {
				b, e := readRegularArtifact(*commandFile, custodyauthority.MaximumCommandBytes)
				if e != nil {
					return e
				}
				command, e = custodyauthority.DecodeCommand(b)
				if e != nil {
					return e
				}
				if command.Kind != custodyauthority.MigrateSchedule || command.ScheduleID != scope.ExpectedID || command.AssignmentID != id || command.ActorPublicKey != a.ReplicaPublicKey {
					return custodyauthority.ErrCommand
				}
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			key, e := loadWalletPrivateKey(*keyFile, *password)
			if e != nil {
				return e
			}
			defer clear(key)
			expected := a.ReplicaPublicKey
			if *mode == "cosign" {
				expected = a.AuthorityPublicKey
			}
			if [32]byte(key.Public().(ed25519.PublicKey)) != expected {
				return custodyauthority.ErrActor
			}
			if *mode == "sign" {
				command, err = command.Sign(key)
				if err == nil {
					encoded, err = command.CanonicalBytes()
				}
				maximum = custodyauthority.MaximumCommandBytes
			} else {
				var entry custodyauthority.Entry
				entry, err = custodyauthority.SignEntry(command, key)
				if err == nil {
					encoded, err = entry.CanonicalBytes()
					artifactID, _ = entry.ID()
				}
				maximum = custodyauthority.MaximumEntryBytes
			}
		}
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = writeNewTieCommandFile(destination, encoded, maximum, workarchive.ErrCustodySchedule, ".custody-schedule-*"); err != nil {
			return err
		}
	}
	var state any
	if *mode == "apply" || *mode == "inspect" || *mode == "resume" {
		owner, e := store.OpenCoordinator(*authority, *pins, a, id)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
		observed, e := owner.Snapshot()
		if e != nil {
			return e
		}
		if *mode == "inspect" {
			if !observed.Authority.ScheduleID.IsZero() && observed.Authority.ScheduleID != scope.ExpectedID {
				return workarchive.ErrCustodySchedule
			}
			state = observed
		} else {
			pin, e := managedCustodyExternalID("entry-id", *entryPin)
			if e != nil {
				return e
			}
			b, e := readRegularArtifact(*entryFile, custodyauthority.MaximumEntryBytes)
			if e != nil {
				return e
			}
			entry, e := custodyauthority.DecodeEntry(b)
			if e != nil {
				return e
			}
			actual, _ := entry.ID()
			if actual != pin || entry.Command.Kind != custodyauthority.MigrateSchedule || entry.Command.ScheduleID != scope.ExpectedID {
				return custodyauthority.ErrCommand
			}
			if *mode == "resume" {
				if observed.Pending == nil || *observed.Pending != entry {
					return store.ErrNoAttempt
				}
				state, err = owner.Resume(ctx)
			} else {
				state, err = owner.MigrateCustodySchedule(ctx, entry, *scope, *journal, custodyPolicy, workarchive.DefaultCustodyJournalLimits())
			}
			if err != nil {
				return err
			}
		}
		if err = owner.Close(); err != nil {
			return err
		}
	}
	if heldDecision != nil {
		if err = heldDecision.Close(); err != nil {
			return err
		}
	}
	target, _ := workarchive.DecodeManifest(scope.Proof.TargetManifest)
	report := struct {
		Mode                  string `json:"mode"`
		ScheduleID            string `json:"schedule_id"`
		AssignmentID          string `json:"assignment_id"`
		ArtifactID            string `json:"artifact_id,omitempty"`
		ReceiptID             string `json:"original_receipt_id"`
		RadixActivationHeight uint64 `json:"radix_activation_height"`
		JournalSequence       uint64 `json:"migration_journal_sequence"`
		StoredAt              uint64 `json:"stored_at"`
		RetainUntil           uint64 `json:"retain_until"`
		State                 any    `json:"state,omitempty"`
	}{Mode: *mode, ScheduleID: scope.ExpectedID.String(), AssignmentID: id.String(), RadixActivationHeight: target.Binding.RadixActivationHeight, JournalSequence: scope.Proof.JournalSequence, StoredAt: reportedReceipt.StoredAt, RetainUntil: reportedReceipt.RetainUntil, State: state}
	if !artifactID.IsZero() {
		report.ArtifactID = artifactID.String()
	}
	receiptID, _ := reportedReceipt.ID()
	report.ReceiptID = receiptID.String()
	b, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return writeCustodyScheduleReport(ctx, out, b)
}

// Owner locks are already released before reporting. Adopt native pipes so a
// blocked reader cannot prevent SIGINT/SIGTERM from ending the command after a
// durable write. Lost output never rolls back an artifact or authority decision.
func writeCustodyScheduleReport(ctx context.Context, output io.Writer, report []byte) (returnErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if file, ok := output.(*os.File); ok {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeNamedPipe != 0 && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
			writer, err := ownPruneEffectOutput(output)
			if err != nil {
				return err
			}
			defer func() { returnErr = errors.Join(returnErr, writer.Close()) }()
			done := make(chan struct{})
			stop := context.AfterFunc(ctx, func() { defer close(done); _ = writer.Close() })
			defer func() {
				if !stop() {
					<-done
				}
			}()
			output = writer
		}
	}
	_, err := fmt.Fprintln(output, string(report))
	return errors.Join(err, ctx.Err())
}
