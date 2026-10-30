package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	authoritystore "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const custodyScheduleQuorumCommand = "work-archive-custody-quorum"

type custodyScheduleQuorumSource struct {
	Assignment   string `json:"assignment"`
	AssignmentID string `json:"assignment_id"`
	Authority    string `json:"authority"`
	Pins         string `json:"authority_pins"`
	Journal      string `json:"journal"`
	Proof        string `json:"schedule_proof"`
	ScheduleID   string `json:"schedule_id"`
	Receipt      string `json:"scheduled_receipt"`
	ReceiptID    string `json:"scheduled_receipt_id"`
}

func runCustodyScheduleQuorumCLI(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runCustodyScheduleQuorum(ctx, args, os.Stdout, func() uint64 { return uint64(time.Now().Unix()) })
}

// The sources file is an operator-reviewed list of exact identities, never peer
// discovery. The command only inspects existing original roots and reports.
func runCustodyScheduleQuorum(ctx context.Context, args []string, out io.Writer, now func() uint64) error {
	if ctx == nil || out == nil || now == nil {
		return workarchive.ErrAvailability
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	inputs, err := loadCustodyScheduleQuorumInputs(ctx, args, nil)
	if err != nil {
		return err
	}
	sources, cp, oldPolicy, policy := inputs.Sources, inputs.Checkpoint, inputs.OriginalPolicy, inputs.ReplicaPolicy
	var checkedAt uint64
	bundle, err := authoritystore.InspectScheduledCustodyQuorum(ctx, sources, cp, oldPolicy, policy, func() uint64 { checkedAt = now(); return checkedAt })
	if err != nil {
		return err
	}
	id, err := bundle.ID()
	if err != nil {
		return err
	}
	report := struct {
		BundleID    string                                  `json:"bundle_id"`
		StatementID string                                  `json:"statement_id"`
		ManifestID  string                                  `json:"manifest_id"`
		Height      uint64                                  `json:"radix_activation_height"`
		CheckedAt   uint64                                  `json:"checked_at"`
		Replicas    int                                     `json:"verified_replicas"`
		Required    uint16                                  `json:"required_replicas"`
		Bundle      workarchive.ScheduledAvailabilityBundle `json:"bundle"`
	}{id.String(), bundle.StatementID.String(), bundle.ManifestID.String(), bundle.RadixActivationHeight, checkedAt, len(bundle.Receipts), policy.RequiredReplicas, bundle}
	// Every original owner is closed before reporting, including blocked output.
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	return writeCustodyScheduleReport(ctx, out, append(encoded, '\n'))
}

type custodyScheduleQuorumInputs struct {
	Sources                    []authoritystore.ScheduledCustodyReplicaSource
	Checkpoint                 workarchive.Checkpoint
	OriginalPolicy             workarchive.Policy
	ReplicaPolicy              workarchive.ReplicaPolicy
	Input                      []custodyScheduleQuorumSource
	SourcePath, CheckpointPath string
}

func loadCustodyScheduleQuorumInputs(ctx context.Context, args []string, configure func(*flag.FlagSet)) (custodyScheduleQuorumInputs, error) {
	f := flag.NewFlagSet(custodyScheduleQuorumCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	sourcesPath := f.String("sources", "", "operator-reviewed JSON source list (2..64 replicas)")
	checkpointPath := f.String("checkpoint", "", "target signed checkpoint")
	checkpointID := f.String("checkpoint-id", "", "independently retained target statement ID")
	attestors := f.String("attestors", "", "comma-separated original trusted attestor keys")
	attestQuorum := f.Uint("attestor-quorum", 2, "original attestor quorum")
	replicas := f.String("replicas", "", "comma-separated independently trusted replica keys")
	replicaQuorum := f.Uint("replica-quorum", 2, "required distinct replicas and locations")
	maxAge := f.Uint64("max-receipt-age-seconds", 86400, "maximum original receipt age")
	minTerm := f.Uint64("min-remaining-term-seconds", 86400, "minimum original remaining retention")
	custody := addArchiveCustodyPolicyFlags(f)
	limits := addArchiveCustodyJournalLimitFlags(f)
	if configure != nil {
		configure(f)
	}
	if err := parsePruneFlags(f, args); err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	if err := custody.validate(); err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	if err := limits.limits().Validate(); err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	cp, err := loadArchiveCheckpoint(*checkpointPath)
	if err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	expected, err := managedCustodyExternalID("checkpoint-id", *checkpointID)
	if err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	actual, err := cp.Statement.ID()
	if err != nil || actual != expected {
		return custodyScheduleQuorumInputs{}, workarchive.ErrAvailability
	}
	if cp.Statement.RadixActivationHeight == 0 {
		return custodyScheduleQuorumInputs{}, workarchive.ErrAvailability
	}
	binding := workarchive.Binding{NetworkID: cp.Statement.NetworkID, GenesisID: cp.Statement.GenesisID, ActivationHeight: cp.Statement.ActivationHeight, BaseID: cp.Statement.BaseID}
	sf := custodyScheduleFlags{keys: attestors, quorum: attestQuorum}
	oldPolicy, err := sf.policy(binding)
	if err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	keys := strings.Split(*replicas, ",")
	if len(keys) < 2 || len(keys) > workarchive.MaximumReplicas || *replicaQuorum < 2 || *replicaQuorum > uint(len(keys)) {
		return custodyScheduleQuorumInputs{}, workarchive.ErrReplicaPolicy
	}
	policy := workarchive.ReplicaPolicy{RequiredReplicas: uint16(*replicaQuorum), MaximumReceiptAge: *maxAge, MinimumRemainingTerm: *minTerm}
	for _, v := range keys {
		k, err := parseArchivePublicKey(v)
		if err != nil {
			return custodyScheduleQuorumInputs{}, err
		}
		policy.TrustedReplicas = append(policy.TrustedReplicas, k)
	}
	sort.Slice(policy.TrustedReplicas, func(i, j int) bool {
		return types.CompareHash(types.Hash(policy.TrustedReplicas[i]), types.Hash(policy.TrustedReplicas[j])) < 0
	})
	raw, err := readRegularArtifact(*sourcesPath, 1<<20)
	if err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	// Strict field names and a single JSON value; canonical IDs are checked below.
	var input []custodyScheduleQuorumSource
	if err := cutoverJSON(raw, &input); err != nil {
		return custodyScheduleQuorumInputs{}, err
	}
	if len(input) < 2 || len(input) > workarchive.MaximumReplicas {
		return custodyScheduleQuorumInputs{}, workarchive.ErrAvailability
	}
	sources := make([]authoritystore.ScheduledCustodyReplicaSource, 0, len(input))
	for _, v := range input {
		if err := ctx.Err(); err != nil {
			return custodyScheduleQuorumInputs{}, err
		}
		id, err := managedCustodyExternalID("assignment_id", v.AssignmentID)
		if err != nil {
			return custodyScheduleQuorumInputs{}, err
		}
		a, err := loadPruneOfflineAssignment(v.Assignment, id)
		if err != nil {
			return custodyScheduleQuorumInputs{}, err
		}
		flags := custodyScheduleFlags{proof: &v.Proof, id: &v.ScheduleID, keys: attestors, quorum: attestQuorum}
		scope, err := flags.load(a)
		if err != nil || scope == nil {
			return custodyScheduleQuorumInputs{}, errors.Join(workarchive.ErrAvailability, err)
		}
		receiptID, err := managedCustodyExternalID("scheduled_receipt_id", v.ReceiptID)
		if err != nil {
			return custodyScheduleQuorumInputs{}, err
		}
		raw, err := readRegularArtifact(v.Receipt, workarchive.MaximumScheduledReceiptBytes)
		if err != nil {
			return custodyScheduleQuorumInputs{}, err
		}
		receipt, err := workarchive.DecodeScheduledReplicaReceipt(raw)
		if err != nil {
			return custodyScheduleQuorumInputs{}, err
		}
		p := workarchive.CustodyPolicy{TrustedAuditors: append([][32]byte(nil), a.Auditors...), MaximumChallengeLifetime: *custody.challengeLifetime, MaximumProofAge: *custody.proofAge, MaximumRenewalTerm: *custody.renewalTerm}
		sources = append(sources, authoritystore.ScheduledCustodyReplicaSource{AuthorityPath: v.Authority, AuthorityPinsPath: v.Pins, JournalPath: v.Journal, Assignment: a, AssignmentID: id, Schedule: *scope, Receipt: receipt, ReceiptID: receiptID, CustodyPolicy: p, JournalLimits: limits.limits()})
	}
	return custodyScheduleQuorumInputs{Sources: sources, Checkpoint: cp, OriginalPolicy: oldPolicy, ReplicaPolicy: policy, Input: input, SourcePath: *sourcesPath, CheckpointPath: *checkpointPath}, nil
}
