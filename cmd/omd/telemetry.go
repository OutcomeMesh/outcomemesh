package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/activation"
	"github.com/outcomemesh/outcomemesh/node/calibration"
)

const telemetryAdvanceInterval = time.Minute

func runWorkTelemetryPolicy(arguments []string) error {
	flags := flag.NewFlagSet("work-telemetry-policy", flag.ContinueOnError)
	path := flags.String("policy", "", "miner-to-cluster policy text file")
	comparisonBudget := flags.Uint("clusters", 0, "precommitted cluster comparison budget")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *path == "" || *comparisonBudget == 0 || *comparisonBudget > calibration.MaximumClusters {
		return fmt.Errorf("policy and clusters 1..%d are required", calibration.MaximumClusters)
	}
	policy, err := loadClusterPolicyText(*path, uint32(*comparisonBudget))
	if err != nil {
		return err
	}
	identifier, err := policy.ID()
	if err != nil {
		return err
	}
	encoded, err := policy.CanonicalBytes()
	if err != nil {
		return err
	}
	fmt.Printf("work_telemetry_policy id=%s clusters=%d canonical_bytes=%d\n",
		identifier, policy.ComparisonBudget(), len(encoded))
	return nil
}

func runWorkTelemetryTiePlan(arguments []string) error {
	flags := flag.NewFlagSet("work-telemetry-tie-plan", flag.ContinueOnError)
	data := flags.String("data", defaultDataDirectory, "WorkGraph-enabled node data directory")
	coordinatorKeyPath := flags.String("coordinator-key", "", "Ed25519 coordinator seed file")
	observerPublicKeyText := flags.String("observer-public-key", "", "observer Ed25519 public key")
	testedMinerText := flags.String("tested-miner", "", "tested miner payout address")
	controlMinerText := flags.String("control-miner", "", "control miner payout address")
	startedAt := flags.Uint64("start", 0, "first slot start as Unix seconds")
	slotCount := flags.Uint64("slots", 0, "number of precommitted trial slots")
	slotSeconds := flags.Uint64("slot-seconds", 0, "half-open slot duration")
	spacingSeconds := flags.Uint64("spacing-seconds", 0, "seconds between slot starts")
	pairDelaySeconds := flags.Uint64("pair-delay-seconds", 0, "maximum observation delay between siblings")
	outputPath := flags.String("output", "", "signed tie plan output path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *coordinatorKeyPath == "" || *observerPublicKeyText == "" || *testedMinerText == "" ||
		*controlMinerText == "" || *startedAt == 0 || *slotCount == 0 ||
		*slotCount > calibration.MaximumTiePlanSlots || *slotSeconds == 0 ||
		*slotSeconds > calibration.MaximumTieSlotSeconds || *spacingSeconds < *slotSeconds ||
		*pairDelaySeconds == 0 || *pairDelaySeconds > *slotSeconds || *outputPath == "" {
		return errors.New("coordinator/observer/miners, bounded schedule, pair delay, and output are required")
	}
	if *startedAt <= unixNow() {
		return errors.New("first controlled-tie slot must start in the future")
	}
	if _, err := os.Lstat(*outputPath); err == nil {
		return errors.New("controlled-tie plan output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	count := *slotCount
	spacing := *spacingSeconds
	duration := *slotSeconds
	if count > 1 && spacing > (^uint64(0)-*startedAt)/(count-1) {
		return errors.New("controlled-tie schedule overflows Unix seconds")
	}
	lastStart := *startedAt + (count-1)*spacing
	if duration > ^uint64(0)-lastStart {
		return errors.New("controlled-tie slot end overflows Unix seconds")
	}
	document, err := loadGenesis(*data)
	if err != nil {
		return err
	}
	profile, err := loadWorkActivation(*data, document)
	if err != nil {
		return err
	}
	genesisID, err := document.ID()
	if err != nil {
		return err
	}
	coordinatorKey, err := loadPrivateKey(*coordinatorKeyPath)
	if err != nil {
		return err
	}
	observerKey, err := parseHash(*observerPublicKeyText)
	if err != nil {
		return fmt.Errorf("observer-public-key: %w", err)
	}
	testedMiner, err := parseAddress(*testedMinerText)
	if err != nil {
		return fmt.Errorf("tested-miner: %w", err)
	}
	controlMiner, err := parseAddress(*controlMinerText)
	if err != nil {
		return fmt.Errorf("control-miner: %w", err)
	}
	plan := calibration.TiePlan{
		Version: calibration.TiePlanVersion0, NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight: profile.ActivationHeight, TestedMiner: testedMiner, ControlMiner: controlMiner,
		MaximumPairDelaySeconds: *pairDelaySeconds,
		Slots:                   make([]calibration.TiePlanSlot, int(count)),
	}
	copy(plan.ObserverPublicKey[:], observerKey[:])
	for index := range plan.Slots {
		start := *startedAt + uint64(index)*spacing
		plan.Slots[index] = calibration.TiePlanSlot{StartedAt: start, EndedAt: start + duration}
	}
	plan, err = calibration.SignTiePlan(coordinatorKey, plan)
	if err != nil {
		return err
	}
	if err := calibration.SaveTiePlanFile(*outputPath, plan, plan.Binding()); err != nil {
		return err
	}
	identifier, err := plan.ID()
	if err != nil {
		return err
	}
	fmt.Printf("work_telemetry_tie_plan id=%s slots=%d first_start=%d final_end=%d output=%s\n",
		identifier, len(plan.Slots), plan.Slots[0].StartedAt, plan.Slots[len(plan.Slots)-1].EndedAt, *outputPath)
	return nil
}

type liveWorkTelemetry struct {
	collector *calibration.Collector
	ties      *calibration.TieCollector
	policy    *calibration.ClusterPolicy
	errors    chan error
	once      sync.Once
}

type liveTieTelemetryConfig struct {
	PlanPath             string
	ExpectedPlanID       types.Hash
	CoordinatorPublicKey [ed25519.PublicKeySize]byte
	ReceiptPath          string
	PendingPath          string
}

func openLiveWorkTelemetry(
	document genesis.Document,
	profile workActivationProfile,
	keyPath string,
	policyPath string,
	expectedPolicyID types.Hash,
	comparisonBudget uint32,
	manifestPath string,
	pendingPath string,
	now uint64,
	tieConfig *liveTieTelemetryConfig,
) (*liveWorkTelemetry, error) {
	if document.NetworkID == 0 || profile.NetworkID != document.NetworkID || profile.ActivationHeight == 0 {
		return nil, errors.New("telemetry deployment binding is invalid")
	}
	privateKey, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	policy, err := loadClusterPolicyText(policyPath, comparisonBudget)
	if err != nil {
		return nil, err
	}
	policyID, err := policy.ID()
	if err != nil {
		return nil, err
	}
	if policyID != expectedPolicyID {
		return nil, fmt.Errorf("telemetry cluster policy ID is %s, want %s", policyID, expectedPolicyID)
	}
	genesisID, err := document.ID()
	if err != nil {
		return nil, err
	}
	binding := calibration.Binding{
		NetworkID: document.NetworkID, GenesisID: genesisID,
		ActivationHeight: profile.ActivationHeight, ClusterPolicyID: policyID,
		ClusterComparisonBudget: comparisonBudget,
	}
	copy(binding.ObserverPublicKey[:], privateKey.Public().(ed25519.PublicKey))
	collector, err := calibration.OpenCollector(calibration.CollectorConfig{
		Binding: binding, PrivateKey: privateKey,
		ManifestPath: manifestPath, PendingPath: pendingPath,
	}, now)
	if err != nil {
		return nil, err
	}
	result := &liveWorkTelemetry{
		collector: collector,
		policy:    policy,
		errors:    make(chan error, 1),
	}
	if tieConfig != nil {
		tieBinding := calibration.TiePlanBinding{
			NetworkID: document.NetworkID, GenesisID: genesisID,
			ActivationHeight:     profile.ActivationHeight,
			CoordinatorPublicKey: tieConfig.CoordinatorPublicKey,
		}
		copy(tieBinding.ObserverPublicKey[:], privateKey.Public().(ed25519.PublicKey))
		plan, err := calibration.LoadTiePlanFile(tieConfig.PlanPath, tieBinding)
		if err != nil {
			_ = collector.Close(now)
			return nil, err
		}
		planID, err := plan.ID()
		if err != nil || planID != tieConfig.ExpectedPlanID {
			_ = collector.Close(now)
			return nil, errors.New("controlled-tie plan does not match published plan ID")
		}
		collectorStatus, err := collector.Status()
		if err != nil {
			_ = collector.Close(now)
			return nil, err
		}
		telemetryStartedAt := collectorStatus.StartedAt
		if telemetryStartedAt == 0 {
			telemetryStartedAt = collectorStatus.PendingStartedAt
		}
		if plan.Slots[0].StartedAt < telemetryStartedAt {
			_ = collector.Close(now)
			return nil, errors.New("controlled-tie plan starts before the signed telemetry window")
		}
		result.ties, err = calibration.OpenTieCollector(calibration.TieCollectorConfig{
			Plan: plan, Binding: tieBinding, PrivateKey: privateKey,
			ReceiptPath: tieConfig.ReceiptPath, PendingPath: tieConfig.PendingPath,
		}, now)
		if err != nil {
			_ = collector.Close(now)
			return nil, err
		}
	}
	return result, nil
}

func (telemetry *liveWorkTelemetry) Observe(event activation.WorkAdmission) {
	if telemetry == nil {
		return
	}
	cluster, err := telemetry.policy.Cluster(event.Miner)
	if err == nil {
		_, err = telemetry.collector.ObserveWork(event.ObservedAt, event.ID, cluster)
	}
	if err == nil && telemetry.ties != nil {
		_, err = telemetry.ties.Observe(calibration.TieAdmission{
			ID: event.ID, ParentID: event.ParentID, Height: event.Height,
			ObservedAt: event.ObservedAt, Miner: event.Miner, SelectedID: event.SelectedID,
		})
	}
	if err != nil {
		telemetry.fail(err)
	}
}

func (telemetry *liveWorkTelemetry) Start(ctx context.Context, now func() uint64) <-chan error {
	if telemetry == nil {
		return nil
	}
	go func() {
		ticker := time.NewTicker(telemetryAdvanceInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := telemetry.collector.Advance(now()); err != nil {
					telemetry.fail(err)
					return
				}
				if telemetry.ties != nil {
					if err := telemetry.ties.Advance(now()); err != nil {
						telemetry.fail(err)
						return
					}
				}
			}
		}
	}()
	return telemetry.errors
}

func (telemetry *liveWorkTelemetry) Close(now uint64) error {
	if telemetry == nil {
		return nil
	}
	var tieErr error
	if telemetry.ties != nil {
		tieErr = telemetry.ties.Close(now)
	}
	return errors.Join(telemetry.collector.Close(now), tieErr)
}

func (telemetry *liveWorkTelemetry) TieStatus() (calibration.TieCollectorStatus, error) {
	if telemetry == nil || telemetry.ties == nil {
		return calibration.TieCollectorStatus{}, errors.New("controlled-tie telemetry is disabled")
	}
	return telemetry.ties.Status()
}

func (telemetry *liveWorkTelemetry) Status() (calibration.CollectorStatus, error) {
	if telemetry == nil {
		return calibration.CollectorStatus{}, errors.New("telemetry is disabled")
	}
	return telemetry.collector.Status()
}

func (telemetry *liveWorkTelemetry) fail(err error) {
	telemetry.once.Do(func() {
		err = errors.Join(err, telemetry.collector.Fail(err))
		telemetry.errors <- err
	})
}

func loadClusterPolicyText(path string, comparisonBudget uint32) (*calibration.ClusterPolicy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var unknown types.Hash
	var assignments []calibration.MinerClusterAssignment
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 4096)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		for index := range fields {
			fields[index] = strings.TrimSpace(fields[index])
		}
		switch {
		case len(fields) == 2 && fields[0] == "unknown":
			if !unknown.IsZero() {
				return nil, fmt.Errorf("telemetry policy line %d repeats unknown cluster", lineNumber)
			}
			unknown, err = parseHash(fields[1])
		case len(fields) == 3 && fields[0] == "miner":
			var miner types.Address
			miner, err = parseAddress(fields[1])
			if err == nil {
				var cluster types.Hash
				cluster, err = parseHash(fields[2])
				if err == nil {
					assignments = append(assignments, calibration.MinerClusterAssignment{
						Miner: miner, ClusterID: cluster,
					})
				}
			}
		default:
			return nil, fmt.Errorf("invalid telemetry policy line %d", lineNumber)
		}
		if err != nil {
			return nil, fmt.Errorf("telemetry policy line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if unknown.IsZero() {
		return nil, errors.New("telemetry policy requires one unknown,<cluster-id> line")
	}
	return calibration.NewClusterPolicy(comparisonBudget, unknown, assignments)
}
