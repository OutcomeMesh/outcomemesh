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

type liveWorkTelemetry struct {
	collector *calibration.Collector
	policy    *calibration.ClusterPolicy
	errors    chan error
	once      sync.Once
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
	return &liveWorkTelemetry{
		collector: collector,
		policy:    policy,
		errors:    make(chan error, 1),
	}, nil
}

func (telemetry *liveWorkTelemetry) Observe(event activation.WorkAdmission) {
	if telemetry == nil {
		return
	}
	cluster, err := telemetry.policy.Cluster(event.Miner)
	if err == nil {
		_, err = telemetry.collector.ObserveWork(event.ObservedAt, event.ID, cluster)
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
			}
		}
	}()
	return telemetry.errors
}

func (telemetry *liveWorkTelemetry) Close(now uint64) error {
	if telemetry == nil {
		return nil
	}
	return telemetry.collector.Close(now)
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
