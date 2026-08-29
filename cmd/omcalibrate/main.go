// Command omcalibrate evaluates an aggregate public-testnet ER-5 evidence
// snapshot and emits its canonical SHA-256 digest as JSON.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	telemetry "github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/sim/workgraphmodel"
)

type output struct {
	DigestSHA256 string                                          `json:"digest_sha256"`
	Document     workgraphmodel.PublicTestnetCalibrationDocument `json:"document"`
	Manifest     *manifestSummary                                `json:"manifest,omitempty"`
	TieManifest  *tieManifestSummary                             `json:"tie_manifest,omitempty"`
}

type manifestSummary struct {
	RecordCount   uint64 `json:"record_count"`
	StartedAt     uint64 `json:"started_at"`
	EndedAt       uint64 `json:"ended_at"`
	FirstRecordID string `json:"first_record_id"`
	LastRecordID  string `json:"last_record_id"`
}

type tieManifestSummary struct {
	PlanID                string `json:"plan_id"`
	PlannedSlots          uint64 `json:"planned_slots"`
	ReceiptCount          uint64 `json:"receipt_count"`
	CompletedTrials       uint64 `json:"completed_trials"`
	NoPairSlots           uint64 `json:"no_pair_slots"`
	TestedAdoptions       uint64 `json:"tested_adoptions"`
	ConservativeAdoptions uint64 `json:"conservative_adoptions"`
	FirstReceiptID        string `json:"first_receipt_id"`
	LastReceiptID         string `json:"last_receipt_id"`
}

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(arguments []string, outputWriter io.Writer) error {
	config := workgraphmodel.PublicTestnetCalibrationConfig{}
	var maximumUpper uint
	var manifestPath, tieManifestPath string
	var networkID uint
	var activationHeight uint64
	var genesisIDHex, clusterPolicyIDHex, observerPublicKeyHex, coordinatorPublicKeyHex string
	flags := flag.NewFlagSet("omcalibrate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Uint64Var(&config.ObservationWindowSeconds, "window-seconds", 0, "continuous observation-window length")
	flags.Uint64Var(&config.ControlledTieAdoptions, "tie-adoptions", 0, "tested-branch adoptions in controlled tie races")
	flags.Uint64Var(&config.ControlledTieTrials, "tie-trials", 0, "independent controlled tie races")
	flags.Uint64Var(&config.LargestCoordinatedWork, "coordinated-work", 0, "work observations attributed to the predeclared largest coordination cluster")
	flags.Uint64Var(&config.ObservedWork, "observed-work", 0, "independent work observations")
	flags.Uint64Var(&config.CoordinatedClusters, "coordinated-clusters", 0, "predeclared coordination clusters compared when selecting the largest")
	flags.StringVar(&config.EvidenceTailID, "evidence-tail-id", "", "published lowercase-hex telemetry tail record ID")
	flags.UintVar(&maximumUpper, "maximum-upper-ppm", uint(workgraphmodel.PublicTestnetMaximumUpperPPM), "maximum permitted 99% upper bound")
	flags.StringVar(&manifestPath, "manifest", "", "signed telemetry manifest to verify and aggregate")
	flags.StringVar(&tieManifestPath, "tie-manifest", "", "signed raw controlled-tie manifest to verify and aggregate")
	flags.UintVar(&networkID, "network-id", 0, "trusted manifest network ID")
	flags.StringVar(&genesisIDHex, "genesis-id", "", "trusted lowercase-hex genesis ID")
	flags.Uint64Var(&activationHeight, "activation-height", 0, "trusted WorkGraph activation height")
	flags.StringVar(&clusterPolicyIDHex, "cluster-policy-id", "", "trusted lowercase-hex cluster-policy ID")
	flags.StringVar(&observerPublicKeyHex, "observer-public-key", "", "trusted lowercase-hex Ed25519 observer public key")
	flags.StringVar(&coordinatorPublicKeyHex, "coordinator-public-key", "", "trusted lowercase-hex controlled-tie coordinator public key")
	flags.StringVar(&config.TiePlanID, "tie-plan-id", "", "externally precommitted lowercase-hex controlled-tie plan ID")
	flags.StringVar(&config.TieEvidenceTailID, "tie-tail-id", "", "published lowercase-hex controlled-tie receipt tail ID")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("unexpected positional arguments")
	}
	if maximumUpper > uint(workgraphmodel.PartsPerMillion) {
		return errors.New("maximum-upper-ppm exceeds one million")
	}
	config.MaximumUpperPPM = uint32(maximumUpper)
	var summary *manifestSummary
	var tieSummary *tieManifestSummary
	if manifestPath != "" {
		if networkID == 0 || networkID > uint(^uint32(0)) || activationHeight == 0 || config.CoordinatedClusters == 0 ||
			config.CoordinatedClusters > telemetry.MaximumClusters || tieManifestPath == "" {
			return errors.New("manifest binding flags are incomplete or out of range")
		}
		binding := telemetry.Binding{
			NetworkID: uint32(networkID), ActivationHeight: activationHeight,
			ClusterComparisonBudget: uint32(config.CoordinatedClusters),
		}
		if err := decodeCanonicalHex("genesis-id", genesisIDHex, binding.GenesisID[:]); err != nil {
			return err
		}
		if err := decodeCanonicalHex("cluster-policy-id", clusterPolicyIDHex, binding.ClusterPolicyID[:]); err != nil {
			return err
		}
		if err := decodeCanonicalHex("observer-public-key", observerPublicKeyHex, binding.ObserverPublicKey[:]); err != nil {
			return err
		}
		tieBinding := telemetry.TiePlanBinding{
			NetworkID: binding.NetworkID, GenesisID: binding.GenesisID,
			ActivationHeight: binding.ActivationHeight, ObserverPublicKey: binding.ObserverPublicKey,
		}
		if err := decodeCanonicalHex("coordinator-public-key", coordinatorPublicKeyHex, tieBinding.CoordinatorPublicKey[:]); err != nil {
			return err
		}
		expected := telemetry.EvidenceBinding{Telemetry: binding, TiePlan: tieBinding}
		if err := decodeCanonicalHex("evidence-tail-id", config.EvidenceTailID, expected.TelemetryTailID[:]); err != nil {
			return err
		}
		if err := decodeCanonicalHex("tie-plan-id", config.TiePlanID, expected.PublishedTiePlanID[:]); err != nil {
			return err
		}
		if err := decodeCanonicalHex("tie-tail-id", config.TieEvidenceTailID, expected.PublishedTieReceiptID[:]); err != nil {
			return err
		}
		evidence, err := telemetry.LoadEvidenceFiles(manifestPath, tieManifestPath, expected)
		if err != nil {
			return err
		}
		aggregate := evidence.Telemetry
		config.ObservationWindowSeconds = aggregate.EndedAt - aggregate.StartedAt
		config.ControlledTieAdoptions = evidence.ControlledTieAdoptions
		config.ControlledTieTrials = evidence.ControlledTieTrials
		config.TieCompletedTrials = evidence.Tie.CompletedTrials
		config.TieNoPairSlots = evidence.Tie.NoPairSlots
		config.LargestCoordinatedWork = aggregate.LargestCoordinatedWork
		config.ObservedWork = aggregate.ObservedWork
		config.CoordinatedClusters = uint64(aggregate.Binding.ClusterComparisonBudget)
		config.EvidenceRecords = aggregate.RecordCount
		config.EvidenceVerified = true
		config.TieEvidenceReceipts = evidence.Tie.ReceiptCount
		config.TieEvidenceVerified = true
		summary = &manifestSummary{
			RecordCount: aggregate.RecordCount, StartedAt: aggregate.StartedAt, EndedAt: aggregate.EndedAt,
			FirstRecordID: aggregate.FirstRecordID.String(), LastRecordID: aggregate.LastRecordID.String(),
		}
		tieSummary = &tieManifestSummary{
			PlanID: evidence.Tie.PlanID.String(), PlannedSlots: evidence.Tie.PlannedSlots,
			ReceiptCount: evidence.Tie.ReceiptCount, CompletedTrials: evidence.Tie.CompletedTrials,
			NoPairSlots: evidence.Tie.NoPairSlots, TestedAdoptions: evidence.Tie.TestedAdoptions,
			ConservativeAdoptions: evidence.Tie.ConservativeAdoptions,
			FirstReceiptID:        evidence.Tie.FirstReceiptID.String(), LastReceiptID: evidence.Tie.LastReceiptID.String(),
		}
	} else if tieManifestPath != "" {
		return errors.New("tie-manifest requires manifest")
	}

	document, err := workgraphmodel.EvaluatePublicTestnetCalibration(config)
	if err != nil {
		return err
	}
	digest, err := document.Digest()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output{
		DigestSHA256: hex.EncodeToString(digest[:]),
		Document:     document,
		Manifest:     summary,
		TieManifest:  tieSummary,
	}); err != nil {
		return err
	}
	return nil
}

func decodeCanonicalHex(label, input string, destination []byte) error {
	decoded, err := hex.DecodeString(input)
	if err != nil || len(decoded) != len(destination) || hex.EncodeToString(decoded) != input {
		return fmt.Errorf("invalid %s", label)
	}
	copy(destination, decoded)
	return nil
}
