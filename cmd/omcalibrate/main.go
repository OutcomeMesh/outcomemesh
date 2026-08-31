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
	"strings"

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
	PlanID                string                         `json:"plan_id"`
	PlannedSlots          uint64                         `json:"planned_slots"`
	ReceiptCount          uint64                         `json:"receipt_count"`
	CompletedTrials       uint64                         `json:"completed_trials"`
	NoPairSlots           uint64                         `json:"no_pair_slots"`
	DisagreementSlots     uint64                         `json:"disagreement_slots,omitempty"`
	TestedAdoptions       uint64                         `json:"tested_adoptions"`
	ConservativeAdoptions uint64                         `json:"conservative_adoptions"`
	ObserverCount         uint64                         `json:"observer_count,omitempty"`
	ValidatedReceipts     uint64                         `json:"validated_receipts,omitempty"`
	CheckpointID          string                         `json:"checkpoint_id,omitempty"`
	Observers             []tieObserverCheckpointSummary `json:"observers,omitempty"`
	FirstReceiptID        string                         `json:"first_receipt_id,omitempty"`
	LastReceiptID         string                         `json:"last_receipt_id,omitempty"`
}

type tieObserverCheckpointSummary struct {
	ObserverPublicKey  string `json:"observer_public_key"`
	PublishedReceiptID string `json:"published_receipt_id"`
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
	var tieManifestPathsText, tieObserverPublicKeysText, tieTailIDsText string
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
	flags.StringVar(&tieManifestPathsText, "tie-manifests", "", "comma-separated canonical v2 observer manifest paths")
	flags.StringVar(&tieObserverPublicKeysText, "tie-observer-public-keys", "", "comma-separated canonical v2 receipt observer public keys")
	flags.StringVar(&tieTailIDsText, "tie-tail-ids", "", "comma-separated published v2 observer receipt tail IDs")
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
	multiTieRequested := tieManifestPathsText != "" || tieObserverPublicKeysText != "" || tieTailIDsText != ""
	singleTieRequested := tieManifestPath != "" || config.TieEvidenceTailID != ""
	if manifestPath != "" {
		if networkID == 0 || networkID > uint(^uint32(0)) || activationHeight == 0 || config.CoordinatedClusters == 0 ||
			config.CoordinatedClusters > telemetry.MaximumClusters || singleTieRequested == multiTieRequested {
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
		var telemetryTailID, publishedPlanID [32]byte
		if err := decodeCanonicalHex("evidence-tail-id", config.EvidenceTailID, telemetryTailID[:]); err != nil {
			return err
		}
		if err := decodeCanonicalHex("tie-plan-id", config.TiePlanID, publishedPlanID[:]); err != nil {
			return err
		}
		if multiTieRequested {
			paths, checkpoints, err := parseMultiTieInputs(
				tieManifestPathsText, tieObserverPublicKeysText, tieTailIDsText,
			)
			if err != nil || tieManifestPath != "" || config.TieEvidenceTailID != "" {
				return errors.Join(errors.New("invalid multi-observer tie evidence flags"), err)
			}
			expected := telemetry.MultiEvidenceBinding{
				Telemetry: binding, TiePlan: tieBinding,
				TelemetryTailID: telemetryTailID, PublishedTiePlanID: publishedPlanID,
				ObserverCheckpoints: checkpoints,
			}
			evidence, err := telemetry.LoadMultiObserverEvidenceFiles(manifestPath, paths, expected)
			if err != nil {
				return err
			}
			checkpointID, err := evidence.Tie.CheckpointID()
			if err != nil {
				return err
			}
			config.TieEvidenceTailID = checkpointID.String()
			applyVerifiedEvidenceConfig(
				&config, evidence.Telemetry, evidence.ControlledTieAdoptions, evidence.ControlledTieTrials,
				evidence.Tie.CompletedTrials, evidence.Tie.NoPairSlots, evidence.Tie.PlannedSlots,
				evidence.Tie.ObserverCount, evidence.Tie.ValidatedReceipts, evidence.Tie.DisagreementSlots,
				telemetry.TiePlanVersion2,
			)
			summary = summarizeManifest(evidence.Telemetry)
			observers := make([]tieObserverCheckpointSummary, len(evidence.Tie.ObserverCheckpoints))
			for index, checkpoint := range evidence.Tie.ObserverCheckpoints {
				observers[index] = tieObserverCheckpointSummary{
					ObserverPublicKey:  hex.EncodeToString(checkpoint.ObserverPublicKey[:]),
					PublishedReceiptID: checkpoint.PublishedReceiptID.String(),
				}
			}
			tieSummary = &tieManifestSummary{
				PlanID: evidence.Tie.PlanID.String(), PlannedSlots: evidence.Tie.PlannedSlots,
				ReceiptCount: evidence.Tie.PlannedSlots, CompletedTrials: evidence.Tie.CompletedTrials,
				NoPairSlots: evidence.Tie.NoPairSlots, DisagreementSlots: evidence.Tie.DisagreementSlots,
				TestedAdoptions:       evidence.Tie.TestedAdoptions,
				ConservativeAdoptions: evidence.Tie.ConservativeAdoptions,
				ObserverCount:         evidence.Tie.ObserverCount, ValidatedReceipts: evidence.Tie.ValidatedReceipts,
				CheckpointID: checkpointID.String(), Observers: observers,
			}
		} else {
			expected := telemetry.EvidenceBinding{
				Telemetry: binding, TiePlan: tieBinding,
				TelemetryTailID: telemetryTailID, PublishedTiePlanID: publishedPlanID,
			}
			if tieManifestPath == "" {
				return errors.New("tie-manifest is required")
			}
			if err := decodeCanonicalHex("tie-tail-id", config.TieEvidenceTailID, expected.PublishedTieReceiptID[:]); err != nil {
				return err
			}
			evidence, err := telemetry.LoadEvidenceFiles(manifestPath, tieManifestPath, expected)
			if err != nil {
				return err
			}
			applyVerifiedEvidenceConfig(
				&config, evidence.Telemetry, evidence.ControlledTieAdoptions, evidence.ControlledTieTrials,
				evidence.Tie.CompletedTrials, evidence.Tie.NoPairSlots, evidence.Tie.ReceiptCount,
				1, evidence.Tie.ReceiptCount, 0, telemetry.TiePlanVersion1,
			)
			summary = summarizeManifest(evidence.Telemetry)
			tieSummary = &tieManifestSummary{
				PlanID: evidence.Tie.PlanID.String(), PlannedSlots: evidence.Tie.PlannedSlots,
				ReceiptCount: evidence.Tie.ReceiptCount, CompletedTrials: evidence.Tie.CompletedTrials,
				NoPairSlots: evidence.Tie.NoPairSlots, TestedAdoptions: evidence.Tie.TestedAdoptions,
				ConservativeAdoptions: evidence.Tie.ConservativeAdoptions,
				FirstReceiptID:        evidence.Tie.FirstReceiptID.String(), LastReceiptID: evidence.Tie.LastReceiptID.String(),
			}
		}
	} else if singleTieRequested || multiTieRequested {
		return errors.New("tie evidence requires manifest")
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

func applyVerifiedEvidenceConfig(
	config *workgraphmodel.PublicTestnetCalibrationConfig,
	aggregate telemetry.Aggregate,
	adoptions uint64,
	trials uint64,
	completed uint64,
	noPair uint64,
	receipts uint64,
	observerCount uint64,
	validatedReceipts uint64,
	disagreementSlots uint64,
	tiePlanVersion uint16,
) {
	config.ObservationWindowSeconds = aggregate.EndedAt - aggregate.StartedAt
	config.ControlledTieAdoptions = adoptions
	config.ControlledTieTrials = trials
	config.TieCompletedTrials = completed
	config.TieNoPairSlots = noPair
	config.LargestCoordinatedWork = aggregate.LargestCoordinatedWork
	config.ObservedWork = aggregate.ObservedWork
	config.CoordinatedClusters = uint64(aggregate.Binding.ClusterComparisonBudget)
	config.EvidenceRecords = aggregate.RecordCount
	config.EvidenceVerified = true
	config.TiePlanVersion = tiePlanVersion
	config.TieEvidenceReceipts = receipts
	config.TieObserverCount = observerCount
	config.TieValidatedReceipts = validatedReceipts
	config.TieDisagreementSlots = disagreementSlots
	config.TieEvidenceVerified = true
}

func summarizeManifest(aggregate telemetry.Aggregate) *manifestSummary {
	return &manifestSummary{
		RecordCount: aggregate.RecordCount, StartedAt: aggregate.StartedAt, EndedAt: aggregate.EndedAt,
		FirstRecordID: aggregate.FirstRecordID.String(), LastRecordID: aggregate.LastRecordID.String(),
	}
}

func parseMultiTieInputs(
	pathsText string,
	observerKeysText string,
	tailIDsText string,
) ([]string, []telemetry.TieObserverCheckpoint, error) {
	paths, err := parseCanonicalList("tie-manifests", pathsText)
	if err != nil {
		return nil, nil, err
	}
	observerKeys, err := parseCanonicalList("tie-observer-public-keys", observerKeysText)
	if err != nil {
		return nil, nil, err
	}
	tailIDs, err := parseCanonicalList("tie-tail-ids", tailIDsText)
	if err != nil {
		return nil, nil, err
	}
	if len(paths) < 2 || len(paths) > telemetry.MaximumTieObservers ||
		len(observerKeys) != len(paths) || len(tailIDs) != len(paths) {
		return nil, nil, errors.New("multi-observer tie lists must contain the same 2..64 entries")
	}
	checkpoints := make([]telemetry.TieObserverCheckpoint, len(paths))
	for index := range paths {
		if err := decodeCanonicalHex(
			fmt.Sprintf("tie-observer-public-keys[%d]", index), observerKeys[index],
			checkpoints[index].ObserverPublicKey[:],
		); err != nil {
			return nil, nil, err
		}
		if err := decodeCanonicalHex(
			fmt.Sprintf("tie-tail-ids[%d]", index), tailIDs[index],
			checkpoints[index].PublishedReceiptID[:],
		); err != nil {
			return nil, nil, err
		}
	}
	return paths, checkpoints, nil
}

func parseCanonicalList(label, input string) ([]string, error) {
	if input == "" || strings.TrimSpace(input) != input {
		return nil, fmt.Errorf("invalid %s", label)
	}
	values := strings.Split(input, ",")
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value {
			return nil, fmt.Errorf("invalid %s", label)
		}
	}
	return values, nil
}

func decodeCanonicalHex(label, input string, destination []byte) error {
	decoded, err := hex.DecodeString(input)
	if err != nil || len(decoded) != len(destination) || hex.EncodeToString(decoded) != input {
		return fmt.Errorf("invalid %s", label)
	}
	copy(destination, decoded)
	return nil
}
