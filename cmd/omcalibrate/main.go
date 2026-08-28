// Command omcalibrate evaluates an aggregate public-testnet ER-5 evidence
// snapshot and emits its canonical SHA-256 digest as JSON.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	telemetry "github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/sim/workgraphmodel"
)

type output struct {
	DigestSHA256 string                                          `json:"digest_sha256"`
	Document     workgraphmodel.PublicTestnetCalibrationDocument `json:"document"`
	Manifest     *manifestSummary                                `json:"manifest,omitempty"`
}

type manifestSummary struct {
	RecordCount   uint64 `json:"record_count"`
	StartedAt     uint64 `json:"started_at"`
	EndedAt       uint64 `json:"ended_at"`
	FirstRecordID string `json:"first_record_id"`
	LastRecordID  string `json:"last_record_id"`
}

func main() {
	log.SetFlags(0)
	config := workgraphmodel.PublicTestnetCalibrationConfig{}
	var maximumUpper uint
	var manifestPath string
	var networkID uint
	var activationHeight uint64
	var genesisIDHex, clusterPolicyIDHex, observerPublicKeyHex string
	flag.Uint64Var(&config.ObservationWindowSeconds, "window-seconds", 0, "continuous observation-window length")
	flag.Uint64Var(&config.ControlledTieAdoptions, "tie-adoptions", 0, "tested-branch adoptions in controlled tie races")
	flag.Uint64Var(&config.ControlledTieTrials, "tie-trials", 0, "independent controlled tie races")
	flag.Uint64Var(&config.LargestCoordinatedWork, "coordinated-work", 0, "work observations attributed to the predeclared largest coordination cluster")
	flag.Uint64Var(&config.ObservedWork, "observed-work", 0, "independent work observations")
	flag.Uint64Var(&config.CoordinatedClusters, "coordinated-clusters", 0, "predeclared coordination clusters compared when selecting the largest")
	flag.StringVar(&config.EvidenceTailID, "evidence-tail-id", "", "published lowercase-hex telemetry tail record ID")
	flag.UintVar(&maximumUpper, "maximum-upper-ppm", uint(workgraphmodel.PublicTestnetMaximumUpperPPM), "maximum permitted 99% upper bound")
	flag.StringVar(&manifestPath, "manifest", "", "signed telemetry manifest to verify and aggregate")
	flag.UintVar(&networkID, "network-id", 0, "trusted manifest network ID")
	flag.StringVar(&genesisIDHex, "genesis-id", "", "trusted lowercase-hex genesis ID")
	flag.Uint64Var(&activationHeight, "activation-height", 0, "trusted WorkGraph activation height")
	flag.StringVar(&clusterPolicyIDHex, "cluster-policy-id", "", "trusted lowercase-hex cluster-policy ID")
	flag.StringVar(&observerPublicKeyHex, "observer-public-key", "", "trusted lowercase-hex Ed25519 observer public key")
	flag.Parse()
	if maximumUpper > uint(workgraphmodel.PartsPerMillion) {
		log.Fatal("maximum-upper-ppm exceeds one million")
	}
	config.MaximumUpperPPM = uint32(maximumUpper)
	var summary *manifestSummary
	if manifestPath != "" {
		if networkID == 0 || networkID > uint(^uint32(0)) || activationHeight == 0 || config.CoordinatedClusters == 0 ||
			config.CoordinatedClusters > telemetry.MaximumClusters {
			log.Fatal("manifest binding flags are incomplete or out of range")
		}
		binding := telemetry.Binding{
			NetworkID: uint32(networkID), ActivationHeight: activationHeight,
			ClusterComparisonBudget: uint32(config.CoordinatedClusters),
		}
		if err := decodeCanonicalHex("genesis-id", genesisIDHex, binding.GenesisID[:]); err != nil {
			log.Fatal(err)
		}
		if err := decodeCanonicalHex("cluster-policy-id", clusterPolicyIDHex, binding.ClusterPolicyID[:]); err != nil {
			log.Fatal(err)
		}
		if err := decodeCanonicalHex("observer-public-key", observerPublicKeyHex, binding.ObserverPublicKey[:]); err != nil {
			log.Fatal(err)
		}
		_, aggregate, err := telemetry.LoadFile(manifestPath, binding)
		if err != nil {
			log.Fatal(err)
		}
		if config.EvidenceTailID == "" || aggregate.LastRecordID.String() != config.EvidenceTailID {
			log.Fatal("manifest tail does not match evidence-tail-id")
		}
		config.ObservationWindowSeconds = aggregate.EndedAt - aggregate.StartedAt
		config.ControlledTieAdoptions = aggregate.ControlledTieAdoptions
		config.ControlledTieTrials = aggregate.ControlledTieTrials
		config.LargestCoordinatedWork = aggregate.LargestCoordinatedWork
		config.ObservedWork = aggregate.ObservedWork
		config.CoordinatedClusters = uint64(aggregate.Binding.ClusterComparisonBudget)
		config.EvidenceRecords = aggregate.RecordCount
		config.EvidenceVerified = true
		summary = &manifestSummary{
			RecordCount: aggregate.RecordCount, StartedAt: aggregate.StartedAt, EndedAt: aggregate.EndedAt,
			FirstRecordID: aggregate.FirstRecordID.String(), LastRecordID: aggregate.LastRecordID.String(),
		}
	}

	document, err := workgraphmodel.EvaluatePublicTestnetCalibration(config)
	if err != nil {
		log.Fatal(err)
	}
	digest, err := document.Digest()
	if err != nil {
		log.Fatal(err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output{
		DigestSHA256: hex.EncodeToString(digest[:]),
		Document:     document,
		Manifest:     summary,
	}); err != nil {
		log.Fatal(err)
	}
}

func decodeCanonicalHex(label, input string, destination []byte) error {
	decoded, err := hex.DecodeString(input)
	if err != nil || len(decoded) != len(destination) || hex.EncodeToString(decoded) != input {
		return fmt.Errorf("invalid %s", label)
	}
	copy(destination, decoded)
	return nil
}
