// Command omcalibrate evaluates an aggregate public-testnet ER-5 evidence
// snapshot and emits its canonical SHA-256 digest as JSON.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/outcomemesh/outcomemesh/sim/workgraphmodel"
)

type output struct {
	DigestSHA256 string                                          `json:"digest_sha256"`
	Document     workgraphmodel.PublicTestnetCalibrationDocument `json:"document"`
}

func main() {
	log.SetFlags(0)
	config := workgraphmodel.PublicTestnetCalibrationConfig{}
	var maximumUpper uint
	flag.Uint64Var(&config.ObservationWindowSeconds, "window-seconds", 0, "continuous observation-window length")
	flag.Uint64Var(&config.ControlledTieAdoptions, "tie-adoptions", 0, "tested-branch adoptions in controlled tie races")
	flag.Uint64Var(&config.ControlledTieTrials, "tie-trials", 0, "independent controlled tie races")
	flag.Uint64Var(&config.LargestCoordinatedWork, "coordinated-work", 0, "work observations attributed to the predeclared largest coordination cluster")
	flag.Uint64Var(&config.ObservedWork, "observed-work", 0, "independent work observations")
	flag.Uint64Var(&config.CoordinatedClusters, "coordinated-clusters", 0, "predeclared coordination clusters compared when selecting the largest")
	flag.UintVar(&maximumUpper, "maximum-upper-ppm", uint(workgraphmodel.PublicTestnetMaximumUpperPPM), "maximum permitted 99% upper bound")
	flag.Parse()
	if maximumUpper > uint(workgraphmodel.PartsPerMillion) {
		log.Fatal("maximum-upper-ppm exceeds one million")
	}
	config.MaximumUpperPPM = uint32(maximumUpper)

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
	}); err != nil {
		log.Fatal(err)
	}
}
