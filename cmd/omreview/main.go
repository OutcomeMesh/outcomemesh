// Command omreview emits the deterministic WorkGraph economic activation
// corpus and its canonical SHA-256 digest as JSON.
package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"os"

	"github.com/outcomemesh/outcomemesh/sim/workgraphmodel"
)

type output struct {
	DigestSHA256 string                                  `json:"digest_sha256"`
	Document     workgraphmodel.ActivationReviewDocument `json:"document"`
}

func main() {
	log.SetFlags(0)
	document, err := workgraphmodel.RunActivationReview(
		workgraphmodel.CanonicalActivationReviewConfig(),
	)
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
