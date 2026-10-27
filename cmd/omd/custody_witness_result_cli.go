package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/custodyproof"
)

const witnessResultCommand = "work-archive-custody-witness-result"

func runWitnessResult(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	common := addCustodyCommandScopeFlags(f)
	mode := f.String("mode", "review", "review by default; publish a verified bundle or verify an existing bundle")
	scopePath := f.String("witness-scope", "", "independently selected witness scope")
	scopeID := f.String("witness-scope-id", "", "independent witness scope ID")
	planPath := f.String("plan", "", "pinned original plan")
	planID := f.String("plan-id", "", "independent plan ID")
	beginPath := f.String("begin", "", "original Begin proposal")
	beginID := f.String("begin-id", "", "independent Begin ID")
	challengePath := f.String("challenge", "", "original signed challenge")
	challengeID := f.String("challenge-id", "", "independent challenge ID")
	auditPath := f.String("audit-admission", "", "original Audit admission")
	auditID := f.String("audit-ticket-id", "", "independent Audit admission ID")
	terminalPath := f.String("terminal", "", "build only: original positive historical terminal")
	terminalID := f.String("terminal-id", "", "independent terminal ID")
	chainPath := f.String("chain", "", "build only: bounded JSON list of certificate file/id pairs")
	bundlePath := f.String("bundle", "", "existing quorum-bound custody result")
	bundleID := f.String("bundle-id", "", "independent result bundle ID")
	output := f.String("out", "", "publish only: immutable output")
	reviewID := f.String("expected-review-id", "", "publish only: exact reviewed bundle ID")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || (*mode != "review" && *mode != "verify" && *mode != "publish") {
		return errors.New("unsupported witness result mode")
	}
	scope, sources, err := common.loadVersion(custodyauthority.Version1)
	if err != nil {
		return err
	}
	pin, err := witnessID("witness-scope-id", *scopeID)
	if err != nil {
		return err
	}
	file, err := custodyCommandFile(*scopePath)
	if err != nil {
		return err
	}
	raw, err := readRegularArtifact(file, custodyfence.MaximumScopeBytes)
	if err != nil {
		return err
	}
	witness, err := custodyfence.DecodeScope(raw)
	if err != nil {
		return err
	}
	plan, pfile, err := remoteOfflinePlan(*planPath, *planID)
	if err != nil {
		return err
	}
	begin, bfile, err := custodyCommandEntry(*beginPath, *beginID)
	if err != nil {
		return err
	}
	challenge, cfile, err := custodyCommandChallenge(*challengePath, *challengeID)
	if err != nil {
		return err
	}
	remote, err := remoteOfflineScope(scope, plan, begin, challenge)
	if err != nil {
		return err
	}
	audit, afile, err := custodyCommandEntry(*auditPath, *auditID)
	if err != nil {
		return err
	}
	inputs := []string{file, pfile, bfile, cfile, afile, sources.Assignment, sources.Manifest, sources.InitialReceipt, sources.PreviousReceipt, sources.Intent}
	var bundle custodyproof.Bundle
	if *bundlePath != "" {
		if *terminalPath != "" || *terminalID != "" || *chainPath != "" || *mode == "publish" {
			return errors.New("existing bundle verification cannot select assembly inputs")
		}
		file, err := custodyCommandFile(*bundlePath)
		if err != nil {
			return err
		}
		raw, err := readRegularArtifact(file, custodyproof.MaximumBundleBytes)
		if err != nil {
			return err
		}
		bundle, err = custodyproof.DecodeBundle(raw)
		if err != nil {
			return err
		}
		pin, err := witnessID("bundle-id", *bundleID)
		id, _ := bundle.ID()
		if err != nil || pin != id {
			return custodyproof.ErrResult
		}
	} else {
		if *bundleID != "" || *mode == "verify" {
			return errors.New("verify requires an existing independently pinned bundle")
		}
		terminalPin, err := witnessID("terminal-id", *terminalID)
		if err != nil {
			return err
		}
		file, err := custodyCommandFile(*terminalPath)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		terminal, err := store.LoadRemoteCustodyTerminal(file, terminalPin)
		if err != nil {
			return err
		}
		file, err = custodyCommandFile(*chainPath)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		raw, err := readRegularArtifact(file, 32768)
		if err != nil {
			return err
		}
		var chain []struct {
			File string `json:"file"`
			ID   string `json:"id"`
		}
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		if err := d.Decode(&chain); err != nil {
			return err
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return errors.New("trailing certificate list data")
		}
		if len(chain) < 2 || len(chain) > 3 {
			return custodyproof.ErrResult
		}
		bundle = custodyproof.Bundle{ScopeID: pin, Terminal: terminal}
		for _, entry := range chain {
			file, err := custodyCommandFile(entry.File)
			if err != nil {
				return err
			}
			inputs = append(inputs, file)
			raw, err := readRegularArtifact(file, custodyfence.MaximumCertificateBytes)
			if err != nil {
				return err
			}
			id, err := witnessID("certificate-id", entry.ID)
			if err != nil || id != witnessArtifactID("certificate", raw) {
				return custodyfence.ErrQuorum
			}
			cert, err := custodyfence.DecodeCertificate(raw)
			if err != nil {
				return err
			}
			bundle.Chain = append(bundle.Chain, cert)
		}
	}
	if err := bundle.Verify(witness, pin, remote, scope.Intent, audit); err != nil {
		return err
	}
	id, _ := bundle.ID()
	if err := ctx.Err(); err != nil {
		return err
	}
	if *mode == "publish" {
		expected, err := witnessID("expected-review-id", *reviewID)
		if err != nil || expected != id {
			return errors.New("publication requires the exact reviewed result bundle ID")
		}
		path, err := custodyCommandOutput(*output)
		if err != nil {
			return err
		}
		if err := rejectPruneLineageOutputAlias(path, inputs); err != nil {
			return err
		}
		raw, _ := bundle.CanonicalBytes()
		if err := publishCustodyCommandArtifact(path, raw); err != nil {
			return err
		}
	} else if *reviewID != "" || *output != "" {
		return errors.New("read-only result verification cannot select publication flags")
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_witness_result mode=%s bundle_id=%s review_id=%s historical_result_verified=true current_source_acceptance_checked=false proof_refreshed=false completion_submitted=false owners_opened=false keys_loaded=false\n", *mode, id, id))
}
