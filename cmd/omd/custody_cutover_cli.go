package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
	s "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	wire "github.com/outcomemesh/outcomemesh/node/custodyregistry/registrywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const custodyCutoverCommand = "work-archive-custody-cutover-review"

func runCustodyCutoverCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyCutover(ctx, args, os.Stdout)
}
func cutoverArtifactID(raw []byte) types.Hash {
	return types.DomainHash("OMESH/custody-cutover-review/v1/cli/artifact/id", raw)
}

// Require a complete typed JSON shape. In addition to unknown/duplicate keys,
// reject overlong fixed key arrays which encoding/json otherwise truncates.
func cutoverJSON(raw []byte, value any) error {
	var read func(*json.Decoder, int) error
	read = func(d *json.Decoder, depth int) error {
		if depth > 64 {
			return cut.ErrPreparation
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return cut.ErrPreparation
				}
				seen[name] = true
				if err = read(d, depth+1); err != nil {
					return err
				}
			}
		} else if delim == '[' {
			for d.More() {
				if err = read(d, depth+1); err != nil {
					return err
				}
			}
		} else {
			return cut.ErrPreparation
		}
		end, err := d.Token()
		if err != nil || delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return cut.ErrPreparation
		}
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := read(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return cut.ErrPreparation
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return err
	}
	normalize := func(input []byte) ([]byte, error) {
		var v any
		d := json.NewDecoder(bytes.NewReader(input))
		d.UseNumber()
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		return json.Marshal(v)
	}
	left, err := normalize(raw)
	if err != nil {
		return err
	}
	right, err := normalize(canonical)
	if err != nil || !bytes.Equal(left, right) {
		return cut.ErrPreparation
	}
	return nil
}
func runCustodyCutover(ctx context.Context, args []string, out io.Writer) (returnErr error) {
	if ctx == nil || out == nil || len(args) == 0 || args[0] != custodyCutoverCommand {
		return cut.ErrPreparation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if file, ok := out.(*os.File); ok && (runtime.GOOS == "darwin" || runtime.GOOS == "linux") {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeNamedPipe != 0 {
			writer, err := ownPruneEffectOutput(out)
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
			out = writer
		}
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mode := fs.String("mode", "review", "review or run")
	action := fs.String("action", "", "import-genesis, history-export, assess, source-location, observe, proposal, sign-proposal, verify-proposal, prepare, read-preparation, recover-preparation")
	evidencePath := fs.String("evidence", "", "complete canonical legacy evidence")
	template := fs.String("template", "", "complete Evidence JSON with empty history and zero end")
	source := fs.String("source", "", "complete SourceLocation JSON; independently retained placement pin required for observe")
	anchorPath := fs.String("anchor", "", "public stable resource Genesis2 descriptor; no selection or grant")
	anchorID := fs.String("anchor-id", "", "independent stable semantic resource ID")
	descriptorID := fs.String("descriptor-id", "", "independent full descriptor ID")
	legacyID := fs.String("legacy-id", "", "independent original V1 assignment ID")
	sequence := fs.String("retired-sequence", "", "independent exact retired authority sequence")
	head := fs.String("retired-head", "", "independent exact retired authority head")
	authority := fs.String("authority", "", "original authority directory; history-export only")
	pinsPath := fs.String("authority-pins", "", "original coordinator pin directory; history-export only")
	placement := fs.String("placement-id", "", "independent exact local SourceLocation ID")
	nonce := fs.String("nonce", "", "explicit nonzero observation nonce")
	aPath := fs.String("a-observation", "", "full canonical original A observation")
	bPath := fs.String("b-observation", "", "full canonical original B observation")
	blueprint := fs.String("blueprint", "", "complete non-runtime Blueprint JSON")
	allowance := fs.String("allowance", "", "explicit remaining operation allowance; no refund")
	proposalPath := fs.String("proposal", "", "complete canonical disabled proposal")
	proposalID := fs.String("proposal-id", "", "independent exact proposal ID; preparation actions")
	role := fs.String("role", "", "issuer, authority or control; sign-proposal only")
	signKey := fs.String("sign-key", "", "existing private role seed; never read during review")
	root := fs.String("root", "", "original disabled preparation directory")
	output := fs.String("out", "", "fresh immutable output outside owners and sources")
	expected := fs.String("expected-review-id", "", "exact public action review ID")
	if err := parsePruneFlags(fs, args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*mode != "review" && *mode != "run") {
		return cut.ErrPreparation
	}
	common := []string{"legacy-id", "retired-sequence", "retired-head"}
	selectors := map[string][]string{
		"history-export": {"template", "authority", "authority-pins"}, "assess": {"evidence"}, "source-location": {"source"},
		"observe":       {"evidence", "source", "anchor-id", "placement-id", "nonce", "sign-key"},
		"proposal":      {"evidence", "anchor", "anchor-id", "descriptor-id", "a-observation", "b-observation", "blueprint", "allowance"},
		"sign-proposal": {"proposal", "anchor-id", "descriptor-id", "role", "sign-key"}, "verify-proposal": {"proposal", "anchor-id", "descriptor-id"},
		"import-genesis":   {"proposal", "anchor-id", "descriptor-id", "proposal-id"},
		"prepare":          {"proposal", "anchor-id", "descriptor-id", "proposal-id", "root"},
		"read-preparation": {"anchor-id", "descriptor-id", "proposal-id", "root"}, "recover-preparation": {"anchor-id", "descriptor-id", "proposal-id", "root"},
	}
	selected, ok := selectors[*action]
	if !ok {
		return cut.ErrPreparation
	}
	allowed := map[string]bool{"action": true, "mode": true, "out": true, "expected-review-id": true}
	for _, name := range selected {
		allowed[name] = true
	}
	if *action != "source-location" {
		for _, name := range common {
			allowed[name] = true
		}
	}
	present := custodyCommandPresence(fs)
	if *action == "prepare" && present["out"] {
		return errors.New("prepare retains the proposal in its original root; --out is unused")
	}
	for name := range present {
		if !allowed[name] {
			return fmt.Errorf("--%s is not used by action %s", name, *action)
		}
	}
	inputs := []string{}
	inputIDs := map[string]string{}
	load := func(path string, limit int) ([]byte, error) {
		p, err := custodyCommandFile(path)
		if err != nil {
			return nil, err
		}
		raw, err := readRegularArtifact(p, limit)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, p)
		inputIDs[p] = cutoverArtifactID(raw).String()
		return raw, nil
	}
	var pin cut.Pins
	var evidence cut.Evidence
	var proposal cut.Proposal
	var location cut.SourceLocation
	var assessment cut.Assessment
	var bridge cut.Bridge
	var prepared []byte
	var locationID, explicitNonce types.Hash
	var err error
	if *action != "source-location" {
		pin.LegacyID, err = witnessID("legacy-id", *legacyID)
		if err != nil {
			return err
		}
		pin.Retired.Sequence, err = strconv.ParseUint(*sequence, 10, 64)
		if err != nil || pin.Retired.Sequence == 0 || pin.Retired.Sequence > cut.MaximumHistoryEntries {
			return cut.ErrPreparation
		}
		pin.Retired.HeadID, err = witnessID("retired-head", *head)
		if err != nil {
			return err
		}
	}
	if allowed["anchor-id"] {
		pin.AnchorID, err = witnessID("anchor-id", *anchorID)
		if err != nil {
			return err
		}
	}
	if allowed["descriptor-id"] {
		pin.DescriptorID, err = witnessID("descriptor-id", *descriptorID)
		if err != nil {
			return err
		}
	}
	if allowed["proposal-id"] {
		pin.ProposalID, err = witnessID("proposal-id", *proposalID)
		if err != nil {
			return err
		}
	}
	if allowed["evidence"] {
		raw, err := load(*evidencePath, cut.MaximumEvidenceBytes)
		if err != nil {
			return err
		}
		evidence, err = cut.DecodeEvidence(raw)
		if err != nil {
			return err
		}
		assessment, err = evidence.Verify(pin.LegacyID, pin.Retired)
		if err != nil {
			return err
		}
	}
	if allowed["proposal"] {
		raw, err := load(*proposalPath, cut.MaximumProposalBytes)
		if err != nil {
			return err
		}
		proposal, err = cut.DecodeProposal(raw)
		if err != nil {
			return err
		}
		bridge, err = proposal.ValidateDraft(pin.AnchorID, pin.DescriptorID, pin.LegacyID, pin.Retired)
		if err != nil {
			return err
		}
		if *action != "sign-proposal" {
			bridge, err = proposal.Verify(pin.AnchorID, pin.DescriptorID, pin.LegacyID, pin.Retired)
			if err != nil {
				return err
			}
		}
		if *action == "prepare" || *action == "import-genesis" {
			id, _ := proposal.ID()
			if id != pin.ProposalID {
				return cut.ErrPreparation
			}
		}
	}
	owners := []string{}
	directory := func(path string) (string, error) {
		if path == "" {
			return "", cut.ErrPreparation
		}
		return canonicalPruneLineageDirectory(path)
	}
	if *action == "history-export" {
		raw, err := load(*template, cut.MaximumEvidenceBytes)
		if err != nil {
			return err
		}
		if err = cutoverJSON(raw, &evidence); err != nil {
			return err
		}
		if evidence.Version != cut.Version1 || len(evidence.History) != 0 || evidence.End != (a.Position{}) || len(evidence.Cycles) > cut.MaximumCycles {
			return cut.ErrEvidence
		}
		id, err := evidence.Assignment.ID()
		if err != nil || id != pin.LegacyID {
			return cut.ErrEvidence
		}
		*authority, err = directory(*authority)
		if err != nil {
			return err
		}
		*pinsPath, err = directory(*pinsPath)
		if err != nil {
			return err
		}
		owners = append(owners, *authority, *pinsPath)
	}
	if allowed["source"] {
		raw, err := load(*source, 1<<20)
		if err != nil {
			return err
		}
		if err = cutoverJSON(raw, &location); err != nil {
			return err
		}
		for _, path := range []*string{&location.Journal, &location.Authority, &location.AuthorityPins} {
			if *path != "" {
				*path, err = directory(*path)
				if err != nil {
					return err
				}
				owners = append(owners, *path)
			}
		}
		for i := range location.Workers {
			location.Workers[i], err = directory(location.Workers[i])
			if err != nil {
				return err
			}
			owners = append(owners, location.Workers[i])
		}
		locationID, err = location.LocationID()
		if err != nil {
			return err
		}
		if *action == "observe" {
			want, err := witnessID("placement-id", *placement)
			if err != nil || want != locationID {
				return cut.ErrPreparation
			}
			explicitNonce, err = witnessID("nonce", *nonce)
			if err != nil {
				return err
			}
			if location.Role == cut.Target && len(location.Workers) != len(evidence.Cycles) {
				return cut.ErrPreparation
			}
		}
	}
	if *action == "proposal" {
		raw, err := load(*anchorPath, wire.MaximumGenesisBytes)
		if err != nil {
			return err
		}
		anchor, err := wire.DecodeGenesis(raw)
		if err != nil {
			return err
		}
		raw, err = load(*aPath, cut.ObservationBytes)
		if err != nil {
			return err
		}
		ao, err := cut.DecodeObservation(raw)
		if err != nil {
			return err
		}
		raw, err = load(*bPath, cut.ObservationBytes)
		if err != nil {
			return err
		}
		bo, err := cut.DecodeObservation(raw)
		if err != nil {
			return err
		}
		raw, err = load(*blueprint, cut.MaximumBlueprintBytes*8)
		if err != nil {
			return err
		}
		var b cut.Blueprint
		if err = cutoverJSON(raw, &b); err != nil {
			return err
		}
		n, err := strconv.ParseUint(*allowance, 10, 32)
		if err != nil {
			return err
		}
		proposal = cut.Proposal{Version: cut.Version1, Anchor: anchor, Evidence: evidence, A: ao, B: bo, Successor: b, Allowance: uint32(n)}
		bridge, err = proposal.ValidateDraft(pin.AnchorID, pin.DescriptorID, pin.LegacyID, pin.Retired)
		if err != nil {
			return err
		}
		prepared, err = proposal.CanonicalBytes()
		if err != nil {
			return err
		}
	}
	if *action == "import-genesis" {
		g, e := v2.NewImportedAdmissionGenesis(proposal, v2.ImportPins{RegistryID: pin.AnchorID, RegistryDescriptorID: pin.DescriptorID, LegacyID: pin.LegacyID, Retirement: pin.Retired, ProposalID: pin.ProposalID})
		if e != nil {
			return e
		}
		prepared, err = g.CanonicalBytes()
		if err != nil {
			return err
		}
	}

	if *action == "assess" {
		prepared, err = json.Marshal(assessment)
		if err != nil {
			return err
		}
	}
	if *action == "source-location" {
		prepared, err = json.Marshal(map[string]any{"location_id": locationID.String(), "candidate": true, "independent_pin": false, "execution_granted": false})
		if err != nil {
			return err
		}
	}
	if *action == "verify-proposal" {
		prepared, err = json.Marshal(bridge)
		if err != nil {
			return err
		}
	}
	if allowed["root"] {
		// Canonical parent only for creation. Existing original roots must be real
		// directories and remain bound by their immutable placement on open.
		if *action == "prepare" {
			if *root == "" {
				return cut.ErrPreparation
			}
			abs, err := filepath.Abs(*root)
			if err != nil {
				return err
			}
			parent, err := directory(filepath.Dir(abs))
			if err != nil {
				return err
			}
			*root = filepath.Join(parent, filepath.Base(abs))
		} else {
			*root, err = directory(*root)
			if err != nil {
				return err
			}
		}
		owners = append(owners, *root)
	}
	if allowed["sign-key"] {
		if *signKey == "" {
			return cut.ErrPreparation
		}
		*signKey, err = custodyCommandOutput(*signKey)
		if err != nil {
			return err
		}
		if *action == "sign-proposal" && *role != "issuer" && *role != "authority" && *role != "control" {
			return cut.ErrPreparation
		}
	}
	if *output == "" && *action != "prepare" {
		return cut.ErrPreparation
	}
	if *output != "" {
		*output, err = custodyCommandOutput(*output)
		if err != nil {
			return err
		}
		if err = rejectPruneLineageOutputAlias(*output, inputs); err != nil {
			return err
		}
	}
	for _, owner := range owners {
		for _, path := range append(append(append([]string{}, inputs...), *output), *signKey) {
			if path != "" {
				if err = witnessOutside(owner, path); err != nil {
					return err
				}
			}
		}
	}
	if *signKey != "" && *output == *signKey {
		return cut.ErrPreparation
	}
	public := map[string]any{"action": *action, "inputs": inputIDs, "pins": pin, "source": location, "source_location_id": locationID.String(), "nonce": explicitNonce.String(), "authority": *authority, "authority_pins": *pinsPath, "root": *root, "out": *output, "role": *role, "sign_key": *signKey, "allowance": proposal.Allowance, "disabled": true, "activation_allowed": false}
	reviewBytes, err := json.Marshal(public)
	if err != nil {
		return err
	}
	review := types.DomainHash("OMESH/custody-cutover-review/v1/cli/review", reviewBytes)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_cutover_review action=%s review_id=%s keys_loaded=false stores_opened=false execution_granted=false activation_allowed=false\n%s\n", *action, review, reviewBytes))
	}
	want, err := witnessID("expected-review-id", *expected)
	if err != nil || want != review {
		return errors.New("disabled cutover action requires its exact public review ID")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if *output != "" {
		if _, err = os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
			return errors.Join(errors.New("output must be absent; retain existing output and recover to a fresh path"), err)
		}
	}
	publish := func(raw []byte) error {
		if err := publishCustodyCommandArtifact(*output, raw); err != nil {
			return err
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_cutover_artifact action=%s artifact_id=%s execution_granted=false activation_allowed=false legacy_modified=false\n", *action, cutoverArtifactID(raw)))
	}
	if prepared != nil {
		return publish(prepared)
	}
	switch *action {
	case "history-export":
		owner, err := s.OpenCoordinator(*authority, *pinsPath, evidence.Assignment, pin.LegacyID)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
		return cut.ExportEvidence(ctx, owner, evidence, pin.LegacyID, pin.Retired, func(e cut.Evidence) error {
			raw, err := e.CanonicalBytes()
			if err != nil {
				return err
			}
			return publish(raw)
		})
	case "observe":
		pub := evidence.Assignment.AuthorityPublicKey
		if location.Role == cut.Target {
			pub = evidence.Assignment.RemoteControlPublicKey
		}
		key, err := witnessKey(*signKey, pub)
		if err != nil {
			return err
		}
		defer clear(key)
		_, err = cut.CaptureSource(ctx, evidence, pin.LegacyID, pin.AnchorID, pin.Retired, location, locationID, explicitNonce, key, func(o cut.Observation) error {
			raw, err := o.CanonicalBytes()
			if err != nil {
				return err
			}
			return publish(raw)
		})
		return err
	case "sign-proposal":
		pub := proposal.Anchor.Issuer
		if *role == "authority" {
			pub = proposal.Evidence.Assignment.AuthorityPublicKey
		}
		if *role == "control" {
			pub = proposal.Evidence.Assignment.RemoteControlPublicKey
		}
		key, err := witnessKey(*signKey, pub)
		if err != nil {
			return err
		}
		defer clear(key)
		signed, err := proposal.Sign(pin.AnchorID, pin.DescriptorID, pin.LegacyID, pin.Retired, *role, key)
		if err != nil {
			return err
		}
		raw, err := signed.CanonicalBytes()
		if err != nil {
			return err
		}
		return publish(raw)
	case "prepare":
		if err := cut.CreatePreparation(*root, proposal, pin); err != nil {
			return err
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_cutover_prepared proposal_id=%s execution_granted=false activation_allowed=false legacy_modified=false\n", pin.ProposalID))
	case "read-preparation", "recover-preparation":
		open := cut.OpenPreparation
		if *action == "recover-preparation" {
			open = cut.RecoverPreparation
		}
		p, err := open(*root, pin)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, p.Close()) }()
		v, err := p.Read(ctx)
		if err != nil {
			return err
		}
		raw, err := v.CanonicalBytes()
		if err != nil {
			return err
		}
		return publish(raw)
	}
	return cut.ErrPreparation
}
