package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	reg "github.com/outcomemesh/outcomemesh/node/custodyregistry"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const custodyRegistryCommand = "work-archive-custody-registry"

func custodyRegistryArtifactID(b []byte) types.Hash {
	return types.DomainHash("OMESH/custody-registry/v1/cli/artifact/id", b)
}

func runCustodyRegistryCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyRegistry(ctx, args, os.Stdout)
}

// This reviewed operator channel selects one immutable experimental candidate.
// It never creates an execution owner, migrates an old ledger or activates work.
func runCustodyRegistry(ctx context.Context, args []string, out io.Writer) (returnErr error) {
	if ctx == nil || len(args) == 0 {
		return reg.ErrRegistry
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review or run")
	action := flags.String("action", "", "genesis, selection, sign-selection, certificate, witness-create, witness-vote, witness-commit, witness-status")
	draft := flags.String("draft", "", "strict public registry Genesis JSON; genesis only")
	registryPath := flags.String("registry", "", "exact canonical registry Genesis")
	registryID := flags.String("registry-id", "", "independent stable resource registry ID")
	descriptorID := flags.String("registry-descriptor-id", "", "independent full registry descriptor ID")
	candidate := flags.String("candidate", "", "canonical new profile-3 admission Genesis; selection only")
	candidateID := flags.String("candidate-id", "", "independent candidate admission Genesis ID")
	candidateDescriptor := flags.String("candidate-descriptor-id", "", "independent full candidate descriptor ID")
	in := flags.String("in", "", "selection or certificate")
	inID := flags.String("in-id", "", "independent registry artifact ID")
	role := flags.String("sign-role", "", "issuer, authority or control; sign-selection only")
	signKey := flags.String("sign-key", "", "existing role or witness seed; review never loads it")
	root := flags.String("root", "", "original single-choice witness root")
	witness := flags.String("witness", "", "independently pinned witness public key")
	sequence := flags.Uint64("sequence", 0, "explicit committed sequence 0 or 1")
	head := flags.String("head-id", "", "explicit committed head")
	pending := flags.String("pending-id", "", "explicit pending selection ID, including zero")
	votes := flags.String("votes", "", "comma-separated canonical vote paths")
	voteIDs := flags.String("vote-ids", "", "matching independent registry artifact IDs")
	output := flags.String("out", "", "fresh immutable output outside the witness root")
	expected := flags.String("expected-review-id", "", "exact public action review ID")
	if e := parsePruneFlags(flags, args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (*mode != "review" && *mode != "run") {
		return reg.ErrRegistry
	}
	selectors := map[string][]string{
		"genesis":        {"draft"},
		"selection":      {"candidate", "candidate-id", "candidate-descriptor-id"},
		"sign-selection": {"in", "in-id", "sign-role", "sign-key"},
		"certificate":    {"in", "in-id", "votes", "vote-ids"},
		"witness-create": {"root", "witness", "sign-key", "sequence", "head-id", "pending-id"},
		"witness-vote":   {"root", "witness", "sign-key", "sequence", "head-id", "pending-id", "in", "in-id"},
		"witness-commit": {"root", "witness", "sign-key", "sequence", "head-id", "pending-id", "in", "in-id"},
		"witness-status": {"root", "witness", "sign-key", "sequence", "head-id", "pending-id"},
	}
	selected, ok := selectors[*action]
	if !ok {
		return reg.ErrRegistry
	}
	present := custodyCommandPresence(flags)
	allowed := map[string]bool{"mode": true, "action": true, "registry-id": true, "registry-descriptor-id": true, "out": true, "expected-review-id": true}
	if *action != "genesis" {
		allowed["registry"] = true
	}
	for _, s := range selected {
		allowed[s] = true
	}
	for s := range present {
		if !allowed[s] {
			return fmt.Errorf("--%s is not used by action %s", s, *action)
		}
	}
	inputs := []string{}
	pins := map[string]string{}
	load := func(path, pin string, limit int) ([]byte, error) {
		p, e := custodyCommandFile(path)
		if e != nil {
			return nil, e
		}
		b, e := readRegularArtifact(p, limit)
		if e != nil {
			return nil, e
		}
		id := custodyRegistryArtifactID(b)
		if pin != "" {
			want, e := witnessID("artifact-id", pin)
			if e != nil || want != id {
				return nil, reg.ErrRegistry
			}
		}
		inputs = append(inputs, p)
		pins[p] = id.String()
		return b, nil
	}
	var g reg.Genesis
	if *action == "genesis" {
		b, e := load(*draft, "", 32<<10)
		if e != nil {
			return e
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if e := d.Decode(&g); e != nil {
			return e
		}
		if e := d.Decode(new(any)); !errors.Is(e, io.EOF) {
			return reg.ErrRegistry
		}
	} else {
		b, e := load(*registryPath, "", reg.MaximumGenesisBytes)
		if e != nil {
			return e
		}
		g, e = reg.DecodeGenesis(b)
		if e != nil {
			return e
		}
	}
	gid, e := g.ID()
	if e != nil {
		return e
	}
	did, e := g.DescriptorID()
	if e != nil {
		return e
	}
	// Public genesis preparation may print both IDs for independent review.
	// Every signing or retained-owner action requires both external pins.
	if *action != "genesis" || *registryID != "" || *descriptorID != "" {
		want, e := witnessID("registry-id", *registryID)
		if e != nil || want != gid {
			return reg.ErrRegistry
		}
		want, e = witnessID("registry-descriptor-id", *descriptorID)
		if e != nil || want != did {
			return reg.ErrRegistry
		}
	}
	var s reg.Selection
	var cert reg.Certificate
	var prepared []byte
	var signing [32]byte
	var before custodyfence.WitnessPin
	if *action == "genesis" {
		prepared, e = g.CanonicalBytes()
		if e != nil {
			return e
		}
	}
	if *action == "selection" {
		b, e := load(*candidate, "", v2.MaximumAdmissionGenesisBytes)
		if e != nil {
			return e
		}
		initial, e := v2.DecodeAdmissionGenesis(b)
		if e != nil {
			return e
		}
		actual, _ := initial.ID()
		want, e := witnessID("candidate-id", *candidateID)
		if e != nil || actual != want {
			return reg.ErrSelection
		}
		actual, _ = initial.DescriptorID()
		want, e = witnessID("candidate-descriptor-id", *candidateDescriptor)
		if e != nil || actual != want {
			return reg.ErrSelection
		}
		s = reg.Selection{Version: reg.Version1, RegistryID: gid, DescriptorID: did, Initial: initial}
		if e := s.ValidateDraft(g); e != nil {
			return e
		}
		prepared, e = s.CanonicalBytes()
		if e != nil {
			return e
		}
	}
	if *action == "sign-selection" || *action == "certificate" || *action == "witness-vote" {
		if *inID == "" {
			return reg.ErrSelection
		}
		b, e := load(*in, *inID, reg.MaximumSelectionBytes)
		if e != nil {
			return e
		}
		s, e = reg.DecodeSelection(b)
		if e != nil {
			return e
		}
		if e := s.ValidateDraft(g); e != nil {
			return e
		}
		if *action == "sign-selection" {
			switch *role {
			case "issuer":
				signing = g.Issuer
			case "authority":
				signing = s.Initial.Assignment.Base.AuthorityPublicKey
			case "control":
				signing = s.Initial.Assignment.Base.RemoteControlPublicKey
			default:
				return reg.ErrSelection
			}
		} else if e := s.Verify(g); e != nil {
			return e
		}
	}
	if *action == "certificate" {
		paths, ids := strings.Split(*votes, ","), strings.Split(*voteIDs, ",")
		if *votes == "" || len(paths) != len(ids) || len(paths) > len(g.Witnesses) {
			return reg.ErrQuorum
		}
		cert = reg.Certificate{Version: reg.Version1, Selection: s}
		for i, path := range paths {
			if ids[i] == "" {
				return reg.ErrQuorum
			}
			b, e := load(path, ids[i], reg.VoteBytes)
			if e != nil {
				return e
			}
			vote, e := reg.DecodeVote(b)
			if e != nil {
				return e
			}
			cert.Votes = append(cert.Votes, vote)
		}
		if e := cert.Verify(g); e != nil {
			return e
		}
		prepared, e = cert.CanonicalBytes()
		if e != nil {
			return e
		}
	}
	if *action == "witness-commit" {
		if *inID == "" {
			return reg.ErrQuorum
		}
		b, e := load(*in, *inID, reg.MaximumCertificateBytes)
		if e != nil {
			return e
		}
		cert, e = reg.DecodeCertificate(b)
		if e != nil {
			return e
		}
		if e := cert.Verify(g); e != nil {
			return e
		}
	}
	isWitness := strings.HasPrefix(*action, "witness-")
	var placement types.Hash
	if isWitness {
		if *root == "" || !utf8.ValidString(*root) || strings.ContainsRune(*root, 0) || !present["sequence"] || !present["head-id"] || !present["pending-id"] || *sequence > 1 {
			return reg.ErrPosition
		}
		*root, e = custodyV2RootPath(*root)
		if e != nil {
			return e
		}
		headID, e := witnessID("head-id", *head)
		if e != nil {
			return e
		}
		pendingBytes, e := hex.DecodeString(*pending)
		if e != nil || len(pendingBytes) != types.HashSize {
			return reg.ErrPosition
		}
		var pendingID types.Hash
		copy(pendingID[:], pendingBytes)
		before = custodyfence.WitnessPin{Position: custodyfence.Position{Sequence: *sequence, HeadID: headID}, PendingID: pendingID}
		member, e := witnessID("witness", *witness)
		if e != nil {
			return e
		}
		signing = [32]byte(member)
		found := false
		for _, key := range g.Witnesses {
			found = found || key == signing
		}
		if !found {
			return reg.ErrRegistry
		}
		if *sequence == 0 && headID != gid || *sequence == 1 && !pendingID.IsZero() {
			return reg.ErrPosition
		}
		if *action == "witness-create" && (before.Position.Sequence != 0 || !pendingID.IsZero()) {
			return reg.ErrPosition
		}
		if (*action == "witness-vote" || *action == "witness-commit") && before.Position.Sequence != 0 {
			return reg.ErrPosition
		}
		placement, e = v2.AdmissionDeliveryReviewPlacement(*root, 0, v2.Sources{})
		if e != nil {
			return e
		}
	}
	if signing != ([32]byte{}) {
		*signKey, e = custodyCommandFile(*signKey)
		if e != nil {
			return e
		}
		inputs = append(inputs, *signKey)
	}
	*output, e = custodyCommandOutput(*output)
	if e != nil {
		return e
	}
	if e := rejectPruneLineageOutputAlias(*output, inputs); e != nil {
		return e
	}
	if isWitness {
		for _, path := range append(append([]string{}, inputs...), *output) {
			if e := witnessOutside(*root, path); e != nil {
				return e
			}
		}
	}
	public := map[string]any{"action": *action, "registry_id": gid.String(), "registry_descriptor_id": did.String(), "inputs": pins, "root": *root, "placement_id": placement.String(), "sign_key": *signKey, "sign_role": *role, "witness": *witness, "sequence": *sequence, "head_id": *head, "pending_id": *pending, "out": *output, "selection_only": true, "execution_granted": false, "legacy_cutover": false}
	reviewBytes, e := json.Marshal(public)
	if e != nil {
		return e
	}
	review := types.DomainHash("OMESH/custody-registry/v1/cli/review", reviewBytes)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_registry_review action=%s review_id=%s registry_id=%s registry_descriptor_id=%s keys_loaded=false owners_opened=false selection_only=true execution_granted=false legacy_cutover=false\n%s\n", *action, review, gid, did, reviewBytes))
	}
	want, e := witnessID("expected-review-id", *expected)
	if e != nil || want != review {
		return errors.New("registry action requires its exact public review ID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if _, e := os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
		return errors.Join(errors.New("output must be absent; recover to a fresh output"), e)
	}
	publish := func(raw []byte) error {
		if e := publishCustodyCommandArtifact(*output, raw); e != nil {
			return e
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_registry_artifact action=%s artifact_id=%s registry_id=%s registry_descriptor_id=%s selection_only=true execution_granted=false legacy_cutover=false\n", *action, custodyRegistryArtifactID(raw), gid, did))
	}
	if prepared != nil {
		return publish(prepared)
	}
	key, e := witnessKey(*signKey, signing)
	if e != nil {
		return e
	}
	defer clear(key)
	if *action == "sign-selection" {
		s, e := s.Sign(g, *role, key)
		if e != nil {
			return e
		}
		b, e := s.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	}
	var w *reg.Witness
	switch *action {
	case "witness-create":
		if e := reg.CreateWitness(*root, g, gid, key); e != nil {
			return e
		}
		w, e = reg.OpenWitness(*root, g, gid, key, before)
	case "witness-vote":
		w, e = reg.RecoverVote(*root, g, gid, key, before, s)
	case "witness-commit":
		w, e = reg.RecoverCommit(*root, g, gid, key, before, cert)
	case "witness-status":
		w, e = reg.OpenWitness(*root, g, gid, key, before)
	default:
		return reg.ErrRegistry
	}
	if e != nil {
		return e
	}
	defer func() { returnErr = errors.Join(returnErr, w.Close()) }()
	if e := ctx.Err(); e != nil {
		return e
	}
	if *action == "witness-vote" {
		vote, e := w.VoteAt(before, s)
		if e != nil {
			return e
		}
		b, e := vote.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	}
	if *action == "witness-commit" {
		if e := w.CommitAt(before, cert); e != nil {
			return e
		}
	}
	snapshot, pin, e := w.Snapshot()
	if e != nil {
		return e
	}
	b, e := json.Marshal(struct {
		Snapshot                                       reg.Snapshot
		Pin                                            custodyfence.WitnessPin
		SelectionOnly, ExecutionGranted, LegacyCutover bool
	}{snapshot, pin, true, false, false})
	if e != nil {
		return e
	}
	return publish(append(b, '\n'))
}
