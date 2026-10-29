package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	guardclient "github.com/outcomemesh/outcomemesh/node/custodyguard"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const custodyV2AdmissionCommand = "work-archive-custody-v2-admission"

func runCustodyV2AdmissionCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyV2Admission(ctx, args, os.Stdout)
}

// runCustodyV2Admission operates the opt-in coordinator only. A resulting
// historical certificate never activates or grants existing raw V2 execution.
func runCustodyV2Admission(ctx context.Context, args []string, out io.Writer) (returnErr error) {
	if ctx == nil || len(args) == 0 {
		return v2.ErrAdmission
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	guardURL := flags.String("guard-url", "", "external guard endpoint; verification key comes from the signed policy")
	mode := flags.String("mode", "review", "review or run")
	action := flags.String("action", "", "genesis, inspect-genesis, inspect-history, admit-entry, close-entry, witness-create, witness-vote, witness-commit, witness-status, certificate")
	enrollmentPath := flags.String("enrollment", "", "complete imported registry selection; required for profile 5")
	enrollmentID := flags.String("enrollment-id", "", "independent exact imported enrollment artifact pin")
	genesisPath := flags.String("genesis", "", "canonical immutable assignment admission descriptor")
	genesisID := flags.String("genesis-id", "", "independent assignment-wide admission genesis pin")
	descriptorID := flags.String("genesis-descriptor-id", "", "independent full genesis descriptor pin")
	contextPath := flags.String("context", "", "canonical signed V2 job context")
	contextID := flags.String("context-id", "", "independent context semantic ID")
	in := flags.String("in", "", "canonical entry, certificate or Serve certificate input")
	inID := flags.String("in-id", "", "independent V2 artifact pin")
	aReceipt := flags.String("a-receipt", "", "original A Serve-applied receipt")
	aReceiptID := flags.String("a-receipt-id", "", "A receipt V2 artifact pin")
	bReceipt := flags.String("b-receipt", "", "original B Serve-applied receipt")
	bReceiptID := flags.String("b-receipt-id", "", "B receipt V2 artifact pin")
	votes := flags.String("votes", "", "comma-separated admission vote paths")
	voteIDs := flags.String("vote-ids", "", "matching comma-separated V2 artifact pins")
	signKey := flags.String("sign-key", "", "existing authority or witness private seed; review does not load it")
	witness := flags.String("witness", "", "independently pinned witness public key")
	root := flags.String("root", "", "original assignment-wide witness root")
	sequence := flags.Uint64("sequence", 0, "independent exact assignment admission sequence")
	head := flags.String("head-id", "", "independent exact assignment admission head")
	pending := flags.String("pending-id", "", "independent pending entry ID, including explicit zero")
	output := flags.String("out", "", "immutable public output outside original roots")
	expected := flags.String("expected-review-id", "", "exact action review ID")
	if e := parsePruneFlags(flags, args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (*mode != "review" && *mode != "run") {
		return v2.ErrAdmission
	}
	permitted := map[string][]string{
		"genesis":         {"context", "context-id"},
		"inspect-genesis": {},
		"inspect-history": {"in", "in-id"},
		"admit-entry":     {"context", "context-id", "sequence", "head-id", "sign-key"},
		"close-entry":     {"context", "context-id", "sequence", "head-id", "sign-key", "in", "in-id", "a-receipt", "a-receipt-id", "b-receipt", "b-receipt-id"},
		"witness-create":  {"root", "witness", "sign-key", "sequence", "head-id", "pending-id"},
		"witness-vote":    {"root", "witness", "sign-key", "sequence", "head-id", "pending-id", "in", "in-id"},
		"witness-commit":  {"root", "witness", "sign-key", "sequence", "head-id", "pending-id", "in", "in-id"},
		"witness-status":  {"root", "witness", "sign-key", "sequence", "head-id", "pending-id"},
		"certificate":     {"in", "in-id", "votes", "vote-ids"},
	}
	selectors, ok := permitted[*action]
	if !ok {
		return v2.ErrAdmission
	}
	present := custodyCommandPresence(flags)
	allowed := map[string]bool{"action": true, "mode": true, "genesis-id": true, "genesis-descriptor-id": true, "out": true, "expected-review-id": true}
	if *action != "genesis" {
		allowed["genesis"] = true
		allowed["enrollment"] = true
		allowed["enrollment-id"] = true
	}
	for _, s := range selectors {
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
		if path == "" || pin == "" {
			return nil, v2.ErrAdmission
		}
		p, e := custodyCommandFile(path)
		if e != nil {
			return nil, e
		}
		b, e := readRegularArtifact(p, limit)
		if e != nil {
			return nil, e
		}
		wanted, e := witnessID("artifact-id", pin)
		id := custodyV2ArtifactID(b)
		if e != nil || wanted != id {
			return nil, v2.ErrAdmission
		}
		inputs = append(inputs, p)
		pins[p] = id.String()
		return b, nil
	}
	var g v2.AdmissionGenesis
	var c v2.Context
	var gid, did types.Hash
	var e error
	if *action == "genesis" || *action == "admit-entry" || *action == "close-entry" {
		cp, e := custodyCommandFile(*contextPath)
		if e != nil {
			return e
		}
		b, e := readRegularArtifact(cp, v2.MaximumContextBytes)
		if e != nil {
			return e
		}
		c, e = v2.DecodeContext(b)
		if e != nil {
			return e
		}
		id, _ := c.ID()
		wanted, e := witnessID("context-id", *contextID)
		if e != nil || wanted != id {
			return v2.ErrAdmission
		}
		inputs = append(inputs, cp)
		pins[cp] = custodyV2ArtifactID(b).String()
	}
	if *action == "genesis" {
		g, e = v2.NewAdmissionGenesis(c)
		if e != nil {
			return e
		}
	} else {
		gp, e := custodyCommandFile(*genesisPath)
		if e != nil {
			return e
		}
		b, e := readRegularArtifact(gp, v2.MaximumAdmissionGenesisBytes)
		if e != nil {
			return e
		}
		g, e = v2.DecodeAdmissionGenesis(b)
		if e != nil {
			return e
		}
		inputs = append(inputs, gp)
		pins[gp] = custodyV2ArtifactID(b).String()
	}
	gid, e = g.ID()
	if e != nil {
		return e
	}
	wanted, e := witnessID("genesis-id", *genesisID)
	if e != nil || gid != wanted {
		return v2.ErrAdmission
	}
	did, e = g.DescriptorID()
	if e != nil {
		return e
	}
	wanted, e = witnessID("genesis-descriptor-id", *descriptorID)
	if e != nil || did != wanted {
		return v2.ErrAdmission
	}
	var enrollments []v2.EnrollmentBinding
	if g.Version == v2.PolicyVersionImported {
		raw, e := load(*enrollmentPath, *enrollmentID, v2.MaximumEnrollmentBindingBytes)
		if e != nil {
			return e
		}
		binding, e := v2.DecodeEnrollmentBinding(raw)
		if e != nil {
			return e
		}
		if e := binding.VerifyImported(g); e != nil {
			return e
		}
		enrollments = []v2.EnrollmentBinding{binding}
	} else if present["enrollment"] || present["enrollment-id"] {
		return v2.ErrEnrollmentRequired
	}

	if *root != "" {
		*root, e = custodyV2RootPath(*root)
		if e != nil {
			return e
		}
	}
	var signing [32]byte
	isWitness := strings.HasPrefix(*action, "witness-")
	if isWitness {
		b, e := hex.DecodeString(*witness)
		if e != nil || len(b) != 32 {
			return v2.ErrAdmission
		}
		copy(signing[:], b)
		member := false
		for _, pub := range g.Assignment.Policy.Witnesses {
			if pub == signing {
				member = true
			}
		}
		if !member || *root == "" {
			return v2.ErrAdmission
		}
	} else if *action == "admit-entry" || *action == "close-entry" {
		signing = g.Assignment.Base.AuthorityPublicKey
	}
	if signing != ([32]byte{}) {
		if *signKey == "" {
			return errors.New("existing role seed path required; review does not load it")
		}
		*signKey, e = custodyCommandFile(*signKey)
		if e != nil {
			return e
		}
		inputs = append(inputs, *signKey)
	}
	var before custodyfence.WitnessPin
	if isWitness || *action == "admit-entry" || *action == "close-entry" {
		fields := []string{"sequence", "head-id"}
		if isWitness {
			fields = append(fields, "pending-id")
		}
		for _, s := range fields {
			if !present[s] {
				return errors.New("explicit independent admission sequence/head and witness pending pin are required")
			}
		}
		before.Position.Sequence = *sequence
		before.Position.HeadID, e = witnessID("head-id", *head)
		if e != nil {
			return e
		}
		if isWitness {
			b, e := hex.DecodeString(*pending)
			if e != nil || len(b) != 32 {
				return v2.ErrAdmission
			}
			copy(before.PendingID[:], b)
		}
		if *action == "witness-create" && (before.Position.Sequence != 0 || before.Position.HeadID != gid || !before.PendingID.IsZero()) {
			return v2.ErrAdmission
		}
	}
	var source, prepared []byte
	var entry v2.AdmissionEntry
	var cert v2.AdmissionCertificate
	if *in != "" || *inID != "" {
		limit := v2.MaximumAdmissionCertificateBytes
		if *action == "inspect-history" {
			limit = v2.MaximumAdmissionBindingBytes
		}
		source, e = load(*in, *inID, limit)
		if e != nil {
			return e
		}
	}
	switch *action {
	case "inspect-genesis", "inspect-history":
		state, err := v2.NewAdmissionState(g, gid)
		if err != nil {
			return err
		}
		if *action == "inspect-history" {
			b, err := v2.DecodeAdmissionBinding(source)
			if err != nil {
				return err
			}
			want, _ := g.CanonicalBytes()
			actual, err := b.Genesis.CanonicalBytes()
			if err != nil || !bytes.Equal(want, actual) {
				return v2.ErrAdmission
			}
			for _, q := range b.Chain {
				if err := state.Apply(q); err != nil {
					return err
				}
			}
		}
		prepared, e = json.Marshal(struct {
			Snapshot                         v2.AdmissionSnapshot
			HistoricalOnly, ExecutionGranted bool
		}{Snapshot: state.Snapshot(), HistoricalOnly: true})
		if e != nil {
			return e
		}
	case "genesis":
		prepared, e = g.CanonicalBytes()
		if e != nil {
			return e
		}
	case "admit-entry", "close-entry":
		entry = v2.AdmissionEntry{Version: v2.Version2, GenesisID: gid, ExpectedSequence: before.Position.Sequence, ExpectedHead: before.Position.HeadID, Kind: v2.AdmissionAdmit, Context: c}
		if *action == "close-entry" {
			serve, e := v2.DecodeServeCertificate(source)
			if e != nil {
				return e
			}
			ab, e := load(*aReceipt, *aReceiptID, v2.ServeReceiptBytes)
			if e != nil {
				return e
			}
			ar, e := v2.DecodeServeReceipt(ab)
			if e != nil {
				return e
			}
			bb, e := load(*bReceipt, *bReceiptID, v2.ServeReceiptBytes)
			if e != nil {
				return e
			}
			br, e := v2.DecodeServeReceipt(bb)
			if e != nil {
				return e
			}
			closure := v2.AdmissionClosure{Serve: serve, A: ar, B: br}
			if e := closure.Verify(c); e != nil {
				return e
			}
			entry.Kind = v2.AdmissionClose
			entry.Closure = &closure
		}
		// Review validates the full unsigned public value without reading a role key.
		if e := entry.ValidateDraft(g); e != nil {
			return e
		}
	case "witness-vote", "certificate":
		entry, e = v2.DecodeAdmissionEntry(source)
		if e != nil {
			return e
		}
		if e := entry.Verify(g); e != nil {
			return e
		}
	case "witness-commit":
		cert, e = v2.DecodeAdmissionCertificate(source)
		if e != nil {
			return e
		}
		if e := cert.Verify(g); e != nil {
			return e
		}
	}
	if *action == "certificate" {
		paths, ids := strings.Split(*votes, ","), strings.Split(*voteIDs, ",")
		if len(paths) != len(ids) || len(paths) > custodyfence.MaximumWitnesses {
			return v2.ErrAdmission
		}
		cert = v2.AdmissionCertificate{Version: v2.Version2, Entry: entry}
		for i, path := range paths {
			b, e := load(path, ids[i], v2.MaximumAdmissionVoteBytes)
			if e != nil {
				return e
			}
			vote, e := v2.DecodeAdmissionVote(b)
			if e != nil {
				return e
			}
			cert.Votes = append(cert.Votes, vote)
		}
		sort.Slice(cert.Votes, func(i, j int) bool { return bytes.Compare(cert.Votes[i].Witness[:], cert.Votes[j].Witness[:]) < 0 })
		if e := cert.Verify(g); e != nil {
			return e
		}
		prepared, e = cert.CanonicalBytes()
		if e != nil {
			return e
		}
	}
	*output, e = custodyCommandOutput(*output)
	if e != nil {
		return e
	}
	if e := rejectPruneLineageOutputAlias(*output, inputs); e != nil {
		return e
	}
	if *root != "" {
		for _, p := range append(append([]string{}, inputs...), *output) {
			if e := witnessOutside(*root, p); e != nil {
				return e
			}
		}
	}
	if *guardURL != "" && (*action != "witness-vote" || v2.AdmissionGuard(entry) == ([32]byte{}) || guardclient.ValidateURL(*guardURL) != nil) {
		return v2.ErrAdmission
	}
	public := map[string]any{"guard_url": *guardURL, "action": *action, "genesis_id": gid.String(), "genesis_descriptor_id": did.String(), "inputs": pins, "root": *root, "sign_key": *signKey, "witness": *witness, "sequence": *sequence, "head_id": *head, "pending_id": *pending, "out": *output, "coordinator_only": true, "execution_granted": false}
	reviewBytes, e := json.Marshal(public)
	if e != nil {
		return e
	}
	review := types.DomainHash("OMESH/custody/v2/admission/cli/review", reviewBytes)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_admission_review action=%s review_id=%s genesis_id=%s keys_loaded=false owners_opened=false coordinator_only=true execution_granted=false\n%s\n", *action, review, gid, reviewBytes))
	}
	wanted, e = witnessID("expected-review-id", *expected)
	if e != nil || wanted != review {
		return errors.New("admission action requires its exact public review ID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if _, e := os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
		return errors.Join(errors.New("output must be absent; recover to a fresh output"), e)
	}
	publish := func(b []byte) error {
		if e := publishCustodyCommandArtifact(*output, b); e != nil {
			return e
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_admission_artifact action=%s artifact_id=%s genesis_id=%s coordinator_only=true execution_granted=false\n", *action, custodyV2ArtifactID(b), gid))
	}
	if prepared != nil {
		return publish(prepared)
	}
	var key ed25519.PrivateKey
	if signing != ([32]byte{}) {
		key, e = witnessKey(*signKey, signing)
		if e != nil {
			return e
		}
		defer clear(key)
	}
	switch *action {
	case "admit-entry", "close-entry":
		entry, e = entry.Sign(g, key)
		if e != nil {
			return e
		}
		b, e := entry.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	case "witness-create", "witness-vote", "witness-commit", "witness-status":
		var w *v2.AdmissionWitness
		switch *action {
		case "witness-create":
			w, e = v2.CreateAdmissionWitness(*root, g, gid, key, enrollments...)
		case "witness-vote":
			w, e = v2.RecoverAdmissionVote(*root, g, gid, key, before, entry, enrollments...)
		case "witness-commit":
			w, e = v2.RecoverAdmissionCommit(*root, g, gid, key, before, cert, enrollments...)
		case "witness-status":
			w, e = v2.OpenAdmissionWitness(*root, g, gid, key, before, enrollments...)
		}
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, w.Close()) }()
		if *guardURL != "" {
			w.SetGuard(guardclient.Client{URL: *guardURL})
		}
		if *action == "witness-vote" {
			vote, e := w.VoteAt(before, entry)
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
			Snapshot                          v2.AdmissionSnapshot
			Pin                               custodyfence.WitnessPin
			CoordinatorOnly, ExecutionGranted bool
		}{Snapshot: snapshot, Pin: pin, CoordinatorOnly: true, ExecutionGranted: false})
		if e != nil {
			return e
		}
		return publish(append(b, '\n'))
	}
	return v2.ErrAdmission
}
