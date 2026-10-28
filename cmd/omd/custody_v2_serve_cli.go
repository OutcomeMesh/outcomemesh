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
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const custodyV2ServeCommand = "work-archive-custody-v2-serve"

func runCustodyV2ServeCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyV2Serve(ctx, args, os.Stdout)
}

func runCustodyV2Serve(ctx context.Context, args []string, out io.Writer) (returnErr error) {
	if ctx == nil || len(args) == 0 {
		return v2.ErrProtocol
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review or run")
	action := flags.String("action", "", "scope, unclaimed-command, proposal-fulfilled, proposal-unclaimed, sign-proposal, decision, witness-create, witness-vote, witness-commit, certificate, apply-a, apply-b, resume-a, resume-b, status-a, status-b")
	contextPath := flags.String("context", "", "signed V2 context")
	contextID := flags.String("context-id", "", "independent context pin")
	scopeID := flags.String("scope-id", "", "original execution scope pin")
	decisionScopeID := flags.String("serve-scope-id", "", "independent Serve decision scope pin")
	in := flags.String("in", "", "primary canonical input")
	inID := flags.String("in-id", "", "input artifact pin")
	extra := flags.String("proof", "", "accepted-source receipt, A applied receipt, or decision command")
	extraID := flags.String("proof-id", "", "proof artifact pin")
	votes := flags.String("votes", "", "comma-separated vote paths")
	voteIDs := flags.String("vote-ids", "", "matching comma-separated artifact pins")
	signKey := flags.String("sign-key", "", "existing role seed path; never loaded by review")
	role := flags.String("sign-role", "", "authority or consumer; sign-proposal only")
	witness := flags.String("witness", "", "independently pinned witness public key")
	root := flags.String("root", "", "original owner or witness root")
	journal := flags.String("journal", "", "original source journal")
	objects := flags.String("objects", "", "original B objects")
	replicaKey := flags.String("replica-key", "", "original B replica seed")
	sequence := flags.Uint64("sequence", 0, "independent witness sequence")
	head := flags.String("head-id", "", "independent witness head")
	pending := flags.String("pending-id", "", "independent witness pending ID, including explicit zero")
	evidence := flags.String("evidence-id", "", "nonzero cancellation reason commitment")
	output := flags.String("out", "", "immutable output outside owner roots")
	expected := flags.String("expected-review-id", "", "exact action review")
	if e := parsePruneFlags(flags, args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (*mode != "review" && *mode != "run") {
		return v2.ErrProtocol
	}
	permitted := map[string][]string{
		"scope": {}, "unclaimed-command": {"sign-key", "evidence-id"}, "proposal-fulfilled": {"in", "in-id", "proof", "proof-id"}, "proposal-unclaimed": {"in", "in-id"}, "sign-proposal": {"in", "in-id", "sign-key", "sign-role"}, "decision": {"in", "in-id", "sign-key"},
		"witness-create": {"root", "witness", "sign-key"}, "witness-vote": {"root", "witness", "sign-key", "in", "in-id", "proof", "proof-id", "sequence", "head-id", "pending-id"}, "witness-commit": {"root", "witness", "sign-key", "in", "in-id", "sequence", "head-id", "pending-id"}, "certificate": {"in", "in-id", "proof", "proof-id", "votes", "vote-ids"},
		"apply-a": {"root", "journal", "sign-key", "in", "in-id"}, "resume-a": {"root", "journal", "sign-key", "in", "in-id"}, "status-a": {"root", "journal", "sign-key"},
		"apply-b": {"root", "journal", "objects", "replica-key", "sign-key", "in", "in-id", "proof", "proof-id"}, "resume-b": {"root", "journal", "objects", "replica-key", "sign-key", "in", "in-id", "proof", "proof-id"}, "status-b": {"root", "journal", "objects", "replica-key", "sign-key"},
	}
	selectors, ok := permitted[*action]
	if !ok {
		return v2.ErrProtocol
	}
	allowed := map[string]bool{"action": true, "mode": true, "context": true, "context-id": true, "scope-id": true, "serve-scope-id": true, "out": true, "expected-review-id": true}
	for _, s := range selectors {
		allowed[s] = true
	}
	present := custodyCommandPresence(flags)
	for s := range present {
		if !allowed[s] {
			return fmt.Errorf("--%s is not used by action %s", s, *action)
		}
	}
	inputs := []string{}
	pins := map[string]string{}
	load := func(path, pin string, limit int) ([]byte, error) {
		if path == "" || pin == "" {
			return nil, v2.ErrProtocol
		}
		p, e := custodyCommandFile(path)
		if e != nil {
			return nil, e
		}
		b, e := readRegularArtifact(p, limit)
		if e != nil {
			return nil, e
		}
		id := custodyV2ArtifactID(b)
		want, e := witnessID("artifact-id", pin)
		if e != nil || want != id {
			return nil, v2.ErrProtocol
		}
		inputs = append(inputs, p)
		pins[p] = id.String()
		return b, nil
	}
	cp, e := custodyCommandFile(*contextPath)
	if e != nil {
		return e
	}
	raw, e := readRegularArtifact(cp, v2.MaximumContextBytes)
	if e != nil {
		return e
	}
	c, e := v2.DecodeContext(raw)
	if e != nil {
		return e
	}
	cid, _ := c.ID()
	wanted, e := witnessID("context-id", *contextID)
	if e != nil || cid != wanted {
		return v2.ErrProtocol
	}
	inputs = append(inputs, cp)
	pins[cp] = custodyV2ArtifactID(raw).String()
	execScope, _ := c.Scope()
	sid, _ := execScope.ID()
	wanted, e = witnessID("scope-id", *scopeID)
	if e != nil || sid != wanted {
		return v2.ErrProtocol
	}
	scope, e := c.ServeScope()
	if e != nil {
		return e
	}
	dsid, _ := scope.ID()
	wanted, e = witnessID("serve-scope-id", *decisionScopeID)
	if e != nil || dsid != wanted {
		return v2.ErrProtocol
	}
	if *root != "" {
		*root, e = custodyV2RootPath(*root)
		if e != nil {
			return e
		}
	}
	for _, p := range []*string{journal, objects} {
		if *p != "" {
			*p, e = filepath.EvalSymlinks(*p)
			if e != nil {
				return e
			}
			*p, e = filepath.Abs(*p)
			if e != nil {
				return e
			}
			info, e := os.Lstat(*p)
			if e != nil || !info.IsDir() {
				return errors.Join(v2.ErrProtocol, e)
			}
		}
	}
	for _, p := range []*string{signKey, replicaKey} {
		if *p != "" {
			*p, e = custodyCommandFile(*p)
			if e != nil {
				return e
			}
			inputs = append(inputs, *p)
		}
	}
	var signing [32]byte
	if strings.HasPrefix(*action, "witness-") {
		b, e := hex.DecodeString(*witness)
		if e != nil || len(b) != 32 {
			return v2.ErrProtocol
		}
		copy(signing[:], b)
		member := false
		for _, pub := range scope.Witnesses {
			if pub == signing {
				member = true
			}
		}
		if !member || *root == "" {
			return v2.ErrProtocol
		}
	} else {
		switch *action {
		case "sign-proposal":
			if *role == "authority" {
				signing = c.Assignment.Base.AuthorityPublicKey
			} else if *role == "consumer" {
				signing = c.Plan.ServeConsumer
			} else {
				return v2.ErrProtocol
			}
		case "unclaimed-command", "decision", "apply-a", "resume-a", "status-a":
			signing = c.Assignment.Base.AuthorityPublicKey
		case "apply-b", "resume-b", "status-b":
			signing = c.Assignment.Base.RemoteControlPublicKey
		}
	}
	if signing != ([32]byte{}) && *signKey == "" {
		return errors.New("existing role seed path required; review does not load it")
	}
	isA := strings.HasSuffix(*action, "-a")
	isB := strings.HasSuffix(*action, "-b")
	if (isA || isB) && (*root == "" || *journal == "") {
		return v2.ErrProtocol
	}
	if isB && (*replicaKey == "" || *objects == "") {
		return v2.ErrProtocol
	}
	var source, proof, prepared []byte
	if *in != "" || *inID != "" {
		source, e = load(*in, *inID, v2.MaximumServeCertificateBytes)
		if e != nil {
			return e
		}
	}
	if *extra != "" || *extraID != "" {
		proof, e = load(*extra, *extraID, v2.MaximumServeCertificateBytes)
		if e != nil {
			return e
		}
	}
	var proposal v2.ServeProposal
	var cert v2.ServeCertificate
	var cmd custodyfence.Command
	var parent v2.ServeReceipt
	var before custodyfence.WitnessPin
	switch *action {
	case "scope":
		prepared, _ = scope.CanonicalBytes()
	case "unclaimed-command":
		id, e := witnessID("evidence-id", *evidence)
		if e != nil {
			return e
		}
		cmd = custodyfence.Command{Version: execScope.Version, ScopeID: sid, ExpectedHead: sid, Kind: custodyfence.CloseUnclaimed, EvidenceID: id}
	case "proposal-fulfilled":
		b, e := v2.DecodeBundle(source)
		if e != nil {
			return e
		}
		r, e := v2.DecodeReceipt(proof)
		if e != nil {
			return e
		}
		proposal, e = v2.NewServeFulfilled(c, b, r)
		if e != nil {
			return e
		}
		prepared, _ = proposal.CanonicalBytes()
	case "proposal-unclaimed":
		q, e := custodyfence.DecodeCertificate(source)
		if e != nil {
			return e
		}
		proposal, e = v2.NewServeUnclaimed(c, q)
		if e != nil {
			return e
		}
		prepared, _ = proposal.CanonicalBytes()
	case "sign-proposal", "decision", "witness-vote", "certificate":
		proposal, e = v2.DecodeServeProposal(source)
		if e != nil {
			return e
		}
		if *action == "sign-proposal" {
			e = proposal.ValidateDraft(c)
		} else {
			e = proposal.Verify(c)
		}
		if e != nil {
			return e
		}
		if *action == "witness-vote" || *action == "certificate" {
			cmd, e = custodyfence.DecodeCommand(proof)
			if e != nil {
				return e
			}
			pid, _ := proposal.ID()
			if cmd.Kind != custodyfence.CloseUnclaimed || cmd.ExpectedSequence != 0 || cmd.ExpectedHead != dsid || cmd.EvidenceID != pid || cmd.Verify(scope) != nil {
				return v2.ErrProtocol
			}
		}
	case "witness-commit", "apply-a", "apply-b", "resume-a", "resume-b":
		cert, e = v2.DecodeServeCertificate(source)
		if e != nil {
			return e
		}
		if e := cert.Verify(c); e != nil {
			return e
		}
	}
	if *action == "apply-b" || *action == "resume-b" {
		parent, e = v2.DecodeServeReceipt(proof)
		if e != nil {
			return e
		}
		if e := parent.Verify(c, cert, v2.ServeAuthority, nil); e != nil {
			return e
		}
	}
	if *action == "witness-vote" || *action == "witness-commit" {
		for _, s := range []string{"sequence", "head-id", "pending-id"} {
			if !present[s] {
				return errors.New("all three independent witness position fields are required")
			}
		}
		before.Position.Sequence = *sequence
		before.Position.HeadID, e = witnessID("head-id", *head)
		if e != nil {
			return e
		}
		b, e := hex.DecodeString(*pending)
		if e != nil || len(b) != 32 {
			return v2.ErrProtocol
		}
		copy(before.PendingID[:], b)
	}
	if *action == "certificate" {
		paths, ids := strings.Split(*votes, ","), strings.Split(*voteIDs, ",")
		if len(paths) != len(ids) || len(paths) > custodyfence.MaximumWitnesses {
			return v2.ErrProtocol
		}
		q := custodyfence.Certificate{Version: scope.Version, Command: cmd}
		for i, path := range paths {
			b, e := load(path, ids[i], custodyfence.VoteBytes)
			if e != nil {
				return e
			}
			vote, e := custodyfence.DecodeVote(b)
			if e != nil {
				return e
			}
			q.Votes = append(q.Votes, vote)
		}
		sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
		cert = v2.ServeCertificate{Version: v2.Version2, Proposal: proposal, Decision: q}
		if e := cert.Verify(c); e != nil {
			return e
		}
		prepared, _ = cert.CanonicalBytes()
	}
	*output, e = custodyCommandOutput(*output)
	if e != nil {
		return e
	}
	if e := rejectPruneLineageOutputAlias(*output, inputs); e != nil {
		return e
	}
	for _, owner := range []string{*root, *journal, *objects} {
		if owner != "" {
			for _, p := range append(append([]string{}, inputs...), *output) {
				if e := witnessOutside(owner, p); e != nil {
					return e
				}
			}
		}
	}
	public := map[string]any{"action": *action, "context_id": cid.String(), "scope_id": sid.String(), "serve_scope_id": dsid.String(), "inputs": pins, "root": *root, "journal": *journal, "objects": *objects, "sign_key": *signKey, "replica_key": *replicaKey, "role": *role, "witness": *witness, "sequence": *sequence, "head_id": *head, "pending_id": *pending, "evidence_id": *evidence, "out": *output}
	reviewBytes, e := json.Marshal(public)
	if e != nil {
		return e
	}
	review := types.DomainHash("OMESH/custody/v2/serve/cli/review", reviewBytes)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_serve_review action=%s review_id=%s keys_loaded=false owners_opened=false\n%s\n", *action, review, reviewBytes))
	}
	wanted, e = witnessID("expected-review-id", *expected)
	if e != nil || wanted != review {
		return errors.New("Serve action requires its exact public review ID")
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
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_serve_artifact action=%s artifact_id=%s scope_id=%s archive_held=true proof_refreshed=false\n", *action, custodyV2ArtifactID(b), sid))
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
	case "unclaimed-command":
		cmd, e = cmd.Sign(key)
		if e != nil {
			return e
		}
		b, e := cmd.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	case "sign-proposal":
		proposal, e = proposal.Sign(c, *role, key)
		if e != nil {
			return e
		}
		b, e := proposal.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	case "decision":
		cmd, e = proposal.Decision(c, key)
		if e != nil {
			return e
		}
		b, e := cmd.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	case "witness-create", "witness-vote", "witness-commit":
		var w *custodyfence.Witness
		switch *action {
		case "witness-create":
			w, e = custodyfence.Create(*root, scope, dsid, key)
		case "witness-vote":
			w, e = custodyfence.RecoverVote(*root, scope, dsid, key, before, cmd)
		case "witness-commit":
			w, e = custodyfence.RecoverCommit(*root, scope, dsid, key, before, cert.Decision)
		}
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, w.Close()) }()
		if *action == "witness-vote" {
			vote, e := v2.VoteServe(c, proposal, cmd, w, before)
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
			if e := v2.CommitServe(c, cert, w, before); e != nil {
				return e
			}
		}
		obs, e := w.Observe(review)
		if e != nil {
			return e
		}
		b, e := obs.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	}
	if isA {
		a, e := v2.OpenAcceptor(*root, c, sid, *journal, key)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, a.Close()) }()
		if *action == "status-a" {
			s, e := a.ServeStatus()
			if e != nil {
				return e
			}
			b, e := json.Marshal(s)
			if e != nil {
				return e
			}
			return publish(append(b, '\n'))
		}
		r, e := a.ApplyServe(ctx, cert, uint64(time.Now().Unix()), *action == "resume-a")
		if e != nil {
			return e
		}
		b, e := r.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	}
	if isB {
		replica, e := witnessKey(*replicaKey, c.Assignment.Base.ReplicaPublicKey)
		if e != nil {
			return e
		}
		defer clear(replica)
		target, e := v2.OpenTarget(*root, c, sid, v2.Sources{Journal: *journal, Objects: *objects}, replica, key)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, target.Close()) }()
		if *action == "status-b" {
			s, e := target.ServeStatus()
			if e != nil {
				return e
			}
			b, e := json.Marshal(s)
			if e != nil {
				return e
			}
			return publish(append(b, '\n'))
		}
		r, e := target.ApplyServe(ctx, cert, parent, uint64(time.Now().Unix()), *action == "resume-b")
		if e != nil {
			return e
		}
		b, e := r.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	}
	return v2.ErrProtocol
}
