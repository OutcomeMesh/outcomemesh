package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const custodyV2Command = "work-archive-custody-v2"

func runCustodyV2CLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyV2(ctx, args, os.Stdin, os.Stdout)
}
func custodyV2ArtifactID(b []byte) types.Hash {
	return types.DomainHash("OMESH/custody/v2/artifact/id", b)
}
func runCustodyV2(ctx context.Context, args []string, input io.ReadCloser, out io.Writer) (returnErr error) {
	if ctx == nil || len(args) == 0 {
		return v2.ErrProtocol
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "review", "review or run; action-specific exact public review required")
	action := flags.String("action", "", "draft-sign, context, scope, create-target, serve-target, create-acceptor, request, call, extract, bundle, accept, resume, receipt")
	contextPath := flags.String("context", "", "canonical signed V2 context")
	contextID := flags.String("context-id", "", "independent context ID")
	scopeID := flags.String("scope-id", "", "independent derived witness scope ID")
	draft := flags.String("draft", "", "public JSON Context draft; never contains private keys")
	role := flags.String("sign-role", "", "audit, serve or authority; draft-sign only")
	root := flags.String("root", "", "original V2 owner root")
	journal := flags.String("journal", "", "existing original custody journal")
	objects := flags.String("objects", "", "existing target objects")
	signKey := flags.String("sign-key", "", "existing private role seed; unused by review")
	replicaKey := flags.String("replica-key", "", "existing private replica seed; serve-target only")
	transportKey := flags.String("transport-key", "", "existing private transport seed; serve-target or call")
	in := flags.String("in", "", "canonical input artifact")
	inID := flags.String("in-id", "", "independent input artifact ID")
	requestPath := flags.String("request", "", "canonical request for response extraction")
	requestID := flags.String("request-id", "", "independent request ID")
	claimPath := flags.String("claim", "", "session claim quorum certificate")
	claimID := flags.String("claim-id", "", "independent claim certificate artifact ID")
	unknownPath := flags.String("unknown", "", "optional explicit unknown quorum certificate")
	unknownID := flags.String("unknown-id", "", "independent unknown certificate artifact ID")
	resultPath := flags.String("result-certificate", "", "result quorum certificate")
	resultID := flags.String("result-certificate-id", "", "independent result certificate artifact ID")
	operation := flags.String("operation", "", "prepare, execute or recover; request only")
	nonce := flags.String("nonce", "", "explicit request nonce; request only")
	part := flags.String("part", "", "claim, result or result-command; extract only")
	bundleID := flags.String("bundle-id", "", "exact retained bundle ID for resume")
	peer := flags.String("peer", "", "pinned target QUIC route")
	listen := flags.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "QUIC listen address")
	timeout := flags.Duration("timeout", 10*time.Second, "100ms..2m RPC bound")
	output := flags.String("out", "", "immutable artifact output outside original roots")
	expected := flags.String("expected-review-id", "", "exact action review ID")
	if e := parsePruneFlags(flags, args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (*mode != "review" && *mode != "run") || *timeout < remotewire.MinimumTimeout || *timeout > remotewire.MaximumTimeout {
		return v2.ErrProtocol
	}
	allowed := map[string]bool{"draft-sign": true, "context": true, "scope": true, "create-target": true, "serve-target": true, "create-acceptor": true, "request": true, "call": true, "extract": true, "bundle": true, "accept": true, "resume": true, "receipt": true}
	if !allowed[*action] {
		return v2.ErrProtocol
	}
	// Reject irrelevant role, network and mutation selectors rather than silently ignoring them.
	present := custodyCommandPresence(flags)
	permitted := map[string][]string{
		"draft-sign": {"draft", "sign-role", "sign-key"}, "context": {"draft"}, "scope": {},
		"create-target": {"root", "journal", "objects"}, "serve-target": {"root", "journal", "objects", "sign-key", "replica-key", "transport-key", "listen", "timeout"},
		"create-acceptor": {"root", "journal"}, "request": {"operation", "nonce", "claim", "claim-id", "unknown", "unknown-id"},
		"call": {"in", "in-id", "transport-key", "peer", "listen", "timeout"}, "extract": {"in", "in-id", "request", "request-id", "part"},
		"bundle": {"in", "in-id", "claim", "claim-id", "unknown", "unknown-id", "result-certificate", "result-certificate-id"},
		"accept": {"root", "journal", "sign-key", "in", "in-id"}, "resume": {"root", "journal", "sign-key", "bundle-id"}, "receipt": {"root", "journal", "sign-key"},
	}
	permit := map[string]bool{"mode": true, "action": true, "out": true, "expected-review-id": true}
	if *action != "draft-sign" && *action != "context" {
		for _, s := range []string{"context", "context-id", "scope-id"} {
			permit[s] = true
		}
	}
	for _, s := range permitted[*action] {
		permit[s] = true
	}
	for s := range present {
		if !permit[s] {
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
		id := custodyV2ArtifactID(b)
		if pin != "" {
			wanted, e := witnessID("artifact-id", pin)
			if e != nil || wanted != id {
				return nil, v2.ErrProtocol
			}
		}
		inputs = append(inputs, p)
		pins[p] = id.String()
		return b, nil
	}
	var c v2.Context
	var sid types.Hash
	if *action == "draft-sign" || *action == "context" {
		raw, e := load(*draft, "", 2*v2.MaximumContextBytes)
		if e != nil {
			return e
		}
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		if e := d.Decode(&c); e != nil {
			return e
		}
		if d.Decode(new(any)) != io.EOF {
			return v2.ErrProtocol
		}
		if e := c.ValidateDraft(); e != nil {
			return e
		}
		if *action == "context" {
			if e := c.Validate(); e != nil {
				return e
			}
		}
	} else {
		raw, e := load(*contextPath, "", v2.MaximumContextBytes)
		if e != nil {
			return e
		}
		c, e = v2.DecodeContext(raw)
		if e != nil {
			return e
		}
		id, _ := c.ID()
		wanted, e := witnessID("context-id", *contextID)
		if e != nil || id != wanted {
			return v2.ErrProtocol
		}
		scope, e := c.Scope()
		if e != nil {
			return e
		}
		sid, _ = scope.ID()
		wanted, e = witnessID("scope-id", *scopeID)
		if e != nil || sid != wanted {
			return v2.ErrProtocol
		}
	}
	if *root != "" {
		p, e := custodyV2RootPath(*root)
		if e != nil {
			return e
		}
		*root = p
	}
	for _, path := range []*string{journal, objects} {
		if *path != "" {
			p, e := filepath.EvalSymlinks(*path)
			if e != nil {
				return e
			}
			p, e = filepath.Abs(p)
			if e != nil {
				return e
			}
			info, e := os.Lstat(p)
			if e != nil || !info.IsDir() {
				return errors.Join(v2.ErrProtocol, e)
			}
			*path = p
		}
	}
	if strings.Contains(*action, "target") && (*root == "" || *journal == "" || *objects == "") {
		return v2.ErrProtocol
	}
	if (*action == "create-acceptor" || *action == "accept" || *action == "resume" || *action == "receipt") && (*root == "" || *journal == "") {
		return v2.ErrProtocol
	}
	var signingPublic [32]byte
	switch *action {
	case "draft-sign":
		switch *role {
		case "audit":
			signingPublic = c.Plan.Intent.ConsumerPublicKey
		case "serve":
			signingPublic = c.Plan.ServeConsumer
		case "authority":
			signingPublic = c.Assignment.Base.AuthorityPublicKey
		default:
			return v2.ErrProtocol
		}
	case "serve-target":
		signingPublic = c.Assignment.Base.RemoteControlPublicKey
	case "accept", "resume", "receipt":
		signingPublic = c.Assignment.Base.AuthorityPublicKey
	}
	for _, path := range []*string{signKey, replicaKey, transportKey} {
		if *path != "" {
			p, e := custodyCommandFile(*path)
			if e != nil {
				return e
			}
			*path = p
			inputs = append(inputs, p)
		}
	}
	if signingPublic != ([32]byte{}) && *signKey == "" {
		return errors.New("existing role seed path required; review does not load it")
	}
	if *action == "serve-target" && (*replicaKey == "" || *transportKey == "") || *action == "call" && (*transportKey == "" || *peer == "") {
		return v2.ErrProtocol
	}
	var source []byte
	var prefix []custodyfence.Certificate
	var request v2.Request
	var bundle v2.Bundle
	var prepared []byte
	var resumeID types.Hash
	if *in != "" {
		if *inID == "" {
			return v2.ErrProtocol
		}
		var e error
		source, e = load(*in, *inID, v2.MaximumBundleBytes)
		if e != nil {
			return e
		}
	} else if *inID != "" {
		return v2.ErrProtocol
	}
	readCert := func(path, pin string) (custodyfence.Certificate, error) {
		if path == "" || pin == "" {
			return custodyfence.Certificate{}, v2.ErrProtocol
		}
		b, e := load(path, pin, custodyfence.MaximumCertificateBytes)
		if e != nil {
			return custodyfence.Certificate{}, e
		}
		return custodyfence.DecodeCertificate(b)
	}
	for _, pair := range [][2]string{{*claimPath, *claimID}, {*unknownPath, *unknownID}} {
		if pair[0] != "" || pair[1] != "" {
			q, e := readCert(pair[0], pair[1])
			if e != nil {
				return e
			}
			prefix = append(prefix, q)
		}
	}
	switch *action {
	case "context":
		prepared, _ = c.CanonicalBytes()
	case "scope":
		s, _ := c.Scope()
		prepared, _ = s.CanonicalBytes()
	case "request":
		op := v2.Prepare
		switch *operation {
		case "prepare":
		case "execute":
			op = v2.Execute
		case "recover":
			op = v2.RecoverResult
		default:
			return v2.ErrProtocol
		}
		n, e := witnessID("nonce", *nonce)
		if e != nil {
			return e
		}
		request = v2.Request{Version: v2.Version2, Operation: op, ScopeID: sid, Nonce: n, Prefix: prefix}
		if e := request.Validate(c); e != nil {
			return e
		}
		prepared, _ = request.CanonicalBytes()
	case "call":
		var e error
		request, e = v2.DecodeRequest(source)
		if e != nil {
			return e
		}
		if e := request.Validate(c); e != nil {
			return e
		}
	case "extract":
		if *requestID == "" {
			return v2.ErrProtocol
		}
		raw, e := load(*requestPath, "", v2.MaximumRequestBytes)
		if e != nil {
			return e
		}
		request, e = v2.DecodeRequest(raw)
		if e != nil {
			return e
		}
		id, _ := request.ID()
		wanted, e := witnessID("request-id", *requestID)
		if e != nil || id != wanted {
			return v2.ErrProtocol
		}
		response, e := v2.DecodeResponse(source)
		if e != nil {
			return e
		}
		if e := v2.ValidateResponse(c, request, response); e != nil {
			return e
		}
		switch *part {
		case "claim":
			if response.Operation != v2.Prepare {
				return v2.ErrProtocol
			}
			prepared, _ = response.Candidate.Claim.CanonicalBytes()
		case "result":
			if response.Operation == v2.Prepare {
				return v2.ErrProtocol
			}
			prepared, _ = response.Result.CanonicalBytes()
		case "result-command":
			if response.Operation == v2.Prepare {
				return v2.ErrProtocol
			}
			prepared, _ = response.Command.CanonicalBytes()
		default:
			return v2.ErrProtocol
		}
	case "bundle":
		result, e := v2.DecodeResult(source)
		if e != nil {
			return e
		}
		last, e := readCert(*resultPath, *resultID)
		if e != nil {
			return e
		}
		bundle = v2.Bundle{Version: v2.Version2, Result: result, Chain: append(prefix, last)}
		if e := bundle.Verify(c); e != nil {
			return e
		}
		prepared, _ = bundle.CanonicalBytes()
	case "accept":
		var e error
		bundle, e = v2.DecodeBundle(source)
		if e != nil {
			return e
		}
		if e := bundle.Verify(c); e != nil {
			return e
		}
	case "resume":
		var e error
		resumeID, e = witnessID("bundle-id", *bundleID)
		if e != nil {
			return e
		}
	}
	requiresOutput := *action != "create-target" && *action != "create-acceptor" && *action != "serve-target"
	if requiresOutput {
		p, e := custodyCommandOutput(*output)
		if e != nil {
			return e
		}
		*output = p
		if e := rejectPruneLineageOutputAlias(p, inputs); e != nil {
			return e
		}
	} else if *output != "" {
		return v2.ErrProtocol
	}
	for _, owner := range []string{*root, *journal, *objects} {
		if owner != "" {
			for _, p := range append(append([]string{}, inputs...), *output) {
				if p != "" {
					if e := witnessOutside(owner, p); e != nil {
						return e
					}
				}
			}
		}
	}
	// The digest binds the action, all public file contents, canonical placements,
	// requested network route and output. The mode and review token are excluded.
	public := map[string]any{"action": *action, "scope_id": sid.String(), "inputs": pins, "root": *root, "journal": *journal, "objects": *objects, "sign_key": *signKey, "replica_key": *replicaKey, "transport_key": *transportKey, "role": *role, "operation": *operation, "part": *part, "bundle_id": *bundleID, "peer": *peer, "listen": *listen, "timeout": timeout.String(), "out": *output}
	raw, e := json.Marshal(public)
	if e != nil {
		return e
	}
	review := types.DomainHash("OMESH/custody/v2/cli/review", raw)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_review action=%s review_id=%s scope_id=%s keys_loaded=false owners_opened=false execution_started=false\n%s\n", *action, review, sid, raw))
	}
	approved, e := witnessID("expected-review-id", *expected)
	if e != nil || approved != review {
		return errors.New("V2 action requires its exact public review ID")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if *action == "call" || *action == "accept" || *action == "resume" {
		if _, e := os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
			return errors.Join(errors.New("effect output must be absent before dispatch; recover to a fresh output"), e)
		}
	}
	publish := func(b []byte) error {
		if e := publishCustodyCommandArtifact(*output, b); e != nil {
			return e
		}
		return writePruneOutputLine(out, fmt.Sprintf("custody_v2_artifact action=%s artifact_id=%s scope_id=%s proof_refreshed=false\n", *action, custodyV2ArtifactID(b), sid))
	}
	if prepared != nil {
		return publish(prepared)
	}
	var key ed25519.PrivateKey
	if signingPublic != ([32]byte{}) {
		key, e = witnessKey(*signKey, signingPublic)
		if e != nil {
			return e
		}
		defer clear(key)
	}
	switch *action {
	case "draft-sign":
		c.Plan, e = c.Plan.Sign(*role, key)
		if e != nil {
			return e
		}
		b, e := json.MarshalIndent(c, "", "  ")
		if e != nil {
			return e
		}
		return publish(append(b, '\n'))
	case "create-target":
		e = v2.CreateTarget(*root, c, sid, v2.Sources{Journal: *journal, Objects: *objects})
	case "create-acceptor":
		e = v2.CreateAcceptor(*root, c, sid, *journal)
	case "serve-target":
		control, e := ownPruneControlInput(input)
		if e != nil {
			return e
		}
		defer control.Close()
		writer, e := ownPruneEffectOutput(out)
		if e != nil {
			return e
		}
		defer writer.Close()
		replica, e := witnessKey(*replicaKey, c.Assignment.Base.ReplicaPublicKey)
		if e != nil {
			return e
		}
		defer clear(replica)
		transport, e := witnessKey(*transportKey, c.Assignment.Base.RemoteTransportPublicKey)
		if e != nil {
			return e
		}
		defer clear(transport)
		target, e := v2.OpenTarget(*root, c, sid, v2.Sources{Journal: *journal, Objects: *objects}, replica, key)
		if e != nil {
			return e
		}
		defer target.Close()
		config := libp2ptransport.DefaultConfig()
		config.Listen = []string{*listen}
		service, e := v2.Start(ctx, target, transport, config, *timeout)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
		if e := writePruneOutputLine(writer, fmt.Sprintf("custody_v2_serving scope_id=%s peer_id=%s address=%s owners_retained=true execution_started=false\n", sid, service.ID(), strings.Join(service.Addresses(), ","))); e != nil {
			return e
		}
		finished := make(chan error, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			scan := bufio.NewScanner(control)
			scan.Buffer(make([]byte, 128), 256)
			if scan.Scan() && scan.Text() != "close" {
				finished <- errors.New("V2 service accepts only close or EOF")
				return
			}
			finished <- scan.Err()
		}()
		defer func() { _ = control.Close(); <-done }()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-finished:
			return e
		}
	case "call":
		transport, e := witnessKey(*transportKey, c.Plan.ClientTransportPublicKey)
		if e != nil {
			return e
		}
		defer clear(transport)
		config := libp2ptransport.DefaultConfig()
		config.Listen = []string{*listen}
		run, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		host, e := libp2ptransport.New(run, transport, config, nil)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, host.Close()) }()
		server, e := transportPeer(c.Assignment.Base.RemoteTransportPublicKey)
		if e != nil {
			return e
		}
		stream, _, e := host.OpenCustodyV2Stream(run, *peer, server)
		if e != nil {
			return errors.Join(v2.ErrUncertain, e)
		}
		response, e := v2.Exchange(run, stream, c, request, *timeout)
		if e != nil {
			return errors.Join(v2.ErrUncertain, e)
		}
		b, _ := response.CanonicalBytes()
		return publish(b)
	case "accept", "resume", "receipt":
		acceptor, e := v2.OpenAcceptor(*root, c, sid, *journal, key)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, acceptor.Close()) }()
		var receipt v2.Receipt
		switch *action {
		case "accept":
			receipt, e = acceptor.Accept(ctx, bundle, uint64(time.Now().Unix()))
		case "resume":
			receipt, e = acceptor.Resume(ctx, resumeID, uint64(time.Now().Unix()))
		case "receipt":
			receipt, e = acceptor.ReadReceipt()
		}
		if e != nil {
			return e
		}
		b, e := receipt.CanonicalBytes()
		if e != nil {
			return e
		}
		return publish(b)
	default:
		return v2.ErrProtocol
	}
	if e != nil {
		return e
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_v2_created action=%s scope_id=%s execution_started=false\n", *action, sid))
}

func custodyV2RootPath(path string) (string, error) {
	absolute, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(absolute))
	if e != nil {
		return "", e
	}
	p := filepath.Join(parent, filepath.Base(absolute))
	if info, e := os.Lstat(p); e == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", v2.ErrProtocol
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	return p, nil
}
