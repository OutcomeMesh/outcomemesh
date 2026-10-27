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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnessnet"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const witnessServerCommand = "work-archive-custody-witness"
const witnessClientCommand = "work-archive-custody-witness-call"
const witnessRequestCommand = "work-archive-custody-witness-request"
const witnessQuorumCommand = "work-archive-custody-witness-quorum"

func runWitnessCLI(args []string) error {
	broken := make(chan os.Signal, 1)
	signal.Notify(broken, syscall.SIGPIPE)
	defer signal.Stop(broken)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runWitness(ctx, args, os.Stdin, os.Stdout)
}
func witnessID(name, text string) (types.Hash, error) { return managedCustodyExternalID(name, text) }
func witnessArtifactID(kind string, b []byte) types.Hash {
	return types.DomainHash("OMESH/custody-fence/"+kind+"/artifact/id/v0", b)
}
func witnessKey(path string, public [32]byte) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(errors.New("witness role seed requires a private regular file"), err)
	}
	key, err := loadPruneOfflineKey(path)
	if err != nil {
		return nil, err
	}
	if !remoteKeyMatches(key, public) {
		return nil, errors.New("seed differs from independently selected public role")
	}
	return key, nil
}
func witnessOutside(root, path string) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("witness input/output/key must be outside the original witness root")
	}
	return nil
}

func runWitness(ctx context.Context, args []string, input io.ReadCloser, out io.Writer) (returnErr error) {
	if ctx == nil || len(args) == 0 {
		return witnesswire.ErrProtocol
	}
	if args[0] == witnessResultCommand {
		return runWitnessResult(ctx, args, out)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review by default; explicit create, serve, exchange, publish, vote, commit or recovery")
	scopePath := f.String("scope", "", "existing canonical independent witness scope")
	scopePin := f.String("scope-id", "", "independent scope ID")
	rootPath := f.String("root", "", "original witness root")
	memberText := f.String("witness-public-key", "", "independently selected witness signing public key")
	sequence := f.String("expected-sequence", "", "explicit original committed witness sequence")
	head := f.String("expected-head", "", "independently retained committed witness head")
	pending := f.String("pending-id", "", "independently retained pending vote ID, omitted only if none")
	keyPath := f.String("sign-key", "", "existing private witness seed, unused by review")
	transportPath := f.String("transport-key", "", "existing distinct private transport seed, unused by review")
	transportText := f.String("transport-public-key", "", "independent local transport public key")
	serverText := f.String("server-transport-public-key", "", "independent remote witness transport public key")
	clientsText := f.String("clients", "", "comma-separated authenticated client peer IDs")
	listen := f.String("listen", "/ip4/127.0.0.1/udp/0/quic-v1", "explicit witness QUIC listen address")
	peer := f.String("peer", "", "pinned remote witness QUIC route")
	timeout := f.Duration("timeout", 10*time.Second, "bounded witness RPC timeout")
	requestPath := f.String("request", "", "existing canonical witness request")
	requestPin := f.String("request-id", "", "independent request ID")
	commandPath := f.String("command", "", "existing signed fence command")
	commandPin := f.String("command-id", "", "independent command ID")
	certPath := f.String("certificate", "", "existing quorum certificate")
	certPin := f.String("certificate-id", "", "independent certificate artifact ID")
	nonceText := f.String("nonce", "", "explicit request nonce; does not change operation identity")
	kindText := f.String("kind", "", "request kind: review, vote or commit")
	pairsPath := f.String("pairs", "", "bounded JSON request/response file pairs for quorum assembly")
	outputPath := f.String("out", "", "immutable public artifact output outside witness roots")
	expectedReview := f.String("expected-review-id", "", "exact reported public review ID")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected witness positional arguments")
	}
	allowedModes := map[string]map[string]bool{
		witnessServerCommand: {"review": true, "create-review": true, "create": true, "serve": true, "vote": true, "commit": true, "recover-vote-review": true, "recover-commit-review": true, "recover-vote": true, "recover-commit": true},
		witnessClientCommand: {"review": true, "exchange": true}, witnessRequestCommand: {"review": true, "publish": true}, witnessQuorumCommand: {"review": true, "publish": true},
	}
	if !allowedModes[args[0]][*mode] {
		return errors.New("unsupported witness mode")
	}
	if *timeout < remotewire.MinimumTimeout || *timeout > remotewire.MaximumTimeout {
		return errors.New("witness timeout must be 100ms..2m")
	}
	sid, err := witnessID("scope-id", *scopePin)
	if err != nil {
		return err
	}
	scopeFile, err := custodyCommandFile(*scopePath)
	if err != nil {
		return err
	}
	b, err := readRegularArtifact(scopeFile, custodyfence.MaximumScopeBytes)
	if err != nil {
		return err
	}
	scope, err := custodyfence.DecodeScope(b)
	if err != nil {
		return err
	}
	id, _ := scope.ID()
	if id != sid {
		return custodyfence.ErrScope
	}
	var member [32]byte
	if *memberText != "" {
		h, err := witnessID("witness-public-key", *memberText)
		if err != nil {
			return err
		}
		member = [32]byte(h)
		found := false
		for _, k := range scope.Witnesses {
			found = found || k == member
		}
		if !found {
			return custodyfence.ErrWitness
		}
	}
	var request witnesswire.Request
	var command custodyfence.Command
	var cert custodyfence.Certificate
	inputs := []string{scopeFile}
	if *commandPath != "" {
		file, err := custodyCommandFile(*commandPath)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		b, err := readRegularArtifact(file, custodyfence.CommandBytes)
		if err != nil {
			return err
		}
		command, err = custodyfence.DecodeCommand(b)
		if err != nil {
			return err
		}
		cid, _ := command.ID()
		pin, err := witnessID("command-id", *commandPin)
		if err != nil || pin != cid {
			return custodyfence.ErrCommand
		}
		if err := command.Verify(scope); err != nil {
			return err
		}
	}
	if *certPath != "" {
		file, err := custodyCommandFile(*certPath)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		b, err := readRegularArtifact(file, custodyfence.MaximumCertificateBytes)
		if err != nil {
			return err
		}
		cert, err = custodyfence.DecodeCertificate(b)
		if err != nil {
			return err
		}
		pin, err := witnessID("certificate-id", *certPin)
		if err != nil || pin != witnessArtifactID("certificate", b) {
			return custodyfence.ErrQuorum
		}
		if err := cert.Verify(scope); err != nil {
			return err
		}
	}
	var expected custodyfence.WitnessPin
	if args[0] == witnessServerCommand || args[0] == witnessRequestCommand {
		n, err := strconv.ParseUint(*sequence, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != *sequence {
			return errors.New("explicit canonical expected-sequence required")
		}
		h, err := witnessID("expected-head", *head)
		if err != nil {
			return err
		}
		expected.Position = custodyfence.Position{Sequence: n, HeadID: h}
		if *pending != "" {
			expected.PendingID, err = witnessID("pending-id", *pending)
			if err != nil {
				return err
			}
		}
	}
	var artifact []byte
	var snapshot custodyfence.Snapshot
	var root string
	var descriptor any
	switch args[0] {
	case witnessServerCommand:
		if types.Hash(member).IsZero() {
			return custodyfence.ErrWitness
		}
		root, err = filepath.Abs(*rootPath)
		if err != nil || *rootPath == "" {
			return errors.New("explicit witness root required")
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(root))
		if err != nil {
			return err
		}
		root = filepath.Join(parent, filepath.Base(root))
		for _, file := range append(append([]string{}, inputs...), *keyPath, *transportPath) {
			if file == "" {
				continue
			}
			file, err = filepath.Abs(file)
			if err != nil {
				return err
			}
			if err := witnessOutside(root, file); err != nil {
				return err
			}
		}
		if *mode == "create-review" || *mode == "create" {
			if expected != (custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}) {
				return custodyfence.ErrTransition
			}
			if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
				return errors.New("create requires an absent original witness root")
			}
			info, err := os.Stat(parent)
			if err != nil || info.Mode().Perm()&0o077 != 0 {
				return errors.New("witness parent must be private")
			}
		} else if strings.HasPrefix(*mode, "recover-") {
			// Recovery is explicit and binds the separately retained before pin
			// plus exact attempted command/certificate in its public review.
			if strings.HasPrefix(*mode, "recover-vote") && *commandPath == "" || strings.HasPrefix(*mode, "recover-commit") && *certPath == "" {
				return errors.New("exact recovery artifact required")
			}
		} else {
			snapshot, _, err = custodyfence.Inspect(root, scope, sid, member, expected)
			if err != nil {
				return err
			}
		}
		descriptor = struct {
			Root                                string
			Scope                               types.Hash
			Witness                             [32]byte
			Before                              custodyfence.WitnessPin
			Snapshot                            custodyfence.Snapshot
			Command                             custodyfence.Command
			Certificate                         custodyfence.Certificate
			Transport, Clients, Listen, Timeout string
		}{root, sid, member, expected, snapshot, command, cert, *transportText, *clientsText, *listen, timeout.String()}
	case witnessRequestCommand:
		nonce, err := witnessID("nonce", *nonceText)
		if err != nil {
			return err
		}
		request = witnesswire.Request{ScopeID: sid, Nonce: nonce, Expected: expected}
		switch *kindText {
		case "review":
			request.Kind = witnesswire.Review
		case "vote":
			request.Kind = witnesswire.Vote
			request.Command = command
		case "commit":
			request.Kind = witnesswire.Commit
			request.Certificate = cert
		default:
			return witnesswire.ErrProtocol
		}
		if err := request.Validate(scope); err != nil {
			return err
		}
		artifact, _ = request.CanonicalBytes()
		descriptor = request
	case witnessQuorumCommand:
		file, err := custodyCommandFile(*pairsPath)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		b, err := readRegularArtifact(file, 32768)
		if err != nil {
			return err
		}
		var pairs []struct {
			Request  string `json:"request"`
			Response string `json:"response"`
		}
		d := json.NewDecoder(strings.NewReader(string(b)))
		d.DisallowUnknownFields()
		if err := d.Decode(&pairs); err != nil {
			return err
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return errors.New("trailing quorum pair data")
		}
		if len(pairs) < 1 || len(pairs) > custodyfence.MaximumWitnesses {
			return custodyfence.ErrQuorum
		}
		var requests []witnesswire.Request
		var responses []witnesswire.Response
		for _, p := range pairs {
			rfile, err := custodyCommandFile(p.Request)
			if err != nil {
				return err
			}
			sfile, err := custodyCommandFile(p.Response)
			if err != nil {
				return err
			}
			inputs = append(inputs, rfile, sfile)
			rb, err := readRegularArtifact(rfile, witnesswire.MaxFrameBytes)
			if err != nil {
				return err
			}
			r, err := witnesswire.DecodeRequest(rb)
			if err != nil {
				return err
			}
			sb, err := readRegularArtifact(sfile, witnesswire.MaxFrameBytes)
			if err != nil {
				return err
			}
			s, err := witnesswire.DecodeResponse(sb)
			if err != nil {
				return err
			}
			requests = append(requests, r)
			responses = append(responses, s)
		}
		cert, err = witnesswire.Assemble(scope, requests, responses)
		if err != nil {
			return err
		}
		cid, _ := cert.Command.ID()
		pin, err := witnessID("command-id", *commandPin)
		if err != nil || pin != cid {
			return custodyfence.ErrCommand
		}
		artifact, _ = cert.CanonicalBytes()
		descriptor = cert
	case witnessClientCommand:
		if types.Hash(member).IsZero() {
			return custodyfence.ErrWitness
		}
		file, err := custodyCommandFile(*requestPath)
		if err != nil {
			return err
		}
		inputs = append(inputs, file)
		b, err := readRegularArtifact(file, witnesswire.MaxFrameBytes)
		if err != nil {
			return err
		}
		request, err = witnesswire.DecodeRequest(b)
		if err != nil {
			return err
		}
		pin, err := witnessID("request-id", *requestPin)
		if err != nil {
			return err
		}
		id, _ := request.ID()
		if id != pin {
			return witnesswire.ErrProtocol
		}
		if err := request.Validate(scope); err != nil {
			return err
		}
		descriptor = struct {
			Request                                        witnesswire.Request
			Member                                         [32]byte
			Peer, LocalTransport, ServerTransport, Timeout string
		}{request, member, *peer, *transportText, *serverText, timeout.String()}
	default:
		return errors.New("unsupported witness command")
	}
	action := "publish"
	if args[0] == witnessClientCommand {
		action = "exchange"
	}
	if args[0] == witnessServerCommand {
		if *commandPath != "" && *certPath != "" {
			return errors.New("select one exact vote or commit artifact")
		}
		action = strings.TrimSuffix(*mode, "-review")
		if *mode == "review" {
			action = "serve"
			if *commandPath != "" {
				action = "vote"
			}
			if *certPath != "" {
				action = "commit"
			}
		}
		if (action == "vote" || action == "recover-vote") && *commandPath == "" {
			return errors.New("vote requires the pinned command")
		}
		if (action == "commit" || action == "recover-commit") && *certPath == "" {
			return errors.New("commit requires the pinned certificate")
		}
		if (action == "create" || action == "serve") && (*commandPath != "" || *certPath != "" || *outputPath != "") {
			return errors.New("create/serve cannot select vote, certificate or output artifacts")
		}
	}
	public, err := json.Marshal(struct {
		Command, Action string
		Context         any
	}{args[0], action, descriptor})
	if err != nil {
		return err
	}
	review := types.DomainHash("OMESH/local/custody-witness-cli/review/v0", public)
	var preparedOutput string
	if *outputPath != "" {
		preparedOutput, err = custodyCommandOutput(*outputPath)
		if err != nil {
			return err
		}
		if root != "" {
			if err := witnessOutside(root, preparedOutput); err != nil {
				return err
			}
		}
		for _, file := range append(append([]string{}, inputs...), *keyPath, *transportPath) {
			if file != "" {
				if err := rejectPruneLineageOutputAlias(preparedOutput, []string{file}); err != nil {
					return err
				}
			}
		}
	}
	needsOutput := args[0] == witnessRequestCommand || args[0] == witnessQuorumCommand || args[0] == witnessClientCommand || *mode == "vote"
	if needsOutput && preparedOutput == "" && *mode != "review" {
		return errors.New("explicit immutable output required before witness action")
	}
	if *mode == "review" || *mode == "create-review" || strings.HasSuffix(*mode, "-review") {
		return writePruneOutputLine(out, fmt.Sprintf("custody_witness_review review_id=%s scope_id=%s keys_loaded=false execution_authorized=false\nscope:\n%s\n", review, sid, public))
	}
	approved, err := witnessID("expected-review-id", *expectedReview)
	if err != nil || approved != review {
		return errors.New("witness action needs the exact public review ID")
	}
	publish := func(kind string, b []byte) error {
		path := preparedOutput
		if path == "" {
			return errors.New("immutable output not prepared")
		}
		if root != "" {
			if err := witnessOutside(root, path); err != nil {
				return err
			}
		}
		aliases := append(append([]string{}, inputs...), *keyPath, *transportPath)
		for _, p := range aliases {
			if p != "" {
				if err := rejectPruneLineageOutputAlias(path, []string{p}); err != nil {
					return err
				}
			}
		}
		if err := publishCustodyCommandArtifact(path, b); err != nil {
			return err
		}
		rid, _ := request.ID()
		return writePruneOutputLine(out, fmt.Sprintf("custody_witness_artifact kind=%s artifact_id=%s request_id=%s execution_authorized=false\n", kind, witnessArtifactID(kind, b), rid))
	}
	if args[0] == witnessRequestCommand || args[0] == witnessQuorumCommand {
		if *mode != "publish" {
			return errors.New("artifact action requires publish")
		}
		kind := "request"
		if args[0] == witnessQuorumCommand {
			kind = "certificate"
		}
		return publish(kind, artifact)
	}
	if args[0] == witnessClientCommand {
		if *mode != "exchange" {
			return errors.New("client action requires exchange")
		}
		local, err := witnessID("transport-public-key", *transportText)
		if err != nil {
			return err
		}
		remote, err := witnessID("server-transport-public-key", *serverText)
		if err != nil {
			return err
		}
		key, err := witnessKey(*transportPath, [32]byte(local))
		if err != nil {
			return err
		}
		server, err := transportPeer([32]byte(remote))
		if err != nil {
			return err
		}
		config := libp2ptransport.DefaultConfig()
		config.Listen = []string{*listen}
		run, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		host, err := libp2ptransport.New(run, key, config, nil)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, host.Close()) }()
		stream, _, err := host.OpenCustodyWitnessStream(run, *peer, server)
		if err != nil {
			return errors.Join(witnesswire.ErrUnconfirmed, err)
		}
		response, err := witnesswire.Exchange(run, stream, scope, member, request, *timeout)
		if err != nil {
			return err
		}
		b, _ := response.CanonicalBytes()
		return publish("response", b)
	}
	key, err := witnessKey(*keyPath, member)
	if err != nil {
		return err
	}
	var w *custodyfence.Witness
	switch *mode {
	case "create":
		w, err = custodyfence.Create(root, scope, sid, key)
	case "recover-vote":
		w, err = custodyfence.RecoverVote(root, scope, sid, key, expected, command)
	case "recover-commit":
		w, err = custodyfence.RecoverCommit(root, scope, sid, key, expected, cert)
	case "serve", "vote", "commit":
		w, err = custodyfence.Open(root, scope, sid, key, expected)
	default:
		return errors.New("unsupported witness action")
	}
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, w.Close()) }()
	switch *mode {
	case "vote":
		v, err := w.VoteAt(expected, command)
		if err != nil {
			return err
		}
		b, _ := v.CanonicalBytes()
		return publish("vote", b)
	case "commit":
		if err := w.CommitAt(expected, cert); err != nil {
			return err
		}
	case "serve":
		transportID, err := witnessID("transport-public-key", *transportText)
		if err != nil {
			return err
		}
		transportKey, err := witnessKey(*transportPath, [32]byte(transportID))
		if err != nil {
			return err
		}
		var clients []types.Hash
		for _, value := range strings.Split(*clientsText, ",") {
			id, err := witnessID("client", value)
			if err != nil {
				return err
			}
			clients = append(clients, id)
		}
		control, err := ownPruneControlInput(input)
		if err != nil {
			return err
		}
		defer control.Close()
		writer, err := ownPruneEffectOutput(out)
		if err != nil {
			return err
		}
		defer writer.Close()
		config := libp2ptransport.DefaultConfig()
		config.Listen = []string{*listen}
		service, err := witnessnet.Start(ctx, w, scope, sid, transportKey, config, clients, *timeout)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, service.Close()) }()
		if err := writePruneOutputLine(writer, fmt.Sprintf("custody_witness_serving scope_id=%s witness_public_key=%x peer_id=%s address=%s execution_authorized=false\n", sid, member, service.ID(), strings.Join(service.Addresses(), ","))); err != nil {
			return err
		}
		read := make(chan error, 1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			scan := bufio.NewScanner(control)
			scan.Buffer(make([]byte, 128), 256)
			if scan.Scan() {
				if scan.Text() != "close" {
					read <- errors.New("witness serve accepts only close or EOF")
					return
				}
			}
			read <- scan.Err()
		}()
		defer func() { _ = control.Close(); <-done }()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-read:
			return err
		}
	}
	x, pin, err := w.Snapshot()
	if err != nil {
		return err
	}
	data, _ := json.Marshal(struct {
		Snapshot custodyfence.Snapshot
		Pin      custodyfence.WitnessPin
	}{x, pin})
	return writePruneOutputLine(out, fmt.Sprintf("custody_witness_state mode=%s execution_authorized=false\n%s\n", *mode, data))
}
