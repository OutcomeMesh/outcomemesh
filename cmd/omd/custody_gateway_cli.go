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

	"github.com/outcomemesh/outcomemesh/core/types"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway"
	client "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const custodyGatewayCommand = "work-archive-custody-gateway"

func runCustodyGatewayCLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyGateway(ctx, args, os.Stdout)
}

// Public plan files use Go JSON field names. Unsigned Descriptor/Request JSON is
// signed only by offline actions; service requests never receive private seeds.
func runCustodyGateway(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return wire.ErrArtifact
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "", "identity-create, identity-public, descriptor-prepare, descriptor-sign, configure, request-sign, response-inspect, call, serve, cleanup-socket")
	participantUID := f.Uint("participant-uid", 0, "separate unprivileged Linux participant UID")
	eventLimit := f.Uint("event-limit", wire.MaximumEvents, "bounded lifetime gateway event count")
	clients := f.String("clients", "", "comma-separated participant Ed25519 public keys, hexadecimal")
	mode := f.String("mode", "review", "review or run")
	root := f.String("root", "", "original private owner root; must be outside participant access")
	input := f.String("input", "", "strict JSON config or unsigned descriptor/request")
	descriptor := f.String("descriptor", "", "complete issuer-signed binary descriptor")
	descriptorID := f.String("descriptor-id", "", "independently retained descriptor ID")
	response := f.String("response", "", "complete signed historical gateway response")
	request := f.String("request", "", "complete binary signed request; exact recovery attempt for serve")
	pinPath := f.String("position", "", "independently retained Position JSON for startup")
	socket := f.String("socket", "", "public Unix socket outside all private roots")
	socketPin := f.String("socket-id", "", "independently reviewed stale socket identity")
	keyPath := f.String("key", "", "offline signer seed file (64 hexadecimal characters)")
	output := f.String("out", "", "fresh public artifact path")
	expected := f.String("expected-review-id", "", "exact public review ID")
	if e := parsePruneFlags(f, args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 || (*mode != "review" && *mode != "run") {
		return wire.ErrArtifact
	}
	valid := map[string]bool{"identity-create": true, "identity-public": true, "descriptor-sign": true, "descriptor-prepare": true, "configure": true, "request-sign": true, "response-inspect": true, "call": true, "serve": true, "cleanup-socket": true}
	if !valid[*action] {
		return wire.ErrArtifact
	}
	// Reject irrelevant selectors, so review never disguises ignored inputs.
	needRoot := *action == "identity-create" || *action == "identity-public" || *action == "descriptor-prepare" || *action == "configure" || *action == "serve" || *action == "cleanup-socket"
	needInput := *action == "descriptor-prepare" || *action == "descriptor-sign" || *action == "request-sign" || *action == "configure"
	needDescriptor := *action == "call" || *action == "serve" || *action == "response-inspect"
	needRequest := *action == "call"
	needSocket := *action == "call" || *action == "serve" || *action == "cleanup-socket"
	needKey := *action == "descriptor-sign" || *action == "request-sign"
	needOutput := *action != "serve" && *action != "cleanup-socket"
	for _, v := range []struct {
		value    string
		required bool
	}{{*root, needRoot}, {*input, needInput}, {*descriptor, needDescriptor}, {*response, *action == "response-inspect"}, {*pinPath, *action == "serve"}, {*socket, needSocket}, {*socketPin, *action == "cleanup-socket"}, {*keyPath, needKey}, {*output, needOutput}} {
		if (v.value != "") != v.required {
			return wire.ErrArtifact
		}
	}
	var actorKeys [][32]byte
	if *action == "descriptor-prepare" {
		if *participantUID == 0 || uint64(*participantUID) > uint64(^uint32(0)) || *participantUID == uint(os.Geteuid()) || *eventLimit < 2 || *eventLimit > wire.MaximumEvents {
			return wire.ErrArtifact
		}
		for _, v := range strings.Split(*clients, ",") {
			b, e := hex.DecodeString(v)
			if e != nil || len(b) != 32 {
				return wire.ErrArtifact
			}
			var k [32]byte
			copy(k[:], b)
			actorKeys = append(actorKeys, k)
		}
		sort.Slice(actorKeys, func(i, j int) bool { return bytes.Compare(actorKeys[i][:], actorKeys[j][:]) < 0 })
		if len(actorKeys) == 0 || len(actorKeys) > wire.MaximumClients {
			return wire.ErrArtifact
		}
	} else if *participantUID != 0 || *clients != "" || *eventLimit != wire.MaximumEvents {
		return wire.ErrArtifact
	}
	if (*request != "") != needRequest && !(*action == "serve" && *request != "") {
		return wire.ErrArtifact
	}
	if (*descriptorID != "") != needDescriptor {
		return wire.ErrArtifact
	}
	paths := map[string]string{}
	canonical := func(path *string, fresh bool) error {
		if *path == "" {
			return nil
		}
		var e error
		if fresh {
			*path, e = custodyCommandOutput(*path)
		} else {
			*path, e = custodyCommandFile(*path)
		}
		return e
	}
	if needRoot {
		abs, e := filepath.Abs(*root)
		if e != nil {
			return e
		}
		*root = filepath.Clean(abs)
	}
	var in, descRaw, reqRaw []byte
	var runtimePayload []byte
	var runtimeSummary any
	var inspected wire.Response
	var pin wire.Position
	var desc wire.Descriptor
	var req wire.Request
	var config gateway.Config
	var unsigned wire.Descriptor
	var socketID types.Hash
	var did types.Hash
	load := func(path *string, limit int) ([]byte, error) {
		if e := canonical(path, false); e != nil {
			return nil, e
		}
		raw, e := readRegularArtifact(*path, limit)
		if e == nil {
			paths[*path] = cutoverArtifactID(raw).String()
		}
		return raw, e
	}
	var e error
	if *input != "" {
		in, e = load(input, gateway.MaximumConfigBytes)
		if e != nil {
			return e
		}
		switch *action {
		case "configure", "descriptor-prepare":
			config, e = gateway.DecodeConfig(in)
		case "descriptor-sign":
			e = cutoverJSON(in, &unsigned)
		case "request-sign":
			e = cutoverJSON(in, &req)
		}
		if e != nil {
			return e
		}
	}
	if needDescriptor {
		descRaw, e = load(descriptor, wire.MaximumDescriptorBytes)
		if e != nil {
			return e
		}
		desc, e = wire.DecodeDescriptor(descRaw)
		if e != nil {
			return e
		}
		did, e = witnessID("descriptor-id", *descriptorID)
		actual, _ := desc.ID()
		if e != nil || actual != did {
			return wire.ErrArtifact
		}
	}
	if *response != "" {
		raw, e := load(response, wire.MaximumResponseBytes)
		if e != nil {
			return e
		}
		inspected, e = wire.DecodeResponse(raw)
		if e != nil {
			return e
		}
		if e = inspected.Verify(desc, inspected.Request); e != nil {
			return e
		}
	}
	if *request != "" {
		reqRaw, e = load(request, wire.MaximumServiceRequestBytes)
		if e != nil {
			return e
		}
		if len(reqRaw) >= 8 && string(reqRaw[:8]) == "OMCGXRQ5" {
			req, runtimePayload, e = wire.DecodeRuntimeRequest(reqRaw)
		} else {
			req, e = wire.DecodeRequest(reqRaw)
		}
		if e != nil {
			return e
		}
		if e = req.Authorize(desc); e != nil {
			return e
		}
	}
	if runtimePayload != nil {
		cmd, e := v2.DecodeProtectedCommand(runtimePayload)
		if e != nil {
			return e
		}
		runtimeSummary = profile5PublicCommand(cmd)
	}
	if *pinPath != "" {
		raw, e := load(pinPath, 4096)
		if e != nil {
			return e
		}
		if e = cutoverJSON(raw, &pin); e != nil || !pin.Valid() {
			return wire.ErrArtifact
		}
	}
	if *socketPin != "" {
		socketID, e = witnessID("socket-id", *socketPin)
		if e != nil {
			return e
		}
	}
	if needKey {
		if e = canonical(keyPath, false); e != nil {
			return e
		}
	}
	if needOutput {
		if e = canonical(output, true); e != nil {
			return e
		}
	}
	if needSocket {
		p, e := filepath.Abs(*socket)
		if e != nil {
			return e
		}
		*socket = filepath.Clean(p)
	}
	// All public inputs/outputs and sockets must remain outside the owner and
	// source roots. No output may overwrite a signing key or preparation input.
	owners := []string{*root}
	if *action == "configure" || *action == "descriptor-prepare" {
		owners = append(owners, config.Source.Journal, config.Source.Authority, config.Source.AuthorityPins, config.Objects)
		owners = append(owners, config.Source.Workers...)
	}
	for _, owner := range owners {
		if owner == "" {
			continue
		}
		for _, p := range append([]string{*input, *descriptor, *request, *response, *pinPath, *output, *keyPath, *socket}, mapKeys(paths)...) {
			if p != "" {
				if e = witnessOutside(owner, p); e != nil {
					return e
				}
			}
		}
	}
	if *output != "" {
		for _, p := range append([]string{*keyPath}, mapKeys(paths)...) {
			if p != "" && p == *output {
				return wire.ErrArtifact
			}
		}
	}
	public, e := json.Marshal(struct {
		Action, Root, Socket, Key, Output string
		Inputs                            map[string]string
		DescriptorID                      types.Hash
		SocketID                          types.Hash
		Position                          wire.Position
		ParticipantUID                    uint
		EventLimit                        uint
		Clients                           [][32]byte
		Runtime                           any
		Request                           wire.Request
	}{*action, *root, *socket, *keyPath, *output, paths, did, socketID, pin, *participantUID, *eventLimit, actorKeys, runtimeSummary, req})
	if e != nil {
		return e
	}
	review := types.DomainHash(wire.Domain+"cli/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_gateway_review action=%s review_id=%s owners_opened=false keys_loaded=false execution_granted=false\n%s\n", *action, review, public))
	}
	want, e := witnessID("expected-review-id", *expected)
	if e != nil || want != review {
		return errors.New("gateway action requires its exact public review")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if needOutput {
		if _, e = os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
			return errors.New("retain existing output and use a fresh public path")
		}
	}
	var result []byte
	switch *action {
	case "descriptor-prepare":
		unsigned, e = gateway.DraftDescriptor(*root, config, uint32(*participantUID), actorKeys, uint32(*eventLimit))
		if e == nil {
			result, e = json.Marshal(unsigned)
		}
	case "identity-create":
		var id gateway.Identity
		id, e = gateway.CreateIdentity(*root)
		if e == nil {
			result, e = json.Marshal(id)
		}
	case "identity-public":
		var id gateway.Identity
		id, e = gateway.ReadIdentity(*root)
		if e == nil {
			result, e = json.Marshal(id)
		}
	case "descriptor-sign", "request-sign":
		raw, err := readRegularArtifact(*keyPath, 256)
		if err != nil {
			return err
		}
		seed, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
		clear(raw)
		if err != nil || len(seed) != ed25519.SeedSize {
			return wire.ErrArtifact
		}
		key := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		defer clear(key)
		if *action == "descriptor-sign" {
			unsigned, e = unsigned.Sign(key)
			if e == nil {
				result, e = unsigned.CanonicalBytes()
			}
		} else {
			req, e = req.Sign(key)
			if e == nil {
				result, e = req.CanonicalBytes()
			}
		}
	case "configure":
		e = gateway.Configure(ctx, *root, config)
		if e == nil {
			result = []byte("{\"configured\":true,\"execution_granted\":false}\n")
		}
	case "call":
		var r wire.Response
		if runtimePayload != nil {
			r, e = client.CallRuntime(ctx, *socket, desc, req, runtimePayload)
		} else {
			r, e = client.Call(ctx, *socket, desc, req)
		}
		if e == nil {
			result, e = r.CanonicalBytes()
		}
	case "response-inspect":
		p, e2 := inspected.Position()
		if e2 != nil {
			return e2
		}
		result, e = json.Marshal(struct {
			Position         wire.Position
			SourceID         types.Hash
			Request          wire.Request
			Revoked          bool
			DataBytes        int
			ExecutionGranted bool
		}{p, inspected.SourceID, inspected.Request, inspected.Request.Kind == wire.Revoke, len(inspected.Data), false})
	case "serve":
		if !client.Supported() {
			return wire.ErrAccess
		}
		var recover *wire.Request
		if len(reqRaw) > 0 {
			recover = &req
		}
		var owner *gateway.Owner
		owner, e = gateway.Open(*root, did, pin, recover)
		if e != nil {
			return e
		}
		defer owner.Close()
		e = gateway.Serve(ctx, owner, *socket, func(id types.Hash) error {
			p, revoked := owner.Position()
			return writePruneOutputLine(out, fmt.Sprintf("custody_gateway_ready socket_id=%s sequence=%d head=%s revoked=%t execution_granted=false\n", id, p.Sequence, p.Head, revoked))
		})
		return e
	case "cleanup-socket":
		return gateway.CleanupSocket(*root, *socket, socketID)
	}
	if e != nil {
		return e
	}
	if e = publishCustodyCommandArtifact(*output, result); e != nil {
		return e
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_gateway action=%s artifact_id=%s execution_granted=false\n", *action, cutoverArtifactID(result)))
}
func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
