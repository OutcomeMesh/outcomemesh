package main

import (
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
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	client "github.com/outcomemesh/outcomemesh/node/pruneservice/serviceclient"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

const pruneServiceCommand = "work-prune-service"

func runPruneServiceCLI(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runPruneServiceCLIContext(ctx, args, os.Stdout)
}

type pruneServiceCLIFlags struct {
	Action, Mode, Root, Input, Output, Key, Identity, Plan, PlanID          string
	Descriptor, DescriptorID, Request, Response, Position, Socket, SocketID string
	Issuer, Guard, Nonce, Expected, ChallengeOut, ApprovalOut, PositionOut  string
	ContinuationID                                                          string
	TransportKey, TransportPublic, RelayPublic, Clients, Address, Listen    string
	Timeout                                                                 time.Duration
	ParticipantUID                                                          uint
}

func runPruneServiceCLIContext(ctx context.Context, args []string, out io.Writer) (returnErr error) {
	if ctx == nil || out == nil || len(args) == 0 {
		return wire.ErrArtifact
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f := flag.NewFlagSet(pruneServiceCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var a pruneServiceCLIFlags
	for _, v := range []struct {
		p                 *string
		name, value, help string
	}{
		{&a.Action, "action", "", "identity-create, identity-public, enrollment-prepare/sign, descriptor-prepare/sign, configure, request-prepare/sign, serve, call, inspect, status, recover, continuation-review, continue, relay-serve, remote-call, cleanup-socket"},
		{&a.Mode, "mode", "review", "review or run"}, {&a.Root, "root", "", "original private service root"},
		{&a.Input, "input", "", "strict unsigned artifact or owner-only runtime config JSON"}, {&a.Output, "out", "", "immutable public output"},
		{&a.Key, "key", "", "offline or participant signer seed; exactly 32 private bytes"}, {&a.Identity, "identity", "", "public service identity JSON"},
		{&a.Plan, "plan", "", "original scheduled plan before service binding"}, {&a.PlanID, "plan-id", "", "independently retained plan ID"},
		{&a.Descriptor, "descriptor", "", "signed public service descriptor"}, {&a.DescriptorID, "descriptor-id", "", "independently retained descriptor ID"},
		{&a.Request, "request", "", "complete signed request"}, {&a.Response, "response", "", "complete retained response"},
		{&a.Position, "position", "", "independently retained service position JSON"}, {&a.Socket, "socket", "", "public Unix socket outside private roots"},
		{&a.SocketID, "socket-id", "", "reviewed stale socket identity"}, {&a.Issuer, "issuer", "", "approved issuer public key, hexadecimal"},
		{&a.Guard, "guard", "", "independent guard public key, hexadecimal"}, {&a.Nonce, "nonce", "", "request nonce, 32-byte hexadecimal"},
		{&a.Expected, "expected-review-id", "", "exact preceding CLI review ID"}, {&a.ChallengeOut, "challenge-out", "", "retain the verified candidate challenge before signing"},
		{&a.ApprovalOut, "approval-out", "", "retain the exact consumer approval before sending"},
		{&a.ContinuationID, "continuation-id", "", "exact original-prefix continuation review ID"},
		{&a.TransportKey, "transport-key", "", "private transport seed, separate from all protocol roles"},
		{&a.TransportPublic, "transport-public-key", "", "independently retained local transport public key"},
		{&a.RelayPublic, "relay-public-key", "", "independently retained remote relay public key"},
		{&a.Clients, "client-transport-keys", "", "explicit comma-separated allowed client transport public keys"},
		{&a.Address, "address", "", "remote relay multiaddress"},
		{&a.Listen, "listen", "", "explicit relay listen multiaddresses, comma-separated"},
		{&a.PositionOut, "position-out", "", "optional immutable initial or confirmed service cursor JSON"},
	} {
		f.StringVar(v.p, v.name, v.value, v.help)
	}
	f.DurationVar(&a.Timeout, "timeout", wire.ExchangeDeadline, "bounded network exchange timeout")
	f.UintVar(&a.ParticipantUID, "participant-uid", 0, "separate unprivileged Linux participant UID")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || (a.Mode != "review" && a.Mode != "run") || (a.Mode == "review" && a.Expected != "") {
		return wire.ErrArtifact
	}
	// Unsupported serving never parses owner paths or loads any key.
	if (a.Action == "serve" || a.Action == "call" || a.Action == "cleanup-socket" || a.Action == "relay-serve") && runtime.GOOS != "linux" {
		return errors.New("isolated Prune transport requires Linux peer credentials")
	}
	required := map[string][]string{
		"identity-create": {"root", "out"}, "identity-public": {"root", "out"},
		"enrollment-prepare": {"identity", "plan", "plan-id", "issuer", "guard", "out"}, "enrollment-sign": {"input", "key", "out"},
		"descriptor-prepare": {"root", "input", "participant-uid", "out"}, "descriptor-sign": {"input", "key", "out"},
		"configure":       {"root", "input", "descriptor", "descriptor-id", "out"},
		"request-prepare": {"descriptor", "descriptor-id", "nonce", "out"}, "request-sign": {"input", "descriptor", "descriptor-id", "key", "out"},
		"serve":               {"root", "descriptor", "descriptor-id", "position", "socket"},
		"call":                {"descriptor", "descriptor-id", "request", "socket", "key", "challenge-out", "approval-out", "out"},
		"inspect":             {"descriptor", "descriptor-id", "request", "response", "out"},
		"recover":             {"root", "descriptor", "descriptor-id", "position", "request", "out"},
		"cleanup-socket":      {"socket", "socket-id"},
		"status":              {"root", "descriptor", "descriptor-id", "position", "request", "out"},
		"continuation-review": {"root", "descriptor", "descriptor-id", "position", "request", "out"},
		"continue":            {"root", "descriptor", "descriptor-id", "position", "request", "continuation-id", "out"},
		"relay-serve":         {"descriptor", "descriptor-id", "socket", "transport-key", "transport-public-key", "client-transport-keys", "listen"},
		"remote-call":         {"descriptor", "descriptor-id", "request", "address", "transport-key", "transport-public-key", "relay-public-key", "key", "challenge-out", "approval-out", "out"},
	}
	need, ok := required[a.Action]
	if !ok {
		return wire.ErrArtifact
	}
	allowed := map[string]bool{"action": true, "mode": true, "expected-review-id": true}
	for _, name := range need {
		allowed[name] = true
	}
	if a.Action == "relay-serve" || a.Action == "remote-call" {
		allowed["timeout"] = true
	}
	if a.Action == "serve" {
		allowed["request"] = true
	}
	if a.Action == "request-prepare" || a.Action == "inspect" || a.Action == "call" || a.Action == "recover" || a.Action == "status" || a.Action == "continue" || a.Action == "remote-call" {
		allowed["position-out"] = true
	}
	var wrong bool
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			wrong = true
		}
	})
	for _, name := range need {
		if f.Lookup(name).Value.String() == "" || name == "participant-uid" && a.ParticipantUID == 0 {
			wrong = true
		}
	}
	if wrong || a.ParticipantUID > uint(^uint32(0)) {
		return wire.ErrArtifact
	}

	inputs := map[string]string{}
	load := func(path *string, limit int) ([]byte, error) {
		p, err := custodyCommandFile(*path)
		if err != nil {
			return nil, err
		}
		*path = p
		b, err := readRegularArtifact(p, limit)
		if err == nil {
			inputs[p] = types.DomainHash(wire.Domain+"cli/input", b).String()
		}
		return b, err
	}
	var desc wire.Descriptor
	var did types.Hash
	var req wire.Request
	var response wire.Response
	var position wire.Position
	var identity service.Identity
	var plan store.ScheduledPrunePlan
	var enrollment prunefence.ServiceEnrollment
	var unsigned wire.Descriptor
	var config service.Config
	if a.Descriptor != "" {
		b, err := load(&a.Descriptor, wire.MaximumDescriptorBytes)
		if err != nil {
			return err
		}
		desc, err = wire.DecodeDescriptor(b)
		if err != nil {
			return err
		}
		did, err = pruneExternalID("descriptor-id", a.DescriptorID)
		if err != nil {
			return err
		}
		id, _ := desc.ID()
		if id != did {
			return wire.ErrArtifact
		}
	}
	if a.Identity != "" {
		b, err := load(&a.Identity, 4096)
		if err != nil {
			return err
		}
		if err = cutoverJSON(b, &identity); err != nil {
			return err
		}
		if identity.RootID.IsZero() || identity.Service == ([32]byte{}) || identity.Transport == ([32]byte{}) || identity.Service == identity.Transport {
			return wire.ErrArtifact
		}
	}
	if a.Plan != "" {
		b, err := load(&a.Plan, store.MaximumScheduledPruneInventoryBytes)
		if err != nil {
			return err
		}
		plan, err = store.DecodeScheduledPrunePlan(b)
		if err != nil {
			return err
		}
		id, err := pruneExternalID("plan-id", a.PlanID)
		if err != nil {
			return err
		}
		got, _ := plan.ID()
		if got != id || plan.FencePolicy != nil {
			return wire.ErrArtifact
		}
	}
	if a.Request != "" {
		b, err := load(&a.Request, wire.RequestBytes)
		if err != nil {
			return err
		}
		req, err = wire.DecodeRequest(b)
		if err != nil {
			return err
		}
		if err = req.Authorize(desc); err != nil {
			return err
		}
	}
	if a.Response != "" {
		b, err := load(&a.Response, wire.MaximumResponseBytes)
		if err != nil {
			return err
		}
		response, err = wire.DecodeResponse(b)
		if err != nil {
			return err
		}
		if err = response.Verify(desc, req); err != nil {
			return err
		}
	}
	if a.Position != "" {
		b, err := load(&a.Position, 4096)
		if err != nil {
			return err
		}
		if err = cutoverJSON(b, &position); err != nil || !position.Valid() {
			return wire.ErrArtifact
		}
	}
	if a.Input != "" {
		limit := service.MaximumConfigBytes
		if a.Action == "enrollment-sign" {
			limit = 4096
		} else if a.Action == "request-sign" || a.Action == "descriptor-sign" {
			limit = 16384
		}
		b, err := load(&a.Input, limit)
		if err != nil {
			return err
		}
		switch a.Action {
		case "configure", "descriptor-prepare":
			config, err = service.DecodeConfig(b)
		case "enrollment-sign":
			err = cutoverJSON(b, &enrollment)
			if err == nil && enrollment.Signature != ([64]byte{}) {
				err = wire.ErrArtifact
			}
			if err == nil {
				_, err = enrollment.ReviewID()
			}
		case "descriptor-sign":
			err = cutoverJSON(b, &unsigned)
			if err == nil && unsigned.Signature != ([64]byte{}) {
				err = wire.ErrArtifact
			}
			if err == nil {
				_, err = unsigned.SigningReviewID()
			}
		case "request-sign":
			err = cutoverJSON(b, &req)
			if err == nil {
				if req.DescriptorID != did || req.Before != (wire.Position{}) || req.Actor != desc.Policy.Owner || req.Nonce == ([32]byte{}) || req.Signature != ([64]byte{}) {
					err = wire.ErrArtifact
				}
			}
		}
		if err != nil {
			return err
		}
	}
	if a.Action == "enrollment-prepare" {
		issuer, err := pruneExternalID("issuer", a.Issuer)
		if err != nil {
			return err
		}
		guard, err := pruneExternalID("guard", a.Guard)
		if err != nil {
			return err
		}
		enrollment = prunefence.ServiceEnrollment{AssignmentID: plan.Request.AssignmentID, ScheduleID: plan.Request.ScheduleID, StorageID: plan.Request.StorageID, StoragePairID: plan.StoragePairID, Service: identity.Service, Issuer: [32]byte(issuer), Guard: [32]byte(guard)}
		if _, err := enrollment.ReviewID(); err != nil {
			return err
		}
	}
	if a.Action == "request-prepare" {
		nonce, err := pruneExternalID("nonce", a.Nonce)
		if err != nil {
			return err
		}
		req = wire.Request{DescriptorID: did, Actor: desc.Policy.Owner, Nonce: [32]byte(nonce)}
	}
	if a.Root != "" {
		if !utf8.ValidString(a.Root) || strings.ContainsRune(a.Root, 0) {
			return wire.ErrArtifact
		}
		p, err := filepath.Abs(a.Root)
		if err != nil {
			return err
		}
		a.Root = filepath.Clean(p)
	}
	if a.Socket != "" {
		if !utf8.ValidString(a.Socket) || strings.ContainsRune(a.Socket, 0) {
			return wire.ErrArtifact
		}
		p, err := filepath.Abs(a.Socket)
		if err != nil {
			return err
		}
		a.Socket = filepath.Clean(p)
	}
	for _, p := range []*string{&a.Output, &a.ChallengeOut, &a.ApprovalOut, &a.PositionOut} {
		if *p != "" {
			v, err := custodyCommandOutput(*p)
			if err != nil {
				return err
			}
			*p = v
		}
	}
	// Call's seed may be absent on historical replay. Its placement is reviewed,
	// but the file is opened only after the complete verified challenge arrives.
	for _, keyPath := range []*string{&a.Key, &a.TransportKey} {
		if *keyPath == "" {
			continue
		}
		v, err := custodyCommandOutput(*keyPath)
		if err != nil {
			return err
		}
		*keyPath = v
	}
	publicPaths := []string{a.Input, a.Identity, a.Plan, a.Descriptor, a.Request, a.Response, a.Position, a.Output, a.Key, a.TransportKey, a.Socket, a.ChallengeOut, a.ApprovalOut, a.PositionOut}
	for i, p := range publicPaths {
		if p == "" {
			continue
		}
		for j, q := range publicPaths {
			if i < j && q != "" && p == q {
				return wire.ErrArtifact
			}
		}
	}
	if a.Root != "" {
		for _, p := range publicPaths {
			if p != "" {
				if err := witnessOutside(a.Root, p); err != nil {
					return err
				}
			}
		}
	}
	if a.Action == "configure" || a.Action == "descriptor-prepare" {
		for _, root := range pruneServiceRuntimeRoots(config.Runtime) {
			for _, p := range publicPaths {
				if p != "" {
					if err := witnessOutside(root, p); err != nil {
						return err
					}
				}
			}
		}
	}
	if a.Action == "relay-serve" || a.Action == "remote-call" {
		if err := validatePruneServiceNetwork(a, desc); err != nil {
			return err
		}
	}
	// Expected confirmation is not part of the plan it confirms.
	reviewFlags := a
	reviewFlags.Mode = "review"
	reviewFlags.Expected = ""
	reviewed := struct {
		Flags      pruneServiceCLIFlags
		Inputs     map[string]string
		Descriptor *wire.Descriptor              `json:",omitempty"`
		Enrollment *prunefence.ServiceEnrollment `json:",omitempty"`
		Identity   *service.Identity             `json:",omitempty"`
		Request    *wire.Request                 `json:",omitempty"`
		Position   *wire.Position                `json:",omitempty"`
	}{Flags: reviewFlags, Inputs: inputs}
	if a.Descriptor != "" {
		reviewed.Descriptor = &desc
	}
	if a.Action == "descriptor-sign" {
		reviewed.Descriptor = &unsigned
	}
	if a.Action == "enrollment-prepare" || a.Action == "enrollment-sign" {
		reviewed.Enrollment = &enrollment
	}
	if a.Identity != "" {
		reviewed.Identity = &identity
	}
	if a.Request != "" || a.Action == "request-prepare" || a.Action == "request-sign" {
		reviewed.Request = &req
	}
	if a.Position != "" {
		reviewed.Position = &position
	}
	public, err := json.Marshal(reviewed)
	if err != nil {
		return err
	}
	review := types.DomainHash(wire.Domain+"cli/review", public)
	if a.Mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("prune_service_review action=%s review_id=%s owners_opened=false keys_loaded=false execution_granted=false\n%s\n", a.Action, review, public))
	}
	want, err := pruneExternalID("expected-review-id", a.Expected)
	if err != nil || want != review {
		return errors.New("Prune service action requires its exact public review")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var result []byte
	var ownerSnapshot service.Snapshot
	switch a.Action {
	case "identity-create":
		if b, e := readRegularArtifact(a.Output, 4096); e == nil {
			var prior service.Identity
			if cutoverJSON(b, &prior) != nil {
				return wire.ErrArtifact
			}
			got, e := service.ReadIdentity(a.Root)
			if e != nil || got != prior {
				return wire.ErrArtifact
			}
			result = b
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else {
			var v service.Identity
			v, err = service.CreateIdentity(a.Root)
			if err == nil {
				result, err = json.Marshal(v)
			}
		}
	case "identity-public":
		var v service.Identity
		v, err = service.ReadIdentity(a.Root)
		if err == nil {
			result, err = json.Marshal(v)
		}
	case "enrollment-prepare":
		result, err = json.Marshal(enrollment)
	case "enrollment-sign":
		result, err = pruneServiceSignRetained(a.Output, func(b []byte) error {
			v, e := prunefence.DecodeServiceEnrollment(b)
			if e != nil {
				return e
			}
			want, e := enrollment.ReviewID()
			got, e2 := v.ReviewID()
			if e != nil || e2 != nil || got != want {
				return wire.ErrArtifact
			}
			return nil
		}, func() ([]byte, error) {
			key, e := witnessKey(a.Key, enrollment.Issuer)
			if e != nil {
				return nil, e
			}
			defer clear(key)
			v, e := enrollment.Sign(key)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		})
	case "descriptor-prepare":
		unsigned, err = service.Prepare(ctx, a.Root, config, uint32(a.ParticipantUID))
		if err == nil {
			result, err = json.Marshal(unsigned)
		}
	case "descriptor-sign":
		result, err = pruneServiceSignRetained(a.Output, func(b []byte) error {
			v, e := wire.DecodeDescriptor(b)
			if e != nil {
				return e
			}
			want, e := unsigned.SigningReviewID()
			got, e2 := v.SigningReviewID()
			if e != nil || e2 != nil || want != got {
				return wire.ErrArtifact
			}
			return nil
		}, func() ([]byte, error) {
			key, e := witnessKey(a.Key, unsigned.Policy.Service.Issuer)
			if e != nil {
				return nil, e
			}
			defer clear(key)
			v, e := unsigned.Sign(key)
			if e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		})
	case "configure":
		err = service.Configure(ctx, a.Root, desc, config)
		if err == nil {
			result = []byte("{\"configured\":true,\"execution_granted\":false}\n")
		}
	case "request-prepare":
		result, err = json.Marshal(req)
	case "request-sign":
		result, err = pruneServiceSignRetained(a.Output, func(b []byte) error {
			v, e := wire.DecodeRequest(b)
			if e != nil {
				return e
			}
			if v.Authorize(desc) != nil || v.DescriptorID != req.DescriptorID || v.Before != req.Before || v.Nonce != req.Nonce || v.Actor != req.Actor {
				return wire.ErrArtifact
			}
			return nil
		}, func() ([]byte, error) {
			key, e := witnessKey(a.Key, desc.Policy.Owner)
			if e != nil {
				return nil, e
			}
			defer clear(key)
			v, e := req.Sign(key)
			if e != nil {
				return nil, e
			}
			if e = v.Authorize(desc); e != nil {
				return nil, e
			}
			return v.CanonicalBytes()
		})
	case "inspect":
		p, e := response.Position()
		err = e
		if err == nil {
			result, err = json.Marshal(struct {
				Position         wire.Position
				Response         wire.Response
				ExecutionGranted bool
			}{p, response, false})
		}
	case "call", "remote-call":
		if b, e := readRegularArtifact(a.Output, wire.MaximumResponseBytes); e == nil {
			r, e := wire.DecodeResponse(b)
			if e != nil || r.Verify(desc, req) != nil {
				return wire.ErrArtifact
			}
			result = b
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		} else {
			var response wire.Response
			approve := func(approveCtx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
				return approvePruneServiceChallenge(approveCtx, desc, req, ch, a.Key, a.ChallengeOut, a.ApprovalOut)
			}
			if a.Action == "remote-call" {
				response, err = callRemotePruneService(ctx, a, desc, req, approve)
			} else {
				response, err = client.Call(ctx, a.Socket, desc, req, approve)
			}
			if err == nil {
				result, err = response.CanonicalBytes()
			}
		}
	case "relay-serve":
		return servePruneServiceRelay(ctx, out, a, desc)
	case "continuation-review":
		var reviewed service.ContinuationReview
		reviewed, err = service.ReviewContinuation(ctx, a.Root, did, position, req)
		if err == nil {
			var id types.Hash
			id, err = reviewed.ID()
			if err == nil {
				result, err = json.Marshal(struct {
					ReviewID         types.Hash
					Review           service.ContinuationReview
					ExecutionGranted bool
				}{id, reviewed, false})
			}
		}
	case "continue":
		var id types.Hash
		id, err = pruneExternalID("continuation-id", a.ContinuationID)
		if err == nil {
			ownerSnapshot, err = service.Continue(ctx, a.Root, did, position, req, id)
		}
		if err == nil {
			result, err = json.Marshal(ownerSnapshot)
		}
	case "serve", "recover", "status":
		var attempt *wire.Request
		if a.Request != "" {
			attempt = &req
		}
		owner, e := service.Open(ctx, a.Root, did, position, attempt)
		if e != nil {
			return e
		}
		defer func() { returnErr = errors.Join(returnErr, owner.Close()) }()
		if a.Action == "serve" {
			return service.Serve(ctx, owner, a.Socket, func(id types.Hash) error {
				return writePruneOutputLine(out, fmt.Sprintf("prune_service_ready socket_id=%s execution_granted=false\n", id))
			})
		}
		if a.Action == "status" {
			ownerSnapshot, err = owner.Snapshot()
			if err == nil {
				result, err = json.Marshal(ownerSnapshot)
			}
			break
		}
		var response wire.Response
		response, err = owner.Recover(ctx, req)
		if err == nil {
			result, err = response.CanonicalBytes()
		}
	case "cleanup-socket":
		id, e := pruneExternalID("socket-id", a.SocketID)
		if e != nil {
			return e
		}
		return service.CleanupSocket(a.Socket, id)
	}
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = publishCustodyCommandArtifact(a.Output, result); err != nil {
		return err
	}
	if a.PositionOut != "" {
		var p wire.Position
		if a.Action == "status" || a.Action == "continue" {
			p = ownerSnapshot.Position
		} else if a.Action == "inspect" {
			p, err = response.Position()
		} else if a.Action != "request-prepare" {
			var r wire.Response
			r, err = wire.DecodeResponse(result)
			if err == nil {
				p, err = r.Position()
			}
		}
		if err != nil {
			return err
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if err = publishCustodyCommandArtifact(a.PositionOut, raw); err != nil {
			return err
		}
	}
	id, err := pruneServiceArtifactID(a.Action, result)
	if err != nil {
		return err
	}
	return writePruneOutputLine(out, fmt.Sprintf("prune_service action=%s artifact_id=%s execution_granted=false\n", a.Action, id))
}

func pruneServiceArtifactID(action string, raw []byte) (types.Hash, error) {
	switch action {
	case "enrollment-sign":
		v, err := prunefence.DecodeServiceEnrollment(raw)
		if err != nil {
			return types.Hash{}, err
		}
		return v.ID()
	case "descriptor-sign":
		v, err := wire.DecodeDescriptor(raw)
		if err != nil {
			return types.Hash{}, err
		}
		return v.ID()
	case "request-sign":
		v, err := wire.DecodeRequest(raw)
		if err != nil {
			return types.Hash{}, err
		}
		return v.ID()
	case "call", "remote-call", "recover":
		v, err := wire.DecodeResponse(raw)
		if err != nil {
			return types.Hash{}, err
		}
		return v.ID()
	default:
		return types.DomainHash(wire.Domain+"cli/artifact", raw), nil
	}
}

func pruneServiceSignRetained(path string, verify func([]byte) error, sign func() ([]byte, error)) ([]byte, error) {
	b, err := readRegularArtifact(path, wire.MaximumDescriptorBytes+4096)
	if err == nil {
		if err = verify(b); err != nil {
			return nil, err
		}
		return b, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return sign()
}
func pruneServiceRuntimeRoots(c store.ScheduledPruneRuntimeConfig) []string {
	roots := []string{c.ExecutorPath, c.ExecutorPinsPath, c.ChainPath, c.ChainPinsPath}
	for _, v := range c.Authorities {
		roots = append(roots, v.AuthorityPath, v.AuthorityPinsPath)
	}
	for _, v := range c.Sources {
		roots = append(roots, v.Directory, v.JournalPath)
	}
	return roots
}

// Retain both public artifacts before exposing the exact consumer signature.
func approvePruneServiceChallenge(ctx context.Context, desc wire.Descriptor, req wire.Request, ch wire.Challenge, keyPath, challengeOut, approvalOut string) (custodyfence.Command, error) {
	if e := ch.Verify(desc, req); e != nil {
		return custodyfence.Command{}, e
	}
	raw, e := ch.CanonicalBytes()
	if e != nil {
		return custodyfence.Command{}, e
	}
	if e = publishCustodyCommandArtifact(challengeOut, raw); e != nil {
		return custodyfence.Command{}, e
	}
	scope, draft, e := ch.Candidate.Draft()
	if e != nil {
		return custodyfence.Command{}, e
	}
	if e = ctx.Err(); e != nil {
		return custodyfence.Command{}, e
	}
	if old, e := readRegularArtifact(approvalOut, custodyfence.CommandBytes); e == nil {
		signed, e := custodyfence.DecodeCommand(old)
		if e != nil {
			return custodyfence.Command{}, e
		}
		check := signed
		check.Signature = [64]byte{}
		if check != draft || signed.Verify(scope) != nil {
			return custodyfence.Command{}, wire.ErrArtifact
		}
		if e = publishCustodyCommandArtifact(approvalOut, old); e != nil {
			return custodyfence.Command{}, e
		}
		return signed, nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return custodyfence.Command{}, e
	}
	key, e := witnessKey(keyPath, desc.Policy.Owner)
	if e != nil {
		return custodyfence.Command{}, e
	}
	defer clear(key)
	signed, e := draft.Sign(key)
	if e != nil {
		return custodyfence.Command{}, e
	}
	raw, e = signed.CanonicalBytes()
	if e != nil {
		return custodyfence.Command{}, e
	}
	if e = publishCustodyCommandArtifact(approvalOut, raw); e != nil {
		return custodyfence.Command{}, e
	}
	return signed, ctx.Err()
}
