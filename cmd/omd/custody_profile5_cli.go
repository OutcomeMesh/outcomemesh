//go:build linux || darwin

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
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

const custodyProfile5Command = "work-archive-custody-profile5"

type profile5CommandInput struct {
	Kind                                                   uint8
	Admission, Data, Deployment, Pair, Certificate, Parent []byte
	Now                                                    uint64
}
type profile5RequestInput struct {
	DescriptorID types.Hash
	Before       wire.Position
	Nonce        types.Hash
	Payload      []byte
}

func runCustodyProfile5CLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyProfile5(ctx, args, os.Stdout)
}
func runCustodyProfile5(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return gateway.ErrExecution
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	descriptorPath := f.String("descriptor", "", "pinned complete gateway descriptor; extract only")
	descriptorID := f.String("descriptor-id", "", "independent gateway descriptor pin; extract only")
	action := f.String("action", "", "deployment, sign-deployment, command, sign-request, configure, extract, retained-acceptance, sign-retained")
	guardKey := f.String("guard-key", "", "independently retained external guard public key; deployment only")
	mode := f.String("mode", "review", "review or run")
	input := f.String("input", "", "complete public preparation input")
	root := f.String("root", "", "original isolated service owner; configure only")
	role := f.String("role", "", "issuer, authority or control; offline signing only")
	keyPath := f.String("key", "", "offline seed; signing only")
	output := f.String("out", "", "fresh public artifact")
	expected := f.String("expected-review-id", "", "exact public review")
	if e := parsePruneFlags(f, args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 || (*mode != "review" && *mode != "run") {
		return gateway.ErrExecution
	}
	valid := map[string]bool{"deployment": true, "sign-deployment": true, "command": true, "sign-request": true, "configure": true, "extract": true, "retained-acceptance": true, "sign-retained": true}
	if !valid[*action] {
		return gateway.ErrExecution
	}
	if (*root != "") != (*action == "configure") || (*keyPath != "") != (*action == "sign-deployment" || *action == "sign-request" || *action == "sign-retained") || (*role != "") != (*action == "sign-deployment" || *action == "sign-retained") {
		return gateway.ErrExecution
	}
	if *guardKey != "" && *action != "deployment" {
		return gateway.ErrExecution
	}
	var e error
	*input, e = custodyCommandFile(*input)
	if e != nil {
		return e
	}
	raw, e := readRegularArtifact(*input, wire.MaximumResponseBytes)
	if e != nil {
		return e
	}
	*output, e = custodyCommandOutput(*output)
	if e != nil {
		return e
	}
	if *input == *output || (*descriptorPath != "" && *descriptorPath == *output) {
		return gateway.ErrExecution
	}
	if *keyPath != "" {
		*keyPath, e = custodyCommandFile(*keyPath)
		if e != nil {
			return e
		}
		if *keyPath == *output {
			return gateway.ErrExecution
		}
	}
	var descriptor wire.Descriptor
	var descriptorHash types.Hash
	if (*descriptorPath != "") != (*action == "extract") || (*descriptorID != "") != (*action == "extract") {
		return gateway.ErrExecution
	}
	if *descriptorPath != "" {
		*descriptorPath, e = custodyCommandFile(*descriptorPath)
		if e != nil {
			return e
		}
		b, e := readRegularArtifact(*descriptorPath, wire.MaximumDescriptorBytes)
		if e != nil {
			return e
		}
		descriptor, e = wire.DecodeDescriptor(b)
		if e != nil {
			return e
		}
		descriptorHash = cutoverArtifactID(b)
		pin, e := witnessID("descriptor-id", *descriptorID)
		id, _ := descriptor.ID()
		if e != nil || pin != id {
			return gateway.ErrExecution
		}
	}
	var artifact []byte
	var dep wire.Deployment
	var request profile5RequestInput
	var setup gateway.ExecutionSetup
	var summary any
	var keyFiles []string
	var retained profile5RetainedInput
	var retainedContext v2.Context
	var retainedBundle v2.Bundle
	switch *action {
	case "retained-acceptance", "sign-retained":
		if e = cutoverJSON(raw, &retained); e != nil {
			return e
		}
		retainedContext, e = v2.DecodeContext(retained.Context)
		if e != nil {
			return e
		}
		retainedBundle, e = v2.DecodeBundle(retained.Bundle)
		if e != nil || retainedBundle.Verify(retainedContext) != nil {
			return gateway.ErrExecution
		}
		cid, _ := retainedContext.ID()
		bid, _ := retainedBundle.ID()
		if retained.Consent.ContextID != cid || retained.Consent.BundleID != bid || !v2.ProtectedContext(retainedContext) || retainedContext.Plan.Deployment.Guard == ([32]byte{}) {
			return gateway.ErrExecution
		}
		if *action == "sign-retained" && *role != "authority" && *role != "consumer" {
			return gateway.ErrExecution
		}
		if *action == "retained-acceptance" && retained.Consent.Verify(retainedContext, retainedBundle, retained.Consent.NotBefore) != nil {
			return gateway.ErrExecution
		}
		artifact, e = v2.EncodeRetainedAcceptance(retainedBundle, retained.Consent)
		if e != nil {
			return e
		}
		summary = retained.Consent
	case "deployment":
		var p gateway.DeploymentPreparation
		if e = cutoverJSON(raw, &p); e != nil {
			return e
		}
		dep, e = gateway.PrepareDeployment(p)
		if e != nil {
			return e
		}
		if *guardKey != "" {
			k, err := witnessID("guard-key", *guardKey)
			if err != nil {
				return err
			}
			dep.Guard = [32]byte(k)
		}
		artifact, e = dep.CanonicalBytes()
		summary = dep
	case "sign-deployment":
		dep, e = wire.DecodeDeployment(raw)
		if e != nil {
			return e
		}
		if *role != "issuer" && *role != "authority" && *role != "control" {
			return gateway.ErrExecution
		}
		summary = dep
	case "command":
		var p profile5CommandInput
		if e = cutoverJSON(raw, &p); e != nil {
			return e
		}
		cmd := v2.ProtectedCommand{Kind: p.Kind, Now: p.Now, Data: p.Data}
		if p.Kind == v2.ProtectedEndorse {
			if len(p.Admission) != 0 || len(p.Data) != 0 || len(p.Certificate) != 0 || len(p.Parent) != 0 {
				return gateway.ErrExecution
			}
			d, e := wire.DecodeDeployment(p.Deployment)
			if e != nil {
				return e
			}
			pair, e := cut.DecodeSourceHandoffPair(p.Pair)
			if e != nil {
				return e
			}
			cmd.Data, e = gateway.EncodeEndorsement(d, pair)
			if e != nil {
				return e
			}
		} else {
			if len(p.Deployment) != 0 || len(p.Pair) != 0 {
				return gateway.ErrExecution
			}
			cmd.Admission, e = v2.DecodeAdmissionBinding(p.Admission)
			if e != nil {
				return e
			}
			if p.Kind == v2.ProtectedServe {
				if len(p.Data) != 0 {
					return gateway.ErrExecution
				}
				cert, e := v2.DecodeServeCertificate(p.Certificate)
				if e != nil {
					return e
				}
				var parent *v2.ServeReceipt
				if len(p.Parent) > 0 {
					r, e := v2.DecodeServeReceipt(p.Parent)
					if e != nil {
						return e
					}
					parent = &r
				}
				cmd.Data, e = gateway.EncodeExecutionServe(cert, parent)
				if e != nil {
					return e
				}
			} else if len(p.Certificate) != 0 || len(p.Parent) != 0 {
				return gateway.ErrExecution
			}
		}
		artifact, e = cmd.CanonicalBytes()
		if e != nil {
			return e
		}
		summary = profile5PublicCommand(cmd)
	case "sign-request":
		if e = cutoverJSON(raw, &request); e != nil {
			return e
		}
		cmd, e := v2.DecodeProtectedCommand(request.Payload)
		if e != nil {
			return e
		}
		if request.DescriptorID.IsZero() || !request.Before.Valid() || request.Nonce.IsZero() {
			return gateway.ErrExecution
		}
		summary = struct {
			Request   profile5RequestInput
			Operation any
		}{profile5RequestInput{DescriptorID: request.DescriptorID, Before: request.Before, Nonce: request.Nonce}, profile5PublicCommand(cmd)}
	case "configure":
		if e = cutoverJSON(raw, &setup); e != nil {
			return e
		}
		*root, e = canonicalPruneLineageDirectory(*root)
		if e != nil {
			return e
		}
		dep, e = wire.DecodeDeployment(setup.Deployment)
		if e != nil || dep.Verify() != nil {
			return gateway.ErrExecution
		}
		if _, e = cut.DecodeSourceHandoffPair(setup.Pair); e != nil {
			return e
		}
		for _, p := range []*string{&setup.ReplicaKeyPath, &setup.ControlKeyPath, &setup.AuthorityKeyPath} {
			if *p != "" {
				*p, e = custodyCommandFile(*p)
				if e != nil {
					return e
				}
				keyFiles = append(keyFiles, *p)
			}
		}
		if len(keyFiles) == 0 {
			return gateway.ErrExecution
		}
		summary = setup
	case "extract":
		response, e := wire.DecodeResponse(raw)
		if e != nil {
			return e
		}
		if response.Request.Kind != wire.Runtime || response.Verify(descriptor, response.Request) != nil {
			return gateway.ErrExecution
		}

		artifact = response.Data
		summary = struct {
			Request           wire.Request
			SourceID          types.Hash
			Bytes             int
			SignatureVerified bool
		}{response.Request, response.SourceID, len(artifact), true}
	}
	if e != nil {
		return e
	}
	if *root != "" {
		for _, p := range append([]string{*input, *output}, keyFiles...) {
			if e = witnessOutside(*root, p); e != nil {
				return e
			}
		}
	}
	for _, p := range keyFiles {
		if p == *output {
			return gateway.ErrExecution
		}
	}
	public, e := json.Marshal(struct {
		Action, Root, Role, Key, Input, Output string
		InputID                                types.Hash
		DescriptorPath                         string
		DescriptorArtifact                     types.Hash
		DescriptorID                           string
		Summary                                any
	}{*action, *root, *role, *keyPath, *input, *output, cutoverArtifactID(raw), *descriptorPath, descriptorHash, *descriptorID, summary})
	if e != nil {
		return e
	}
	review := types.DomainHash(wire.Domain+"profile5/cli/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_profile5_review action=%s review_id=%s keys_loaded=false owners_opened=false execution_granted=false\n%s\n", *action, review, public))
	}
	want, e := witnessID("expected-review-id", *expected)
	if e != nil || want != review {
		return errors.New("profile-5 action requires its exact public review")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if _, err := os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("retain existing output and use a fresh path")
	}
	switch *action {
	case "sign-retained":
		key, err := profile5Seed(*keyPath, false)
		if err != nil {
			return err
		}
		defer clear(key)
		retained.Consent, e = retained.Consent.Sign(retainedContext, retainedBundle, *role, key)
		if e != nil {
			return e
		}
		artifact, e = json.Marshal(retained)
	case "sign-deployment":
		key, e := profile5Seed(*keyPath, false)
		if e != nil {
			return e
		}
		defer clear(key)
		dep, e = dep.Sign(*role, key)
		if e != nil {
			return e
		}
		artifact, e = dep.CanonicalBytes()
	case "sign-request":
		key, e := profile5Seed(*keyPath, false)
		if e != nil {
			return e
		}
		defer clear(key)
		q, e := (wire.Request{DescriptorID: request.DescriptorID, Before: request.Before, Nonce: request.Nonce, Kind: wire.Runtime, ChunkID: wire.RuntimePayloadID(request.Payload)}).Sign(key)
		if e != nil {
			return e
		}
		artifact, e = wire.EncodeRuntimeRequest(q, request.Payload)
	case "configure":
		var keys gateway.ExecutionKeys
		for _, p := range []struct {
			path string
			dst  *ed25519.PrivateKey
		}{{setup.ReplicaKeyPath, &keys.Replica}, {setup.ControlKeyPath, &keys.Control}, {setup.AuthorityKeyPath, &keys.Authority}} {
			if p.path != "" {
				*p.dst, e = profile5Seed(p.path, true)
				if e != nil {
					clear(keys.Replica)
					clear(keys.Control)
					clear(keys.Authority)
					return e
				}
			}
		}
		defer clear(keys.Replica)
		defer clear(keys.Control)
		defer clear(keys.Authority)
		if e = gateway.ConfigureExecution(ctx, *root, setup.ExecutionConfig, keys); e != nil {
			return e
		}
		artifact = []byte("{\"profile5_configured\":true,\"execution_granted\":false}\n")
	}
	if e != nil {
		return e
	}
	if e = publishCustodyCommandArtifact(*output, artifact); e != nil {
		return e
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_profile5 action=%s artifact_id=%s execution_granted=false\n", *action, cutoverArtifactID(artifact)))
}
func profile5Seed(path string, private bool) (ed25519.PrivateKey, error) {
	if private {
		if _, e := gateway.PlacementID(path, false); e != nil {
			return nil, e
		}
	}
	raw, e := readRegularArtifact(path, 256)
	if e != nil {
		return nil, e
	}
	seed, e := hex.DecodeString(string(bytes.TrimSpace(raw)))
	clear(raw)
	if e != nil || len(seed) != 32 {
		clear(seed)
		return nil, gateway.ErrExecution
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return key, nil
}

// Signing retains the complete public input so the other role can verify the
// same bundle. retained-acceptance extracts canonical command Data from it.
type profile5RetainedInput struct {
	Context, Bundle []byte
	Consent         v2.RetainedAcceptance
}
