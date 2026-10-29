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
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	gateway "github.com/outcomemesh/outcomemesh/node/custodygateway"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

const custodyGatewayReplaceCommand = "work-archive-custody-gateway-replace"

func runCustodyGatewayReplaceCLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyGatewayReplace(ctx, args, os.Stdout)
}
func runCustodyGatewayReplace(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return wire.ErrArtifact
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review or run")
	root := f.String("root", "", "original private service root")
	descriptor := f.String("descriptor", "", "original issuer-signed guarded descriptor")
	descriptorID := f.String("descriptor-id", "", "independently retained descriptor ID")
	position := f.String("position", "", "independently retained exact current service Position")
	attempt := f.String("request", "", "optional exact retained unresolved service request")
	replacement := f.String("replacement", "", "signed guard replacement receipt")
	key := f.String("key", "", "private successor seed, 32 raw bytes; unused during review")
	output := f.String("out", "", "fresh public activation report")
	expected := f.String("expected-review-id", "", "exact public review")
	if err := parsePruneFlags(f, args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || *mode != "review" && *mode != "run" || *root == "" {
		return wire.ErrArtifact
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return err
	}
	*root = filepath.Join(parent, filepath.Base(abs))
	inputs := map[string]string{}
	var paths []string
	load := func(path *string, limit int) ([]byte, error) {
		var err error
		*path, err = custodyCommandFile(*path)
		if err != nil {
			return nil, err
		}
		if err = witnessOutside(*root, *path); err != nil {
			return nil, err
		}
		b, err := readRegularArtifact(*path, limit)
		if err == nil {
			inputs[*path] = cutoverArtifactID(b).String()
			paths = append(paths, *path)
		}
		return b, err
	}
	b, err := load(descriptor, wire.MaximumDescriptorBytes)
	if err != nil {
		return err
	}
	d, err := wire.DecodeDescriptor(b)
	if err != nil {
		return err
	}
	did, err := witnessID("descriptor-id", *descriptorID)
	if err != nil {
		return err
	}
	actual, _ := d.ID()
	if did != actual || d.Guard == ([32]byte{}) {
		return wire.ErrArtifact
	}
	b, err = load(position, 1024)
	if err != nil {
		return err
	}
	var p wire.Position
	if err = cutoverJSON(b, &p); err != nil || !p.Valid() {
		return wire.ErrArtifact
	}
	b, err = load(replacement, guard.ReplacementReceiptBytes)
	if err != nil {
		return err
	}
	r, err := guard.DecodeReplacementReceipt(b)
	if err != nil {
		return err
	}
	principal, err := r.Principal(d.Guard, r.Request.Successor)
	if err != nil || principal != d.Gateway {
		return wire.ErrArtifact
	}
	var q *wire.Request
	if *attempt != "" {
		b, err = load(attempt, wire.MaximumRequestBytes)
		if err != nil {
			return err
		}
		v, e := wire.DecodeRequest(b)
		if e != nil || v.Authorize(d) != nil || v.Before != p {
			return wire.ErrArtifact
		}
		q = &v
	}
	*key, err = custodyCommandOutput(*key)
	if err != nil {
		return err
	}
	*output, err = custodyCommandOutput(*output)
	if err != nil {
		return err
	}
	for _, path := range []string{*key, *output} {
		if err = witnessOutside(*root, path); err != nil {
			return err
		}
	}
	if err = rejectPruneLineageOutputAlias(*output, append(paths, *key)); err != nil {
		return err
	}
	public, err := json.Marshal(struct {
		Root, Key, Output string
		Inputs            map[string]string
		DescriptorID      types.Hash
		Position          wire.Position
		Attempt           *wire.Request
		Replacement       guard.ReplacementReceipt
	}{*root, *key, *output, inputs, did, p, q, r})
	if err != nil {
		return err
	}
	review := types.DomainHash(wire.Domain+"cli/replace/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_gateway_replacement_review review_id=%s roots_opened=false keys_loaded=false network_called=false\n%s\n", review, public))
	}
	want, err := witnessID("expected-review-id", *expected)
	if err != nil || want != review {
		return errors.New("service replacement requires its exact public review")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = os.Lstat(*output); !errors.Is(err, os.ErrNotExist) {
		return wire.ErrArtifact
	}
	private, err := witnessKey(*key, r.Request.Successor)
	if err != nil {
		return err
	}
	defer clear(private)
	if err = gateway.ActivateReplacement(ctx, *root, did, p, q, r, private); err != nil {
		return err
	}
	b, err = json.Marshal(struct {
		DescriptorID, SourceID                    types.Hash
		Position                                  wire.Position
		Subject, Successor                        [32]byte
		ObligationsPreserved, UnknownOutcomesHeld bool
	}{did, d.SourceID, p, r.Request.Subject, r.Request.Successor, true, true})
	if err != nil {
		return err
	}
	if err = publishCustodyCommandArtifact(*output, b); err != nil {
		return err
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_gateway_replacement descriptor_id=%s subject=%x successor=%x position=%d\n", did, r.Request.Subject, r.Request.Successor, p.Sequence))
}
