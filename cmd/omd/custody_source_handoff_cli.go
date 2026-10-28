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
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	cut "github.com/outcomemesh/outcomemesh/node/custodycutover"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

const custodySourceHandoffCommand = "work-archive-custody-source-handoff"

func runCustodySourceHandoffCLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodySourceHandoff(ctx, args, os.Stdout)
}
func runCustodySourceHandoff(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return cut.ErrPreparation
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "", "transfer or inspect; both default to public review")
	mode := f.String("mode", "review", "review or run")
	genesis := f.String("genesis", "", "complete imported admission genesis")
	gid := f.String("genesis-id", "", "independent admission genesis pin")
	did := f.String("genesis-descriptor-id", "", "independent complete genesis descriptor pin")
	enrollment := f.String("enrollment", "", "complete selected imported enrollment")
	eid := f.String("enrollment-id", "", "independent enrollment object ID")
	source := f.String("source", "", "original SourceLocation JSON")
	placement := f.String("placement-id", "", "independent original source location pin")
	output := f.String("out", "", "fresh public handoff record outside owners")
	expected := f.String("expected-review-id", "", "exact public action review")
	if e := parsePruneFlags(f, args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 || (*action != "transfer" && *action != "inspect") || (*mode != "review" && *mode != "run") {
		return cut.ErrPreparation
	}
	var pins cut.SourceHandoffPins
	for _, p := range []struct {
		name, value string
		dst         *types.Hash
	}{{"genesis-id", *gid, &pins.GenesisID}, {"genesis-descriptor-id", *did, &pins.GenesisDescriptorID}, {"enrollment-id", *eid, &pins.EnrollmentID}, {"placement-id", *placement, &pins.PlacementID}} {
		id, e := witnessID(p.name, p.value)
		if e != nil {
			return e
		}
		*p.dst = id
	}
	paths := []string{}
	inputs := map[string]string{}
	load := func(path string, limit int) ([]byte, error) {
		p, e := custodyCommandFile(path)
		if e != nil {
			return nil, e
		}
		raw, e := readRegularArtifact(p, limit)
		if e != nil {
			return nil, e
		}
		paths = append(paths, p)
		inputs[p] = cutoverArtifactID(raw).String()
		return raw, nil
	}
	raw, e := load(*genesis, v2.MaximumAdmissionGenesisBytes)
	if e != nil {
		return e
	}
	g, e := v2.DecodeAdmissionGenesis(raw)
	if e != nil {
		return e
	}
	raw, e = load(*enrollment, v2.MaximumEnrollmentBindingBytes)
	if e != nil {
		return e
	}
	b, e := v2.DecodeEnrollmentBinding(raw)
	if e != nil {
		return e
	}
	raw, e = load(*source, 1<<20)
	if e != nil {
		return e
	}
	var l cut.SourceLocation
	if e := cutoverJSON(raw, &l); e != nil {
		return e
	}
	actual, e := l.LocationID()
	if e != nil || actual != pins.PlacementID {
		return errors.Join(cut.ErrPreparation, e)
	}
	h, e := cut.ReviewSourceHandoff(g, b, pins, l.Role)
	if e != nil {
		return e
	}
	*output, e = custodyCommandOutput(*output)
	if e != nil {
		return e
	}
	if e := rejectPruneLineageOutputAlias(*output, paths); e != nil {
		return e
	}
	owners := append([]string{l.Journal, l.Authority, l.AuthorityPins}, l.Workers...)
	for _, owner := range owners {
		if owner != "" {
			for _, path := range append(append([]string{}, paths...), *output) {
				if e := witnessOutside(owner, path); e != nil {
					return e
				}
			}
		}
	}
	public, e := json.Marshal(struct {
		Action           string
		Pins             cut.SourceHandoffPins
		Source           cut.SourceLocation
		Inputs           map[string]string
		Output           string
		Handoff          workarchive.CustodySourceHandoff
		ExecutionGranted bool
	}{*action, pins, l, inputs, *output, h, false})
	if e != nil {
		return e
	}
	rid := types.DomainHash("OMESH/custody-source-handoff/v1/cli/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_source_handoff_review action=%s review_id=%s keys_loaded=false owners_opened=false execution_granted=false\n%s\n", *action, rid, public))
	}
	wanted, e := witnessID("expected-review-id", *expected)
	if e != nil || wanted != rid {
		return errors.New("source handoff requires its exact public action review")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if _, e := os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
		return errors.Join(errors.New("retain existing output and retry to a fresh path"), e)
	}
	changed := false
	if *action == "transfer" {
		h, changed, e = cut.TransferSourceHandoff(ctx, g, b, pins, l)
	} else {
		h, e = cut.InspectSourceHandoff(ctx, g, b, pins, l)
	}
	if e != nil {
		return e
	}
	raw, e = h.CanonicalBytes()
	if e != nil {
		return e
	}
	if e := publishCustodyCommandArtifact(*output, raw); e != nil {
		return e
	}
	id, _ := h.ID()
	return writePruneOutputLine(out, fmt.Sprintf("custody_source_handoff action=%s handoff_id=%s changed=%t source_sealed=true execution_granted=false\n", *action, id, changed))
}
