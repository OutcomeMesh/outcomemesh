package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func reviewPruneServiceSuccession(a *pruneServiceCLIFlags, d wire.Descriptor, load func(*string, int) ([]byte, error)) (*prunefence.ServiceSuccession, error) {
	var s prunefence.ServiceSuccession
	if a.Action == "successor-authorize" {
		raw, err := load(&a.Replacement, guardwire.ReplacementReceiptBytes)
		if err != nil {
			return nil, err
		}
		id, err := pruneExternalID("replacement-id", a.ReplacementID)
		if err != nil || id != cutoverArtifactID(raw) {
			return nil, wire.ErrArtifact
		}
		s.Replacement, err = guardwire.DecodeReplacementReceipt(raw)
		if err != nil {
			return nil, err
		}
		if _, err = s.ReviewID(d.Policy, d.Binding); err != nil {
			return nil, err
		}
	} else {
		raw, err := load(&a.Succession, prunefence.SuccessionBytes)
		if err != nil {
			return nil, err
		}
		id, err := pruneExternalID("succession-id", a.SuccessionID)
		if err != nil {
			return nil, err
		}
		s, err = prunefence.DecodeServiceSuccession(raw, d.Policy, d.Binding)
		if err != nil {
			return nil, err
		}
		got, err := s.ID(d.Policy, d.Binding)
		if err != nil || got != id {
			return nil, wire.ErrArtifact
		}
	}
	if s.Replacement.Request.Successor == d.Transport || s.Replacement.Request.Authority == d.Transport {
		return nil, wire.ErrAccess
	}
	return &s, nil
}

func authorizePruneServiceSuccession(a pruneServiceCLIFlags, d wire.Descriptor, draft prunefence.ServiceSuccession) ([]byte, error) {
	return pruneServiceSignRetained(a.Output, func(raw []byte) error {
		signed, err := prunefence.DecodeServiceSuccession(raw, d.Policy, d.Binding)
		if err != nil {
			return err
		}
		if signed.Replacement != draft.Replacement {
			return wire.ErrArtifact
		}
		return nil
	}, func() ([]byte, error) {
		key, err := witnessKey(a.Key, d.Policy.Service.Issuer)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		signed, err := draft.Sign(d.Policy, d.Binding, key)
		if err != nil {
			return nil, err
		}
		return signed.CanonicalBytes(d.Policy, d.Binding)
	})
}

func activatePruneServiceSuccession(ctx context.Context, a pruneServiceCLIFlags, did types.Hash, position wire.Position, s prunefence.ServiceSuccession) ([]byte, error) {
	// Check the report destination before installing a key. An existing report
	// does not establish installation; the owner must confirm the original state.
	report, err := json.Marshal(struct {
		DescriptorID, SuccessionID string
		Original, Successor        [32]byte
		Position                   wire.Position
		ExecutionGranted           bool
	}{did.String(), a.SuccessionID, s.Replacement.Request.Subject, s.Replacement.Request.Successor, position, false})
	if err != nil {
		return nil, err
	}
	prior, err := readRegularArtifact(a.Output, len(report))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil && !bytes.Equal(prior, report) {
		return nil, wire.ErrArtifact
	}
	key, err := witnessKey(a.Key, s.Replacement.Request.Successor)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if err = service.ActivateSuccessor(ctx, a.Root, did, position, s, key, a.Output, a.Descriptor, a.Position, a.Succession, a.Key); err != nil {
		return nil, err
	}
	return report, nil
}
