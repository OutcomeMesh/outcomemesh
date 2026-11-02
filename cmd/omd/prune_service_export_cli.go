package main

import (
	"context"
	"io"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
)

// Export uses only public role identities and the read-only activation base.
// The private owner validates all original stores when preparing its descriptor.
func exportPruneServiceRuntime(ctx context.Context, out io.Writer, runtime store.ScheduledPruneRuntimeConfig, inventory store.ScheduledPruneInventory, output, identityPath, guardURL, networkPath string, timeout time.Duration, dataPath, sourcesPath string) error {
	if inventory.FencePolicy == nil || inventory.FencePolicy.Service == nil {
		return service.ErrOwner
	}
	identityPath, err := custodyCommandFile(identityPath)
	if err != nil {
		return err
	}
	raw, err := readRegularArtifact(identityPath, 4096)
	if err != nil {
		return err
	}
	var identity service.Identity
	if err = cutoverJSON(raw, &identity); err != nil {
		return err
	}
	if identity.RootID.IsZero() || identity.Service != inventory.FencePolicy.Service.Service || identity.Transport == ([32]byte{}) || identity.Transport == identity.Service {
		return service.ErrOwner
	}
	networkPath, err = custodyCommandFile(networkPath)
	if err != nil {
		return err
	}
	raw, err = readRegularArtifact(networkPath, 64<<10)
	if err != nil {
		return err
	}
	var network pruneFenceNetworkJSON
	if err = cutoverJSON(raw, &network); err != nil {
		return err
	}
	transport, err := pruneExternalID("client_transport", network.ClientTransport)
	if err != nil || [32]byte(transport) != identity.Transport || len(network.Witnesses) > custodyfence.MaximumWitnesses {
		return service.ErrOwner
	}
	var endpoints []prunenet.Endpoint
	for _, endpoint := range network.Witnesses {
		w, err := pruneExternalID("witness", endpoint.Witness)
		if err != nil {
			return err
		}
		p, err := pruneExternalID("transport", endpoint.Transport)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, prunenet.Endpoint{Witness: [32]byte(w), Transport: [32]byte(p), Address: endpoint.Address})
	}
	rid, err := inventory.Request.ID()
	if err != nil {
		return err
	}
	scope, err := inventory.FencePolicy.Scope(inventory.Request.AssignmentID, rid)
	if err != nil {
		return err
	}
	if err = prunenet.Validate(scope, identity.Transport, endpoints, timeout); err != nil {
		return err
	}
	for _, path := range []*string{&runtime.ExecutorPath, &runtime.ExecutorPinsPath, &runtime.ChainPath, &runtime.ChainPinsPath} {
		*path, err = canonicalPruneLineageDirectory(*path)
		if err != nil {
			return err
		}
	}
	for i := range runtime.Authorities {
		for _, path := range []*string{&runtime.Authorities[i].AuthorityPath, &runtime.Authorities[i].AuthorityPinsPath} {
			*path, err = canonicalPruneLineageDirectory(*path)
			if err != nil {
				return err
			}
		}
	}
	for i := range runtime.Sources {
		for _, path := range []*string{&runtime.Sources[i].Directory, &runtime.Sources[i].JournalPath} {
			*path, err = canonicalPruneLineageDirectory(*path)
			if err != nil {
				return err
			}
		}
	}
	runtime.InventoryPath, err = custodyCommandFile(runtime.InventoryPath)
	if err != nil {
		return err
	}
	output, err = custodyCommandOutput(output)
	if err != nil {
		return err
	}
	roots := append(pruneServiceRuntimeRoots(runtime), dataPath)
	if err = scheduledOperatorOutput(output, []string{runtime.InventoryPath, identityPath, networkPath, sourcesPath}, roots); err != nil {
		return err
	}
	config := service.Config{Runtime: runtime, GuardURL: guardURL, Witnesses: endpoints, WitnessTimeout: timeout}
	raw, err = service.EncodeConfig(config)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = publishCustodyCommandArtifact(output, raw); err != nil {
		return err
	}
	return scheduledOperatorReport(ctx, out, struct {
		ArtifactID          string `json:"artifact_id"`
		OwnersOpened        bool   `json:"owners_opened"`
		KeysLoaded          bool   `json:"keys_loaded"`
		ExecutionAuthorized bool   `json:"execution_authorized"`
	}{types.DomainHash("OMESH/prune-service/cli/runtime-export/v0", raw).String(), false, false, false})
}
