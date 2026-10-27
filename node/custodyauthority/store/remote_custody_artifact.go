package store

import (
	"context"
	"path/filepath"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
)

// RemoteCustodyDrainArtifact normalizes the channel nonce to the immutable seal
// ID. Its contents are historical metadata, never proof of a fresh exchange.
func RemoteCustodyDrainArtifact(scope RemoteCustodyScope, response remotewire.Response) (remotewire.Response, types.Hash, error) {
	if err := ValidateRemoteCustodyDrain(scope, response.Seal, response.Drain); err != nil {
		return remotewire.Response{}, types.Hash{}, err
	}
	sealID, err := response.Seal.ID()
	if err != nil {
		return remotewire.Response{}, types.Hash{}, err
	}
	response = remotewire.Response{Version: remotewire.Version0, Status: remotewire.StatusDrained, Nonce: sealID, PlanID: scope.Worker.PlanID, BeginID: scope.Worker.BeginID, Seal: response.Seal, Drain: response.Drain}
	b, err := response.CanonicalBytes()
	if err != nil {
		return remotewire.Response{}, types.Hash{}, err
	}
	return response, types.DomainHash("OMESH/custody-authority/remote-drain-artifact/id/v0", b), nil
}

func PublishRemoteCustodyDrain(ctx context.Context, path string, scope RemoteCustodyScope, response remotewire.Response) (types.Hash, error) {
	r, id, err := RemoteCustodyDrainArtifact(scope, response)
	if err != nil {
		return types.Hash{}, err
	}
	b, _ := r.CanonicalBytes()
	if err := publishCustodyArtifactBytes(ctx, path, b); err != nil {
		return types.Hash{}, err
	}
	return id, nil
}

func LoadRemoteCustodyDrain(path string, pin types.Hash, scope RemoteCustodyScope) (remotewire.Response, error) {
	if pin.IsZero() {
		return remotewire.Response{}, ErrRemoteCustody
	}
	b, err := readRegular(path, remotewire.MaxFrameBytes)
	if err != nil {
		return remotewire.Response{}, err
	}
	r, err := remotewire.DecodeResponse(b)
	if err != nil {
		return remotewire.Response{}, err
	}
	normal, id, err := RemoteCustodyDrainArtifact(scope, r)
	if err != nil || id != pin || normal.Nonce != r.Nonce {
		return remotewire.Response{}, ErrRemoteCustody
	}
	return normal, nil
}

func LoadRemoteCustodyTerminal(path string, pin types.Hash) (RemoteCustodyTerminal, error) {
	if pin.IsZero() {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	b, err := readRegular(path, MaximumRemoteCustodyTerminalBytes)
	if err != nil {
		return RemoteCustodyTerminal{}, err
	}
	t, err := DecodeRemoteCustodyTerminal(b)
	if err != nil {
		return RemoteCustodyTerminal{}, err
	}
	id, err := t.ID()
	if err != nil || id != pin {
		return RemoteCustodyTerminal{}, ErrRemoteCustody
	}
	return t, nil
}

func (r *RemoteCustodyAuditRuntime) remoteOutputPath(path string) error {
	for _, root := range []string{r.life.owner.authority.path, r.life.owner.journal.path, r.journal.Directory(), r.session.artifactsPath, filepath.Dir(r.session.intentPath)} {
		if _, _, err := coordinatorPaths(filepath.Dir(path), root); err != nil {
			return err
		}
	}
	return nil
}
