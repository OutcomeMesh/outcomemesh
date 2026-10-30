// Package prunenet obtains a Prune claim from already enrolled witness services.
// It never creates witnesses, adopts remote pins or retries an unknown effect.
package prunenet

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sort"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnesswire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/transport"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type Endpoint struct {
	Witness, Transport [32]byte
	Address            string
}

func Validate(scope custodyfence.Scope, local [32]byte, endpoints []Endpoint, timeout time.Duration) error {
	if _, err := scope.CanonicalBytes(); err != nil {
		return err
	}
	if local == ([32]byte{}) || len(endpoints) != len(scope.Witnesses) || timeout < remotewire.MinimumTimeout || timeout > remotewire.MaximumTimeout {
		return prunefence.ErrFence
	}
	roles := append([][32]byte{scope.Owner, scope.Controller, scope.Guard}, scope.Witnesses...)
	seen := map[[32]byte]bool{local: true}
	members := make(map[[32]byte]bool)
	for _, k := range roles {
		if local == k {
			return prunefence.ErrFence
		}
	}
	for _, e := range endpoints {
		if e.Address == "" || len(e.Address) > 4096 || e.Transport == ([32]byte{}) || seen[e.Transport] || members[e.Witness] {
			return prunefence.ErrFence
		}
		member := false
		for _, key := range scope.Witnesses {
			member = member || key == e.Witness
		}
		if !member {
			return prunefence.ErrFence
		}
		for _, key := range roles {
			if e.Transport == key {
				return prunefence.ErrFence
			}
		}
		seen[e.Transport] = true
		members[e.Witness] = true
	}
	return nil
}

// Collect uses the initial scope pin and one bounded attempt per configured
// witness. A lost response leaves the witness's durable vote intact. Only a full
// valid quorum is returned; a minority or timeout never means "not executed".
func Collect(ctx context.Context, host *libp2ptransport.Host, key ed25519.PrivateKey, local [32]byte, endpoints []Endpoint, timeout time.Duration, scope custodyfence.Scope, draft custodyfence.Command) (custodyfence.Certificate, error) {
	var empty custodyfence.Certificate
	if ctx == nil || host == nil || len(key) != 64 || !bytes.Equal(key, ed25519.NewKeyFromSeed(key[:32])) || !bytes.Equal(key[32:], scope.Owner[:]) {
		return empty, prunefence.ErrFence
	}
	if err := Validate(scope, local, endpoints, timeout); err != nil {
		return empty, err
	}
	client, err := transport.PeerIDFromPublicKey(local[:])
	if err != nil || host.ID() != client {
		return empty, prunefence.ErrFence
	}
	sid, _ := scope.ID()
	if draft.Version != 1 || draft.Kind != custodyfence.Claim || draft.ScopeID != sid || draft.ExpectedSequence != 0 || draft.ExpectedHead != sid || draft.Signature != ([64]byte{}) {
		return empty, prunefence.ErrFence
	}
	command, err := draft.Sign(key)
	if err != nil {
		return empty, err
	}
	cid, _ := command.ID()
	q := custodyfence.Certificate{Version: 1, Command: command}
	var failures []error
	for _, e := range endpoints {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		peer, err := transport.PeerIDFromPublicKey(e.Transport[:])
		if err != nil {
			return empty, err
		}
		request := witnesswire.Request{Version: 1, Kind: witnesswire.Vote, ScopeID: sid, Nonce: types.DomainHash("OMESH/prune-fence/network-request/v0", cid[:], e.Witness[:]), Expected: custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: sid}}, Command: command}
		run, cancel := context.WithTimeout(ctx, timeout)
		stream, _, err := host.OpenCustodyWitnessStream(run, e.Address, peer)
		if err == nil {
			var response witnesswire.Response
			response, err = witnesswire.Exchange(run, stream, scope, e.Witness, request, timeout)
			if err == nil {
				q.Votes = append(q.Votes, response.Vote)
			}
		}
		cancel()
		if err != nil {
			failures = append(failures, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	sort.Slice(q.Votes, func(i, j int) bool { return bytes.Compare(q.Votes[i].Witness[:], q.Votes[j].Witness[:]) < 0 })
	if err := q.Verify(scope); err != nil {
		return empty, errors.Join(append([]error{err}, failures...)...)
	}
	return q, nil
}
