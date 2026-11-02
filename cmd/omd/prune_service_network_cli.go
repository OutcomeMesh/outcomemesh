package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	relay "github.com/outcomemesh/outcomemesh/node/pruneservice/servicerelay"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func pruneServiceTransportKeys(a pruneServiceCLIFlags, d wire.Descriptor) (local, remote [32]byte, peers [][32]byte, err error) {
	h, e := pruneExternalID("transport-public-key", a.TransportPublic)
	if e != nil {
		return local, remote, nil, e
	}
	local = [32]byte(h)
	if e = relay.ValidateTransport(d, local); e != nil {
		return local, remote, nil, e
	}
	if a.Action == "remote-call" {
		h, e = pruneExternalID("relay-public-key", a.RelayPublic)
		if e != nil {
			return local, remote, nil, e
		}
		remote = [32]byte(h)
		if remote == local || relay.ValidateTransport(d, remote) != nil {
			return local, remote, nil, wire.ErrAccess
		}
	} else {
		seen := map[[32]byte]bool{local: true}
		for _, s := range strings.Split(a.Clients, ",") {
			h, e = pruneExternalID("client-transport-keys", s)
			if e != nil {
				return local, remote, nil, e
			}
			p := [32]byte(h)
			if seen[p] || relay.ValidateTransport(d, p) != nil {
				return local, remote, nil, wire.ErrAccess
			}
			seen[p] = true
			peers = append(peers, p)
		}
		if len(peers) == 0 || len(peers) > 32 {
			return local, remote, nil, wire.ErrAccess
		}
	}
	return local, remote, peers, nil
}
func validatePruneServiceNetwork(a pruneServiceCLIFlags, d wire.Descriptor) error {
	if a.Timeout < remotewire.MinimumTimeout || a.Timeout > wire.ExchangeDeadline {
		return wire.ErrAccess
	}
	_, _, _, err := pruneServiceTransportKeys(a, d)
	return err
}

func callRemotePruneService(ctx context.Context, a pruneServiceCLIFlags, d wire.Descriptor, q wire.Request, approve func(context.Context, wire.Challenge) (custodyfence.Command, error)) (_ wire.Response, returnErr error) {
	local, remote, _, err := pruneServiceTransportKeys(a, d)
	if err != nil {
		return wire.Response{}, err
	}
	key, err := witnessKey(a.TransportKey, local)
	if err != nil {
		return wire.Response{}, err
	}
	defer clear(key)
	c := libp2ptransport.DefaultConfig()
	c.Listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1"}
	host, err := libp2ptransport.New(ctx, key, c, nil)
	if err != nil {
		return wire.Response{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, host.Close()) }()
	return relay.Call(ctx, host, a.Address, local, remote, d, q, a.Timeout, approve)
}

func servePruneServiceRelay(ctx context.Context, out io.Writer, a pruneServiceCLIFlags, d wire.Descriptor) (returnErr error) {
	local, _, peers, err := pruneServiceTransportKeys(a, d)
	if err != nil {
		return err
	}
	key, err := witnessKey(a.TransportKey, local)
	if err != nil {
		return err
	}
	defer clear(key)
	c := libp2ptransport.DefaultConfig()
	c.Listen = strings.Split(a.Listen, ",")
	s, err := relay.Start(ctx, a.Socket, d, key, c, peers, a.Timeout)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, s.Close()) }()
	raw, err := json.Marshal(struct {
		Event            string
		PeerID           string
		Addresses        []string
		ExecutionGranted bool
	}{"prune_relay_ready", s.ID().String(), s.Addresses(), false})
	if err != nil {
		return err
	}
	if err = writePruneOutputLine(out, string(raw)+"\n"); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}
