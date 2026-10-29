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
	"strings"
	"syscall"
	"time"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	client "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayclient"
	relay "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewayrelay"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

const custodyRelayCommand = "work-archive-custody-relay"

func runCustodyRelayCLI(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runCustodyRelay(ctx, args, os.Stdout)
}

// No owner-root or role-key selector exists here. This process runs as the
// descriptor's participant UID; its only secret is a network transport key.
func runCustodyRelay(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || len(args) == 0 {
		return wire.ErrArtifact
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	f.SetOutput(io.Discard)
	action := f.String("action", "", "serve or call")
	mode := f.String("mode", "review", "review or run")
	descPath := f.String("descriptor", "", "complete issuer-signed gateway descriptor")
	pin := f.String("descriptor-id", "", "independently retained descriptor ID")
	keyPath := f.String("key", "", "network transport seed file, hexadecimal")
	socket := f.String("socket", "", "local isolated gateway Unix socket; serve only")
	listen := f.String("listen", "", "QUIC listen multiaddress; serve only")
	peers := f.String("clients", "", "comma-separated allowed client peer IDs; serve only")
	address := f.String("address", "", "remote QUIC multiaddress; call only")
	clientListen := f.String("client-listen", "/ip4/0.0.0.0/udp/0/quic-v1", "local client QUIC binding; call only")
	peer := f.String("peer", "", "independently pinned remote peer ID; call only")
	request := f.String("request", "", "exact signed Runtime envelope; call only")
	output := f.String("out", "", "fresh verified response artifact; call only")
	timeout := f.Duration("timeout", client.Deadline, "bounded one-attempt timeout, at most 10s")
	expected := f.String("expected-review-id", "", "exact public review ID")
	if e := parsePruneFlags(f, args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 || (*action != "serve" && *action != "call") || (*mode != "review" && *mode != "run") || *timeout < remotewire.MinimumTimeout || *timeout > client.Deadline {
		return wire.ErrArtifact
	}
	serve := *action == "serve"
	if serve && *clientListen != "/ip4/0.0.0.0/udp/0/quic-v1" {
		return wire.ErrArtifact
	}
	for _, v := range []struct {
		s        string
		required bool
	}{{*socket, serve}, {*listen, serve}, {*peers, serve}, {*address, !serve}, {*peer, !serve}, {*request, !serve}, {*output, !serve}} {
		if (v.s != "") != v.required {
			return wire.ErrArtifact
		}
	}
	var e error
	*descPath, e = custodyCommandFile(*descPath)
	if e != nil {
		return e
	}
	descRaw, e := readRegularArtifact(*descPath, wire.MaximumDescriptorBytes)
	if e != nil {
		return e
	}
	d, e := wire.DecodeDescriptor(descRaw)
	if e != nil {
		return e
	}
	id, e := witnessID("descriptor-id", *pin)
	actual, _ := d.ID()
	if e != nil || id != actual {
		return wire.ErrArtifact
	}
	*keyPath, e = custodyCommandFile(*keyPath)
	if e != nil {
		return e
	}
	if *keyPath == *descPath {
		return wire.ErrArtifact
	}
	inputs := map[string]string{*descPath: cutoverArtifactID(descRaw).String()}
	var allowed []types.Hash
	var remote types.Hash
	var packet []byte
	var summary any
	endpoint := *address
	if serve {
		endpoint = *listen
		*socket, e = filepath.Abs(*socket)
		if e != nil || len(*socket) > 100 || *socket == *keyPath || *socket == *descPath {
			return wire.ErrArtifact
		}
		seen := map[types.Hash]bool{}
		for _, s := range strings.Split(*peers, ",") {
			x, err := witnessID("client", s)
			if err != nil || seen[x] || len(allowed) == 16 {
				return wire.ErrArtifact
			}
			seen[x] = true
			allowed = append(allowed, x)
		}
	} else {
		remote, e = witnessID("peer", *peer)
		if e != nil {
			return e
		}
		*request, e = custodyCommandFile(*request)
		if e != nil {
			return e
		}
		packet, e = readRegularArtifact(*request, wire.MaximumServiceRequestBytes)
		if e != nil {
			return e
		}
		q, payload, err := relay.DecodeAttempt(d, packet)
		if err != nil {
			return err
		}
		cmd, err := v2.DecodeProtectedCommand(payload)
		if err != nil {
			return err
		}
		summary = struct {
			Request wire.Request
			Runtime any
		}{q, profile5PublicCommand(cmd)}
		inputs[*request] = cutoverArtifactID(packet).String()
		*output, e = custodyCommandOutput(*output)
		if e != nil || *output == *keyPath || *output == *descPath || *output == *request || *request == *keyPath {
			return wire.ErrArtifact
		}
	}
	m, e := ma.NewMultiaddr(endpoint)
	if e != nil {
		return e
	}
	// Reject another transport during review, before a listener/key is opened.
	if _, e = m.ValueForProtocol(ma.P_QUIC_V1); e != nil {
		return wire.ErrArtifact
	}
	if !serve {
		advertised, err := libp2ptransport.PeerIDFromAddress(*address)
		if err != nil || advertised != remote {
			return errors.Join(wire.ErrAccess, err)
		}
	}
	cm, e := ma.NewMultiaddr(*clientListen)
	if e != nil {
		return e
	}
	if _, e = cm.ValueForProtocol(ma.P_QUIC_V1); e != nil {
		return wire.ErrArtifact
	}
	public, e := json.Marshal(struct {
		Action, Descriptor, Key, Socket, Listen, Address, Output, ClientListen string
		DescriptorID, Peer                                                     types.Hash
		Clients                                                                []types.Hash
		Timeout                                                                time.Duration
		Inputs                                                                 map[string]string
		Attempt                                                                any
	}{*action, *descPath, *keyPath, *socket, *listen, *address, *output, *clientListen, id, remote, allowed, *timeout, inputs, summary})
	if e != nil {
		return e
	}
	review := types.DomainHash(wire.Domain+"relay/cli/review", public)
	if *mode == "review" {
		return writePruneOutputLine(out, fmt.Sprintf("custody_relay_review action=%s review_id=%s owners_opened=false keys_loaded=false network_opened=false\n%s\n", *action, review, public))
	}
	want, e := witnessID("expected-review-id", *expected)
	if e != nil || want != review {
		return errors.New("relay action requires its exact public review")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if !serve {
		if _, e = os.Lstat(*output); !errors.Is(e, os.ErrNotExist) {
			return errors.New("retain existing response and use a fresh output path")
		}
	}
	raw, e := readRegularArtifact(*keyPath, 256)
	if e != nil {
		return e
	}
	seed, e := hex.DecodeString(string(bytes.TrimSpace(raw)))
	clear(raw)
	if e != nil || len(seed) != ed25519.SeedSize {
		clear(seed)
		return wire.ErrArtifact
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	config := libp2ptransport.DefaultConfig()
	if serve {
		config.Listen = []string{*listen}
		s, e := relay.Start(ctx, *socket, d, key, config, allowed, *timeout)
		if e != nil {
			return e
		}
		defer s.Close()
		b, _ := json.Marshal(s.Addresses())
		if e = writePruneOutputLine(out, fmt.Sprintf("custody_relay_ready peer=%s descriptor_id=%s addresses=%s\n", s.ID(), id, b)); e != nil {
			return e
		}
		<-ctx.Done()
		return s.Close()
	}
	config.Listen = []string{*clientListen}
	run, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	host, e := libp2ptransport.New(run, key, config, nil)
	if e != nil {
		return e
	}
	defer host.Close()
	stream, _, e := host.OpenCustodyGatewayStream(run, *address, remote)
	if e != nil {
		return e
	}
	r, e := relay.Exchange(run, stream, d, packet, *timeout)
	if e != nil {
		return e
	}
	result, e := r.CanonicalBytes()
	if e != nil {
		return e
	}
	if e = publishCustodyCommandArtifact(*output, result); e != nil {
		return errors.Join(relay.ErrUnconfirmed, e)
	}
	return writePruneOutputLine(out, fmt.Sprintf("custody_relay action=call artifact_id=%s\n", cutoverArtifactID(result)))
}
