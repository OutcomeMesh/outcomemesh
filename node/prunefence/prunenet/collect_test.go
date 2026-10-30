package prunenet_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyfence/witnessnet"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

func TestPruneFenceNetworkQuorumPartitionAndCompetingCopy(t *testing.T) {
	for _, offline := range []int{0, 1, 2} {
		t.Run(string(rune('0'+offline))+"-offline", func(t *testing.T) {
			policy := prunefence.Policy{Owner: f.Public(1), Controller: f.Public(2), Threshold: 3, Witnesses: f.Scope().Witnesses}
			binding := prunefence.Binding{AssignmentID: f.Hash("assignment"), RequestID: f.Hash("request"), OperationID: f.Hash("operation"), InventoryID: f.Hash("inventory"), ExecutorBindingID: f.Hash("executor"), StoragePairID: f.Hash("storage")}
			session, err := prunefence.NewSession(policy, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			candidate, _ := session.Candidate()
			scope, draft, _ := candidate.Draft()
			sid, _ := scope.ID()
			client, err := libp2ptransport.New(t.Context(), f.Key(99), libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var endpoints []prunenet.Endpoint
			var servers []*witnessnet.Service
			for i := byte(0); i < 4; i++ {
				w, err := custodyfence.Create(filepath.Join(t.TempDir(), "witness"), scope, sid, f.Key(70+i))
				if err != nil {
					t.Fatal(err)
				}
				server, err := witnessnet.Start(t.Context(), w, scope, sid, f.Key(90+i), libp2ptransport.DefaultConfig(), []types.Hash{client.ID()}, time.Second)
				if err != nil {
					w.Close()
					t.Fatal(err)
				}
				t.Cleanup(func() { server.Close() })
				servers = append(servers, server)
				endpoints = append(endpoints, prunenet.Endpoint{Witness: f.Public(70 + i), Transport: f.Public(90 + i), Address: server.Addresses()[0]})
			}
			for i := 0; i < offline; i++ {
				servers[i].Close()
			}
			q, err := prunenet.Collect(t.Context(), client, f.Key(1), f.Public(99), endpoints, time.Second, scope, draft)
			if offline == 2 {
				if err == nil {
					t.Fatal("minority authorized deletion")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := session.Authorize(q); err != nil {
				t.Fatal(err)
			}
			copy, err := prunefence.NewSession(policy, binding)
			if err != nil {
				t.Fatal(err)
			}
			defer copy.Close()
			c, _ := copy.Candidate()
			s, d, _ := c.Draft()
			if _, err := prunenet.Collect(t.Context(), client, f.Key(1), f.Public(99), endpoints, time.Second, s, d); err == nil {
				t.Fatal("participant copy obtained competing quorum")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := prunenet.Collect(ctx, client, f.Key(1), f.Public(99), endpoints, time.Second, scope, draft); err == nil {
				t.Fatal("cancelled collector returned permission")
			}
		})
	}
}
