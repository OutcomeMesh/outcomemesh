//go:build integration && (linux || darwin)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	"github.com/outcomemesh/outcomemesh/node/workchain"
)

type prunePublicationFixture struct {
	Root, Request, Key, Stage, Marker string
	DescriptorID, ContinuationID      types.Hash
	Before                            wire.Position
	Settlement                        *service.SettlementInput
	SettlementReviewID                types.Hash
}

func prunePublicationBinary(t testing.TB) string {
	t.Helper()
	if p := os.Getenv("OUTCOMEMESH_PRUNE_SERVICE_TEST_BINARY"); p != "" {
		return p
	}
	p := filepath.Join(t.TempDir(), "pruneservice.test")
	cmd := exec.Command("go", "test", "-tags=integration", "-c", "./node/pruneservice", "-o", p)
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("publication helper build: %v\n%s", err, out)
	}
	return p
}

func killPrunePublication(t *testing.T, binary string, c prunePublicationFixture) {
	t.Helper()
	dir := t.TempDir()
	c.Marker = filepath.Join(dir, "barrier")
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "fixture.json")
	writePruneCLIFile(t, config, raw)
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestPruneServicePublicationBarrier$", "-test.count=1", "-test.timeout=95s")
	cmd.Env = append(os.Environ(), "OUTCOMEMESH_PRUNE_PUBLICATION_FIXTURE="+config)
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if marker, err := os.ReadFile(c.Marker); err == nil && string(marker) == c.Stage {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("publisher ended before %s: %v\n%s", c.Stage, err, log.String())
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			<-done
			t.Fatalf("publisher missed %s\n%s", c.Stage, log.String())
		case <-tick.C:
		}
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("publisher was not killed")
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("not SIGKILL", cmd.ProcessState)
	}
}

func TestProcessPruneServicePublicationRecovery(t *testing.T) {
	binary := prunePublicationBinary(t)
	for _, stage := range []string{"intent-created", "intent-partial", "intent-written", "intent-file-synced", "intent-confirmed", "candidate-retained", "original-result-confirmed", "result-created", "result-partial", "result-written", "result-file-synced", "result-durable", "response-ready"} {
		t.Run(stage, func(t *testing.T) {
			f := preparePruneServiceOwnerCLI(t)
			did, _ := f.descriptor.ID()
			before := publicationAuthorities(t, f)
			c := prunePublicationFixture{Root: f.root, Request: f.requestPath, Key: f.consumerPath, Stage: stage, DescriptorID: did}
			killPrunePublication(t, binary, c)
			completed := strings.HasPrefix(stage, "result-") || stage == "original-result-confirmed" || stage == "response-ready"
			f.stopNetwork()
			if err := os.Remove(f.consumerPath); err != nil {
				t.Fatal(err)
			}
			intentRaw, err := os.ReadFile(filepath.Join(f.root, "events", "intent"))
			if err != nil {
				t.Fatal(err)
			}
			qraw, _ := f.request.CanonicalBytes()
			if !bytes.HasPrefix(qraw, intentRaw) {
				t.Fatal("torn request differs from retained request")
			}
			if len(intentRaw) < len(qraw) {
				r, err := service.ReviewContinuation(t.Context(), f.root, did, wire.Position{}, f.request)
				if err != nil {
					t.Fatal(err)
				}
				id, _ := r.ID()
				if stage == "intent-partial" {
					// Interrupt continuation itself; the old prefix review must become stale.
					c.ContinuationID = id
					killPrunePublication(t, binary, c)
					if _, err = service.Continue(t.Context(), f.root, did, wire.Position{}, f.request, id); err == nil {
						t.Fatal("stale append review accepted")
					}
					r, err = service.ReviewContinuation(t.Context(), f.root, did, wire.Position{}, f.request)
					if err != nil {
						t.Fatal(err)
					}
					id, _ = r.ID()
				}
				if _, err = service.Continue(t.Context(), f.root, did, wire.Position{}, f.request, id); err != nil {
					t.Fatal("intent continuation", err)
				}
			}
			position, _ := f.request.IntentPosition()
			if completed {
				// Recovery needs the original executor proof, not archive sources or network.
				for _, src := range f.config.Runtime.Sources {
					for _, p := range []string{src.Directory, src.JournalPath} {
						if err = os.Rename(p, p+".offline"); err != nil {
							t.Fatal(err)
						}
					}
				}
				r, err := service.ReviewContinuation(t.Context(), f.root, did, position, f.request)
				if err != nil {
					t.Fatal("result review", err)
				}
				id, _ := r.ID()
				if stage == "result-partial" {
					c.ContinuationID = id
					c.Before = position
					killPrunePublication(t, binary, c)
					if _, err = service.Continue(t.Context(), f.root, did, position, f.request, id); err == nil {
						t.Fatal("stale result review accepted")
					}
					r, err = service.ReviewContinuation(t.Context(), f.root, did, position, f.request)
					if err != nil {
						t.Fatal(err)
					}
					id, _ = r.ID()
				}
				snapshot, err := service.Continue(t.Context(), f.root, did, position, f.request, id)
				if err != nil || snapshot.Response == nil {
					t.Fatal("result continuation", err)
				}
				if err = snapshot.Response.Verify(f.descriptor, f.request); err != nil {
					t.Fatal(err)
				}
				position = snapshot.Position
			}
			o := f.open(t, position, &f.request)
			reply, err := o.Execute(t.Context(), f.request, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
				t.Error("recovery created a session")
				return custodyfence.Command{}, io.ErrUnexpectedEOF
			})
			if completed {
				if err != nil {
					t.Fatal(err)
				}
				if reply.Effect.Report.RemovedNodes == 0 {
					t.Fatal("missing actual deletion")
				}
			} else if !errors.Is(err, service.ErrHeld) {
				t.Fatal("unknown attempt not held", err)
			}
			if err = o.Close(); err != nil {
				t.Fatal(err)
			}
			if after := publicationAuthorities(t, f); !reflect.DeepEqual(before, after) {
				t.Fatal("process cut changed original accounting")
			}
			cRuntime := f.config.Runtime
			chain, err := workchain.OpenRadixMigratedPositionPinnedWithPolicy(cRuntime.ChainPath, cRuntime.ChainPinsPath, cRuntime.Base, cRuntime.Parameters, cRuntime.StoragePolicy, f.inventory.Request.StorageID, cRuntime.StorageMigrationID)
			if err != nil {
				t.Fatal(err)
			}
			floor, err := chain.CanonicalFloor()
			closeErr := chain.Close()
			if err != nil || closeErr != nil || floor.Pruned != completed {
				t.Fatal("wrong original storage floor", err, closeErr, floor.Pruned)
			}
		})
	}
}

func publicationAuthorities(t testing.TB, f *pruneServiceOwnerCLIFixture) []store.Coordination {
	t.Helper()
	var all []store.Coordination
	for _, replica := range f.inventory.Replicas {
		aid, _ := replica.Assignment.ID()
		for _, root := range f.config.Runtime.Authorities {
			if root.AssignmentID != aid {
				continue
			}
			o, err := store.OpenCoordinator(root.AuthorityPath, root.AuthorityPinsPath, replica.Assignment, aid)
			if err != nil {
				t.Fatal(err)
			}
			s, err := o.Snapshot()
			e := o.Close()
			if err != nil || e != nil {
				t.Fatal(err, e)
			}
			all = append(all, s)
		}
	}
	if len(all) != len(f.inventory.Replicas) {
		t.Fatal("missing original authority")
	}
	return all
}
