//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func TestPruneServiceSuccessorSignerPlacement(t *testing.T) {
	for _, change := range []string{"changed-bytes", "identical-copy"} {
		t.Run(change, func(t *testing.T) {
			f, receipt := preparePruneServiceReplacement(t)
			pruneServiceCLIRun(t, pruneSuccessorCLIArgs(t, f, receipt))
			executor, replicas := pruneFailureSnapshot(t, f), pruneFailureAuthorities(t, f)
			guard, err := f.guard.Position()
			if err != nil {
				t.Fatal(err)
			}
			owner := f.open(t, wire.Position{}, nil)
			record := filepath.Join(f.root, "signer-succession")
			raw := pruneServiceCLIRead(t, record)
			defer clear(raw)
			if change == "changed-bytes" {
				raw[len(raw)-1] ^= 1
				writePruneCLIFile(t, record, raw)
			} else {
				copyPath := record + ".copy"
				writePruneCLIFile(t, copyPath, raw)
				if err := os.Rename(copyPath, record); err != nil {
					t.Fatal(err)
				}
			}
			_, err = owner.Execute(t.Context(), f.request, func(context.Context, wire.Challenge) (custodyfence.Command, error) {
				t.Fatal("owner requested approval after signer file changed")
				return custodyfence.Command{}, nil
			})
			if !errors.Is(err, service.ErrOwner) {
				t.Fatalf("hot owner returned %v, want placement refusal", err)
			}
			if err = owner.Close(); err != nil {
				t.Fatal(err)
			}
			if change == "changed-bytes" {
				did, _ := f.descriptor.ID()
				if cold, err := service.Open(t.Context(), f.root, did, wire.Position{}, nil); err == nil {
					cold.Close()
					t.Fatal("cold owner accepted damaged signer authorization")
				}
			}
			events, err := os.ReadDir(filepath.Join(f.root, "events"))
			if err != nil || len(events) != 0 {
				t.Fatal("owner failed to preserve empty event history", err)
			}
			if got, err := f.guard.Position(); err != nil || got != guard || f.fault.choices.Load() != 0 {
				t.Fatal("signer file change reached guard", err)
			}
			if !reflect.DeepEqual(pruneFailureSnapshot(t, f), executor) || !reflect.DeepEqual(pruneFailureAuthorities(t, f), replicas) {
				t.Fatal("signer file change modified admission or replica accounting")
			}
		})
	}
}
