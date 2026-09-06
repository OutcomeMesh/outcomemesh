//go:build integration

package workarchive

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/workchain"
)

func TestAvailabilityPruneProcessCrashAtomicity(t *testing.T) {
	for _, boundary := range []string{"evidence", "decision", "complete"} {
		t.Run(boundary, func(t *testing.T) {
			f, replicas, policy := prepareAvailabilityPrune(t)
			bundle, err := VerifyReplicaSet(replicas, f.checkpoint, f.policy, policy, f.base, f.parameters, DefaultLimits(), 1_001)
			if err != nil {
				t.Fatal(err)
			}
			bundleID, _ := bundle.ID()
			before, _, err := f.source.HistoryUsage()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.source.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "availability.omav")
			marker := filepath.Join(t.TempDir(), "reached")
			command := exec.Command(os.Args[0], "-test.run=^TestAvailabilityPruneCrashHelper$", "-test.count=1")
			command.Env = append(os.Environ(),
				"OUTCOMEMESH_AVAILABILITY_CRASH="+boundary,
				"OUTCOMEMESH_AVAILABILITY_CHAIN="+f.sourcePath,
				"OUTCOMEMESH_AVAILABILITY_EVIDENCE="+path,
				"OUTCOMEMESH_AVAILABILITY_MARKER="+marker)
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			waitForArchiveCrashMarker(t, marker, command)
			if err := command.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = command.Wait()
			workPolicy := workchain.DefaultPolicy()
			workPolicy.ForkRetention, workPolicy.CanonicalRetention = 1, 1
			reopened, err := workchain.OpenWithPolicy(f.sourcePath, f.base, f.parameters, workPolicy)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			floor, err := reopened.CanonicalFloor()
			if err != nil || floor.Pruned != (boundary == "complete") {
				t.Fatalf("floor=%+v err=%v", floor, err)
			}
			if floor.Pruned && (floor.AvailabilityID != bundleID || floor.VerifiedAt != 1_001) {
				t.Fatal("committed floor lost exact evidence or authorization time")
			}
			after, _, err := reopened.HistoryUsage()
			if err != nil || (!floor.Pruned && after != before) {
				t.Fatal("uncommitted crash changed accounting", err)
			}
			if _, err := LoadAvailabilityBundleFile(path, f.checkpoint, f.policy, policy, 1_001, bundleID); err != nil {
				t.Fatal("crash lost complete published evidence", err)
			}
			encoded := mustReadArchiveFile(t, path)
			if _, err := pruneArchiveAt(reopened, replicas, path, f.checkpoint, f.policy, policy,
				f.base, f.parameters, DefaultLimits(), 1_101); !errors.Is(err, ErrAvailability) {
				t.Fatal("restart reused published evidence after freshness expired", err)
			}
			if !bytes.Equal(encoded, mustReadArchiveFile(t, path)) {
				t.Fatal("failed retry replaced historical evidence")
			}
			current, err := reopened.CanonicalFloor()
			if err != nil || current.Pruned != floor.Pruned || current.AvailabilityID != floor.AvailabilityID {
				t.Fatal("stale retry changed floor", err)
			}
			tip, err := reopened.Tip()
			if err != nil {
				t.Fatal(err)
			}
			block, _ := mineArchiveChild(t, reopened, tip.ID, tip.Timestamp+f.parameters.TargetSpacing, "availability-after-crash")
			if _, _, err := reopened.Commit(block, block.Header.Seal.Timestamp); err != nil {
				t.Fatal("recovered chain cannot extend", err)
			}
		})
	}
}

func TestAvailabilityPruneCrashHelper(t *testing.T) {
	boundary := os.Getenv("OUTCOMEMESH_AVAILABILITY_CRASH")
	if boundary == "" {
		t.Skip("subprocess helper")
	}
	// Reconstruct trusted archive/checkpoint/receipt inputs independently. Only
	// the exact chain and output destinations come from the parent environment.
	f, replicas, policy := prepareAvailabilityPrune(t)
	workPolicy := workchain.DefaultPolicy()
	workPolicy.ForkRetention, workPolicy.CanonicalRetention = 1, 1
	chain, err := workchain.OpenWithPolicy(os.Getenv("OUTCOMEMESH_AVAILABILITY_CHAIN"), f.base, f.parameters, workPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	stop := func() {
		if err := os.WriteFile(os.Getenv("OUTCOMEMESH_AVAILABILITY_MARKER"), []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	calls := 0
	clock := func() time.Time {
		calls++
		if (boundary == "evidence" && calls == 3) || (boundary == "decision" && calls == 4) {
			stop()
		}
		return time.Unix(1_001, 0)
	}
	if _, err := pruneCanonicalPrefix(context.Background(), chain, replicas, os.Getenv("OUTCOMEMESH_AVAILABILITY_EVIDENCE"),
		f.checkpoint, f.policy, policy, f.base, f.parameters, DefaultLimits(), clock); err != nil {
		t.Fatal(err)
	}
	if boundary == "complete" {
		stop()
	}
	t.Fatal("crash boundary was not reached")
}
