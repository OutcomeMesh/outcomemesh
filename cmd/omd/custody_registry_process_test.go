//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestProcessCustodyRegistryLostVoteAndCommitOutput(t *testing.T) {
	lost := map[string]bool{}
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		action := admissionProcessFlag(args, "--action")
		if admissionProcessFlag(args, "--mode") != "run" || lost[action] || (action != "witness-vote" && action != "witness-commit") {
			return runProcessCommand(t, 15*time.Second, args...)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		reader, writer, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		_ = reader.Close()
		child := helperCommand(ctx, args...)
		child.Stdout = writer
		var stderr bytes.Buffer
		child.Stderr = &stderr
		if e := child.Start(); e != nil {
			_ = writer.Close()
			t.Fatal(e)
		}
		_ = writer.Close()
		if e := child.Wait(); e == nil || ctx.Err() != nil {
			t.Fatal("expected lost registry stdout", action, e, ctx.Err(), stderr.String())
		}
		if _, e := os.ReadFile(admissionProcessFlag(args, "--out")); e != nil {
			t.Fatal("registry result not retained before lost output", e, stderr.String())
		}
		lost[action] = true
		return ""
	}
	runRegistryCLICampaign(t, driver)
	if !lost["witness-vote"] || !lost["witness-commit"] {
		t.Fatal("missing real-process lost-output boundary")
	}
}

// Only public deterministic fixture seeds and never-started artifacts leave
// this exporter. Both witness owners are created independently at destination.
func TestExportCustodyRegistryFixture(t *testing.T) {
	parent := os.Getenv("OUTCOMEMESH_REMOTE_FIXTURE_OUT")
	if parent == "" {
		t.Skip("explicit unstarted registry fixture export")
	}
	info, e := os.Lstat(parent)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private existing export parent required", e)
	}
	root, e := os.MkdirTemp(parent, "registry-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	z := newRegistryCLIFixture(t)
	z.g.ResourceID = remoteCustodyRandomHash(t)
	gid, _ := z.g.ID()
	did, _ := z.g.DescriptorID()
	other := z.initial
	a := other.Assignment.Base
	other.Assignment.Base, e = workarchive.CreateRemoteCustodyAuthorityAssignment(other.Manifest, other.Initial, other.CustodyPolicy, remoteCustodyRandomHash(t), a.AuthorityPublicKey, a.Consumers, a.MaximumOperations, a.MaximumPending, a.RemoteControlPublicKey, a.RemoteTransportPublicKey)
	if e != nil {
		t.Fatal(e)
	}
	cid, _ := z.initial.ID()
	cdid, _ := z.initial.DescriptorID()
	oid, _ := other.ID()
	odid, _ := other.DescriptorID()
	members := []map[string]any{}
	for seed := byte(111); seed <= 114; seed++ {
		host := "a"
		if seed >= 113 {
			host = "b"
		}
		members = append(members, map[string]any{"seed": seed, "public": types.Hash(f.Public(seed)).String(), "host": host})
	}
	metadata := map[string]any{"Version": 1, "RegistryID": gid.String(), "RegistryDescriptorID": did.String(), "CandidateID": cid.String(), "CandidateDescriptorID": cdid.String(), "OtherCandidateID": oid.String(), "OtherCandidateDescriptorID": odid.String(), "Members": members, "OwnersCreated": false, "SelectionOnly": true, "ExecutionGranted": false, "TestKeysPublic": true}
	for _, role := range []string{"a", "b"} {
		dir := filepath.Join(root, role)
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Mkdir(filepath.Join(dir, "keys"), 0700); e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(z.g)
		writePruneCLIFile(t, filepath.Join(dir, "registry-draft.json"), raw)
		raw, _ = z.initial.CanonicalBytes()
		writePruneCLIFile(t, filepath.Join(dir, "candidate"), raw)
		raw, _ = other.CanonicalBytes()
		writePruneCLIFile(t, filepath.Join(dir, "candidate-other"), raw)
		raw, _ = json.Marshal(metadata)
		writePruneCLIFile(t, filepath.Join(dir, "public.json"), raw)
		seeds := []byte{1, 110, 111, 112}
		if role == "b" {
			seeds = []byte{14, 113, 114}
		}
		for _, seed := range seeds {
			writePruneCLIFile(t, filepath.Join(dir, "keys", fmt.Sprintf("%d.seed", seed)), f.Key(seed).Seed())
		}
	}
	fmt.Printf("custody_registry_fixture root=%s roots_created=false test_keys_public=true selection_only=true execution_granted=false\n", root)
}
