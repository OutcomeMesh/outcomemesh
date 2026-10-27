//go:build integration

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestProcessRemoteCustodyOfflineSignaturesAndFreshAuthority(t *testing.T) {
	f := newRemoteCLIFixture(t)
	args := append([]string{remoteCustodySignCommand}, remoteOfflineCommonArgs(f)...)
	args = append(args, "--kind", "admit", "--purpose", "audit", "--consumer-public-key", fmt.Sprintf("%x", f.intent.ConsumerPublicKey), "--expected-sequence", "0", "--expected-head", f.scope.Worker.Plan.AssignmentID.String())
	run := func(args []string, prefix string) map[string]string {
		t.Helper()
		fields := outputFields(runProcessCommand(t, 15*time.Second, args...), prefix)
		if fields == nil {
			t.Fatal("missing subprocess report", prefix)
		}
		return fields
	}
	review := run(args, "remote_custody_signing")["review_id"]
	key, command := filepath.Join(t.TempDir(), "actor.seed"), filepath.Join(t.TempDir(), "command")
	writePruneCLIFile(t, key, pruneCLIKey(4).Seed())
	signing := append(append([]string{}, args...), "--mode", "sign", "--expected-review-id", review, "--actor-key", key, "--out", command)
	run(signing, "remote_custody_signing")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if run(signing, "remote_custody_signing")["artifact_reused"] != "true" {
		t.Fatal("subprocess retried signing")
	}
	cosign := append([]string{}, args...)
	cosign[0] = remoteCustodyCosignCommand
	cosign = append(cosign, "--command", command)
	review = run(cosign, "remote_custody_signing")["review_id"]
	entryPath := filepath.Join(t.TempDir(), "entry")
	cosign = append(cosign, "--mode", "sign", "--expected-review-id", review, "--authority-key", f.keyPaths[1], "--out", entryPath)
	run(cosign, "remote_custody_signing")
	if err := os.Remove(f.keyPaths[1]); err != nil {
		t.Fatal(err)
	}
	if run(cosign, "remote_custody_signing")["artifact_reused"] != "true" {
		t.Fatal("subprocess retried authority signing")
	}
	b, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.DecodeEntry(b)
	if err != nil || entry != f.audit {
		t.Fatal("subprocess changed canonical entry", err)
	}
	authority, pins := filepath.Join(t.TempDir(), "authority"), filepath.Join(t.TempDir(), "pins")
	bootstrap := []string{remoteCustodyAuthorityBootstrapCommand, "--assignment", filepath.Join(f.public, "assignment"), "--assignment-id", f.scope.Worker.Plan.AssignmentID.String(), "--authority", authority, "--authority-pins", pins}
	review = run(bootstrap, "remote_custody_authority_bootstrap")["review_id"]
	run(append(append([]string{}, bootstrap...), "--mode", "create", "--expected-review-id", review), "remote_custody_authority_bootstrap")
	if fields := run(append(bootstrap, "--mode", "verify"), "remote_custody_authority_bootstrap"); fields["confirmed_sequence"] != "0" || fields["retained_attempt"] != "false" {
		t.Fatal(fields)
	}
}
