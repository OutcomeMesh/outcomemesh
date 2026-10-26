package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func custodyCommandCLICommonArgs(f *managedCustodyAuditCLIFixture) []string {
	a := f.config.Audit
	p := a.CustodyPolicy
	return []string{"--assignment", f.serve.assignmentPath, "--assignment-id", a.AssignmentID.String(), "--manifest", f.serve.manifestPath, "--receipt", f.serve.receiptPath,
		"--intent", f.intentPath, "--intent-id", a.IntentID.String(), "--previous-receipt", f.serve.receiptPath,
		"--max-challenge-lifetime-seconds", strconv.FormatUint(p.MaximumChallengeLifetime, 10), "--max-proof-age-seconds", strconv.FormatUint(p.MaximumProofAge, 10), "--max-renewal-term-seconds", strconv.FormatUint(p.MaximumRenewalTerm, 10)}
}

func custodyCommandSigningArgs(f *managedCustodyAuditCLIFixture, purpose string) []string {
	a := append([]string{custodyCommandSignCommand}, custodyCommandCLICommonArgs(f)...)
	a = append(a, "--kind", "admit", "--purpose", purpose, "--expected-sequence", "0", "--expected-head", f.config.Audit.AssignmentID.String(), "--consumer-public-key", fmt.Sprintf("%x", pruneCLIPublic(4)))
	return a
}

func custodyCommandReviewToken(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runCustodyCommand(t.Context(), args, nil, &out); err != nil {
		t.Fatal(err)
	}
	fields := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])
	if fields["review_id"] == "" {
		t.Fatal(out.String())
	}
	return fields["review_id"]
}

func TestCustodyCommandSigningExactArtifactsAndRetryWithoutSeed(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	before := f.snapshot(t)
	key := filepath.Join(t.TempDir(), "consumer.seed")
	authority := filepath.Join(t.TempDir(), "authority.seed")
	writePruneCLIFile(t, key, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, authority, pruneCLIKey(1).Seed())
	for _, purpose := range []string{"audit", "serve"} {
		t.Run(purpose, func(t *testing.T) {
			args := custodyCommandSigningArgs(f, purpose)
			if purpose == "serve" {
				b, _ := f.serve.challenge.CanonicalBytes()
				path := filepath.Join(t.TempDir(), "challenge.omcc")
				writePruneCLIFile(t, path, b)
				id, _ := f.serve.challenge.ID()
				args = append(args, "--challenge", path, "--challenge-id", id.String())
			}
			review := custodyCommandReviewToken(t, args)
			commandFile := filepath.Join(t.TempDir(), "command.omcac")
			signing := append(append([]string{}, args...), "--mode", "sign", "--consumer-key", key, "--expected-review-id", review, "--out", commandFile)
			var out bytes.Buffer
			if err := runCustodyCommand(t.Context(), signing, nil, &out); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(commandFile)
			if err != nil {
				t.Fatal(err)
			}
			command, err := custodyauthority.DecodeCommand(b)
			if err != nil {
				t.Fatal(err)
			}
			if command.ExpectedSequence != 0 || command.ExpectedHead != f.config.Audit.AssignmentID {
				t.Fatal("position refreshed")
			}
			cosign := append([]string{}, args...)
			cosign[0] = custodyCommandCosignCommand
			cosign = append(cosign, "--command", commandFile)
			cosignReview := custodyCommandReviewToken(t, cosign)
			entryFile := filepath.Join(t.TempDir(), "entry.omcae")
			cosign = append(cosign, "--mode", "sign", "--authority-key", authority, "--expected-review-id", cosignReview, "--out", entryFile)
			if err := runCustodyCommand(t.Context(), cosign, nil, io.Discard); err != nil {
				t.Fatal(err)
			}
			eb, err := os.ReadFile(entryFile)
			if err != nil {
				t.Fatal(err)
			}
			entry, err := custodyauthority.DecodeEntry(eb)
			if err != nil || entry.Command != command {
				t.Fatal(err)
			}
			// A retained canonical result recovers stdout without another key read.
			for i := range signing {
				if signing[i] == key {
					signing[i] = filepath.Join(t.TempDir(), "missing.seed")
				}
			}
			if err := runCustodyCommand(t.Context(), signing, nil, io.Discard); err != nil {
				t.Fatal("exact retry read missing key", err)
			}
			for i := range cosign {
				if cosign[i] == authority {
					cosign[i] = filepath.Join(t.TempDir(), "missing.seed")
				}
			}
			if err := runCustodyCommand(t.Context(), cosign, nil, io.Discard); err != nil {
				t.Fatal("exact co-sign retry read missing key", err)
			}
		})
	}
	if !reflect.DeepEqual(before, f.snapshot(t)) {
		t.Fatal("offline signing changed authority")
	}
}

func TestCustodyCommandSigningReviewRestrictionsAndFixedPosition(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	args := custodyCommandSigningArgs(f, "audit")
	for _, extra := range [][]string{{"--consumer-key", ""}, {"--out", ""}, {"--expected-review-id", ""}, {"--challenge", ""}, {"--admission", ""}, {"--purpose", "serve"}, {"stray"}} {
		if err := runCustodyCommand(t.Context(), append(append([]string{}, args...), extra...), nil, io.Discard); err == nil {
			t.Fatal("accepted", extra)
		}
	}
	for _, sequence := range []string{"", "00", "+0", "18446744073709551615"} {
		bad := append([]string{}, args...)
		for i := range bad {
			if bad[i] == "--expected-sequence" {
				bad[i+1] = sequence
			}
		}
		if err := runCustodyCommand(t.Context(), bad, nil, io.Discard); err == nil {
			t.Fatal("accepted sequence", sequence)
		}
	}
	var out bytes.Buffer
	if err := runCustodyCommand(t.Context(), args, nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.intent.Nonce.String(), hex.EncodeToString(pruneCLIKey(4).Seed()), "PrivateKey"} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("review leaked private material")
		}
	}
}

func TestCustodyCommandSigningPreservesArtifactAfterLostOutput(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	args := custodyCommandSigningArgs(f, "audit")
	id := custodyCommandReviewToken(t, args)
	key := filepath.Join(t.TempDir(), "consumer.seed")
	writePruneCLIFile(t, key, pruneCLIKey(4).Seed())
	out := filepath.Join(t.TempDir(), "command.omcac")
	args = append(args, "--mode", "sign", "--consumer-key", key, "--expected-review-id", id, "--out", out)
	broken := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err := runCustodyCommand(t.Context(), args, nil, broken); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal("lost output erased signed artifact", err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := runCustodyCommand(t.Context(), args, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(out)
	if !bytes.Equal(b, again) {
		t.Fatal("retry changed canonical command")
	}
	if err := os.WriteFile(out, []byte("conflicting"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runCustodyCommand(t.Context(), args, nil, io.Discard); err == nil {
		t.Fatal("replaced conflicting output")
	}
	retained, _ := os.ReadFile(out)
	if string(retained) != "conflicting" {
		t.Fatal("replaced output")
	}
}

func TestCustodyCommandSigningRetainedRetryNeedsNoTemporaryFile(t *testing.T) {
	f := newManagedCustodyAuditCLIFixture(t)
	args := custodyCommandSigningArgs(f, "audit")
	commandReviewID := custodyCommandReviewToken(t, args)
	keyDirectory, outputDirectory := t.TempDir(), t.TempDir()
	consumerKey := filepath.Join(keyDirectory, "consumer.seed")
	authorityKey := filepath.Join(keyDirectory, "authority.seed")
	writePruneCLIFile(t, consumerKey, pruneCLIKey(4).Seed())
	writePruneCLIFile(t, authorityKey, pruneCLIKey(1).Seed())
	commandFile := filepath.Join(outputDirectory, "command.omcac")
	entryFile := filepath.Join(outputDirectory, "entry.omcae")
	signing := append(append([]string{}, args...), "--mode", "sign", "--consumer-key", consumerKey,
		"--expected-review-id", commandReviewID, "--out", commandFile)
	if err := runCustodyCommand(t.Context(), signing, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	cosigning := append([]string{}, args...)
	cosigning[0] = custodyCommandCosignCommand
	cosigning = append(cosigning, "--command", commandFile)
	entryReviewID := custodyCommandReviewToken(t, cosigning)
	cosigning = append(cosigning, "--mode", "sign", "--authority-key", authorityKey,
		"--expected-review-id", entryReviewID, "--out", entryFile)
	if err := runCustodyCommand(t.Context(), cosigning, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	commandBefore, err := os.ReadFile(commandFile)
	if err != nil {
		t.Fatal(err)
	}
	entryBefore, err := os.ReadFile(entryFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{consumerKey, authorityKey} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(outputDirectory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outputDirectory, 0o700) })
	probe, err := os.CreateTemp(outputDirectory, ".permission-probe-*")
	if err == nil {
		name := probe.Name()
		_ = probe.Close()
		_ = os.Remove(name)
		t.Skip("filesystem does not enforce owner write removal")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal("temporary-file prohibition did not come from the selected directory permissions", err)
	}
	for _, retry := range [][]string{signing, cosigning} {
		var output bytes.Buffer
		if err := runCustodyCommand(t.Context(), retry, nil, &output); err != nil {
			t.Fatal("exact retained retry required a temporary file or signer seed", err)
		}
		fields := pruneCLIFields(strings.SplitN(output.String(), "\n", 2)[0])
		if fields["artifact_reused"] != "true" || fields["artifact_published"] != "true" {
			t.Fatal(output.String())
		}
	}
	commandAfter, err := os.ReadFile(commandFile)
	if err != nil || !bytes.Equal(commandBefore, commandAfter) {
		t.Fatal("retained consumer command changed", err)
	}
	entryAfter, err := os.ReadFile(entryFile)
	if err != nil || !bytes.Equal(entryBefore, entryAfter) {
		t.Fatal("retained co-signed entry changed", err)
	}
}
