package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRemoteCustodyInitialCLIReviewAndLostChallengeOutput(t *testing.T) {
	f := newRemoteCLIFixture(t)
	args := remoteZeroAdmissionArgs(f, "audit", "audit", f.audit)
	args[0] = remoteCustodyChallengeCommand
	args = append(args, "--artifacts", f.base.config.Audit.ArtifactsPath)
	roots := []string{f.authority, f.pins, f.base.config.Audit.JournalPath, f.base.config.Audit.ArtifactsPath}
	before := remoteCLITrees(t, roots)
	var review bytes.Buffer
	if err := runCustodyCommand(t.Context(), args, nil, &review); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, remoteCLITrees(t, roots)) || !strings.Contains(review.String(), "owners_retained=false") {
		t.Fatal("review changed original roots", review.String())
	}
	if err := runCustodyCommand(t.Context(), append(append([]string{}, args...), "--auditor-key", f.keyPaths[3]), nil, io.Discard); err == nil {
		t.Fatal("review accepted a seed flag")
	}
	controlArgs := append(append([]string{}, args...), "--auditor-key", f.keyPaths[3])
	writer := pruneEffectTestWriter(func(b []byte) (int, error) {
		if strings.HasPrefix(string(b), "work_archive_custody_command_result ") {
			return 0, io.ErrClosedPipe
		}
		return len(b), nil
	})
	// A normal observer is still needed for Ready and the full comparison.
	writes := make(chan string, 4)
	observer := pruneEffectTestWriter(func(b []byte) (int, error) {
		if strings.HasPrefix(string(b), "work_archive_custody_command_result ") {
			return writer.Write(b)
		}
		writes <- string(b)
		return len(b), nil
	})
	s := startCustodyCommandControl(t, controlArgs, observer)
	s.writes = writes
	custodyCommandControlLine(t, s, "work_archive_custody_command_ready")
	id := custodyCommandControlReview(t, s)
	if _, err := io.WriteString(s.input, "prepare "+id+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := s.wait(t); !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, errCustodyCommandUnobserved) {
		t.Fatal("lost output was reported as success", err)
	}
	path := filepath.Join(f.base.config.Audit.ArtifactsPath, "cycle-00000000000000000001", "challenge.omcc")
	retained, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("lost output lost the signed challenge", err)
	}
	s = startCustodyCommandControl(t, controlArgs, nil)
	custodyCommandControlLine(t, s, "work_archive_custody_command_ready")
	id = custodyCommandControlReview(t, s)
	_, _ = io.WriteString(s.input, "prepare "+id+"\n")
	result := custodyCommandControlLine(t, s, "work_archive_custody_command_result")
	_, _ = io.WriteString(s.input, "close\n")
	if err := s.wait(t); err != nil {
		t.Fatal(err)
	}
	want, _ := f.scope.Challenge.ID()
	if result["challenge_id"] != want.String() {
		t.Fatal("retry changed challenge", result)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, retained) {
		t.Fatal("retry refreshed artifact", err)
	}
}

func TestRemoteCustodySourceCLIRejectsUnreviewedAndOverlappingSetup(t *testing.T) {
	f := newRemoteCLIFixture(t)
	journal, artifacts := filepath.Join(t.TempDir(), "journal"), filepath.Join(t.TempDir(), "artifacts")
	args := []string{remoteCustodySourceCommand, "--assignment", filepath.Join(f.public, "assignment"), "--assignment-id", f.scope.Worker.Plan.AssignmentID.String(), "--manifest", f.base.serve.manifestPath, "--receipt", f.base.serve.receiptPath, "--role", "audit", "--journal", journal, "--artifacts", artifacts}
	// Use the same explicit policy as the independently pinned assignment.
	common := remoteOfflineCommonArgs(f)
	for i := 0; i < len(common)-1; i += 2 {
		if strings.HasPrefix(common[i], "--max-") {
			args = append(args, common[i], common[i+1])
		}
	}
	review := remoteOfflineRun(t, args)["review_id"]
	if _, err := os.Lstat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("review initialized source", err)
	}
	bad := append(append([]string{}, args...), "--mode", "create", "--expected-review-id", pruneCLIHash(252).String())
	if err := runCustodyCommand(t.Context(), bad, nil, io.Discard); err == nil {
		t.Fatal("unreviewed source created")
	}
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	create := append(append([]string{}, args...), "--mode", "create", "--expected-review-id", review)
	if err := runCustodyCommand(t.Context(), create, nil, io.Discard); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing artifacts accepted", err)
	}
	if _, err := os.Lstat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preflight failure partially created journal", err)
	}
	if err := runCustodyCommand(t.Context(), pruneCLISet(args, "role", "serve"), nil, io.Discard); err == nil {
		t.Fatal("B selected A artifacts")
	}
	if err := runCustodyCommand(t.Context(), pruneCLISet(args, "journal", filepath.Join(f.public, "nested-source")), nil, io.Discard); err == nil {
		t.Fatal("source nested in metadata accepted")
	}
	if err := runCustodyCommand(t.Context(), append(append([]string{}, args...), "--mode", "verify"), nil, io.Discard); err == nil {
		t.Fatal("verify initialized missing source")
	}
}
