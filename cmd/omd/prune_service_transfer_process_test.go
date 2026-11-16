//go:build integration && (linux || darwin)

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

type pruneTransferCut struct {
	Source, Target, Stage, Report string
	DescriptorID, ReviewID        types.Hash
	Position                      wire.Position
	Inputs                        []string
	Bundle                        service.TransferBundle
}

func cutPruneTransfer(t *testing.T, binary string, cfg pruneTransferCut) {
	t.Helper()
	var err error
	cfg.Report, err = custodyCommandOutput(cfg.Report)
	if err != nil {
		t.Fatal(err)
	}
	for i, path := range cfg.Inputs {
		cfg.Inputs[i], err = custodyCommandFile(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestPruneServiceTransferBarrier$", "-test.count=1")
	cmd.Env = append(os.Environ(), "OUTCOMEMESH_TEST_PRUNE_TRANSFER_BARRIER=1")
	cmd.ExtraFiles = []*os.File{write}
	cmd.Stdin = bytes.NewReader(raw)
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	write.Close()
	reached, err := io.ReadAll(read)
	if err != nil || string(reached) != cfg.Stage {
		_ = cmd.Process.Kill()
		exit := cmd.Wait()
		t.Fatalf("missed cut %s: got %q, read=%v, exit=%v\n%s", cfg.Stage, reached, err, exit, &log)
	}
	for _, root := range []string{cfg.Source, cfg.Target} {
		if o, err := service.Open(ctx, root, cfg.DescriptorID, cfg.Position, nil); err == nil {
			o.Close()
			t.Fatalf("concurrent owner opened %s during %s", root, cfg.Stage)
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err == nil {
		t.Fatal("transfer completed before SIGKILL")
	}
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("transfer did not die at selected cut", cfg.Stage, cmd.ProcessState)
	}
}

type pruneTransferFile struct {
	info os.FileInfo
	hash [sha256.Size]byte
}

func snapshotPruneTransferTree(t *testing.T, root string) map[string]pruneTransferFile {
	t.Helper()
	tree := make(map[string]pruneTransferFile)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := pruneTransferFile{info: info}
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			entry.hash = sha256.Sum256(raw)
		}
		tree[name] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func checkPruneTransferTree(t *testing.T, root string, before map[string]pruneTransferFile, transferID string) {
	t.Helper()
	after := snapshotPruneTransferTree(t, root)
	if transferID != "" {
		for _, name := range []string{"transfer-" + transferID, "transfer-committed"} {
			if _, ok := after[name]; !ok {
				t.Fatal("missing transfer record", name)
			}
			delete(after, name)
		}
	}
	if len(before) != len(after) {
		t.Fatalf("%s: had %d original paths, found %d", root, len(before), len(after))
	}
	for name, v := range before {
		got, ok := after[name]
		if !ok || !os.SameFile(v.info, got.info) || v.info.Mode() != got.info.Mode() || v.hash != got.hash {
			t.Fatalf("transfer changed physical placement, permissions or contents of %s", filepath.Join(root, name))
		}
	}
}

func TestProcessPruneServiceTransferCLIHelper(t *testing.T) {
	if os.Getenv("OUTCOMEMESH_TEST_PRUNE_TRANSFER_CLI") != "1" {
		t.Skip("subprocess-only CLI retry")
	}
	var args []string
	if err := json.NewDecoder(os.Stdin).Decode(&args); err != nil {
		t.Fatal(err)
	}
	if err := runPruneServiceCLIContext(t.Context(), args, os.Stdout); err != nil {
		t.Fatal(err)
	}
}

func restartPruneTransferCLI(t *testing.T, args []string) {
	t.Helper()
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestProcessPruneServiceTransferCLIHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "OUTCOMEMESH_TEST_PRUNE_TRANSFER_CLI=1")
	cmd.Stdin = bytes.NewReader(data)
	if log, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cold CLI transfer retry: %v\n%s", err, log)
	}
}

// The moved container still contains the enrolled owner. A byte-identical
// replacement of a pin journal inside it must not finish the pending move.
func refusePruneTransferPinCopy(t *testing.T, pins, report, owner string, run []string) {
	t.Helper()
	aside := t.TempDir()
	original := filepath.Join(aside, "original-pins")
	files := snapshotPruneTransferTree(t, pins)
	if err := os.Rename(pins, original); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(pins, os.DirFS(original)); err != nil {
		t.Fatal(err)
	}
	for name, original := range files {
		if err := os.Chmod(filepath.Join(pins, name), original.info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	copied := snapshotPruneTransferTree(t, pins)
	if len(copied) != len(files) {
		t.Fatal("incomplete pin copy")
	}
	for name, original := range files {
		clone, ok := copied[name]
		if !ok || os.SameFile(original.info, clone.info) || clone.hash != original.hash || clone.info.Mode() != original.info.Mode() {
			t.Fatal("expected independent pin copy with identical bytes and modes", name)
		}
	}
	err := runPruneServiceCLIContext(t.Context(), run, io.Discard)
	if !errors.Is(err, service.ErrPosition) && !errors.Is(err, service.ErrOwner) {
		t.Fatal("transfer accepted the substituted placement or failed for another reason", err)
	}
	for _, path := range []string{report, filepath.Join(owner, "transfer-committed")} {
		if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("substituted placement received transfer confirmation", path, err)
		}
	}
	if err = os.Rename(pins, filepath.Join(aside, "rejected-copy")); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(original, pins); err != nil {
		t.Fatal(err)
	}
}

func approvePruneTransfer(_ context.Context, ch wire.Challenge) (custodyfence.Command, error) {
	_, cmd, err := ch.Candidate.Draft()
	if err != nil {
		return custodyfence.Command{}, err
	}
	return cmd.Sign(pruneCLIKey(4))
}

// Each transfer uses real authority journals, pins, a protected store and an
// independently owned guard. The driver checks the original physical files as
// well as the retained accounting and restarts the CLI in a new process.
func TestProcessPruneServiceTransferRecovery(t *testing.T) {
	binary := prunePublicationBinary(t)
	for _, tc := range []struct {
		stage, state string
		bundle       bool
	}{
		{"transfer-before-record", "admitted", false},
		{"transfer-record-created", "held", false},
		{"transfer-record-partial", "completed", false},
		{"transfer-record-written", "held", false},
		{"transfer-record-file-synced", "completed", false},
		{"transfer-record-durable", "admitted", false},
		{"transfer-before-rename", "completed", false},
		{"transfer-renamed", "held", false},
		{"transfer-destination-synced", "admitted", false},
		{"transfer-source-synced", "completed", false},
		{"transfer-committed-created", "observed", false},
		{"transfer-committed-durable", "completed", false},
		{"transfer-before-rename", "held", true},
		{"transfer-renamed", "observed", true},
		{"transfer-source-synced", "completed", true},
	} {
		name := tc.stage
		if tc.bundle {
			name = "storage/" + name
		}
		t.Run(name, func(t *testing.T) {
			if tc.state == "observed" && os.Geteuid() == 0 {
				t.Skip("result-write fault requires an unprivileged owner")
			}
			var f *pruneServiceOwnerCLIFixture
			var bundle service.TransferBundle
			if tc.bundle {
				f, bundle = newPruneTransferBundle(t)
			} else {
				f = preparePruneServiceOwnerCLI(t)
			}
			accounting := pruneFailureAuthorities(t, f)
			var position wire.Position
			var result []byte
			switch tc.state {
			case "held", "observed":
				mode := "guard-loss"
				if tc.state == "observed" {
					mode = "result-write"
				}
				o, pos := pruneFailureExecute(t, f, mode)
				if err := o.Close(); err != nil {
					t.Fatal(err)
				}
				position = pos
			case "completed":
				o := f.open(t, wire.Position{}, nil)
				r, err := o.Execute(t.Context(), f.request, approvePruneTransfer)
				if err != nil || r.Effect.Report.RemovedNodes == 0 {
					t.Fatal("expected actual protected deletion", err)
				}
				result, err = r.CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				position, err = r.Position()
				if err != nil {
					t.Fatal(err)
				}
				if err = o.Close(); err != nil {
					t.Fatal(err)
				}
			}
			source := f.root
			targetParent, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(targetParent, "relocated")
			if tc.bundle {
				bundle.Destination = filepath.Join(targetParent, "bundle")
				rel, err := filepath.Rel(bundle.Source, source)
				if err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(bundle.Destination, rel)
			}
			did, _ := f.descriptor.ID()
			posPath := filepath.Join(f.public, "transfer-position.json")
			pruneServiceCLIJSON(t, posPath, position)
			report := filepath.Join(f.public, "transfer-result.json")
			shared := []string{pruneServiceCommand, "--root", source, "--destination", target, "--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--position", posPath}
			if tc.bundle {
				shared = append(shared, "--storage-root", bundle.Source, "--storage-destination", bundle.Destination)
			}
			reviewArgs := append(append([]string(nil), shared...), "--action", "transfer-review", "--out", filepath.Join(f.public, "transfer-review.json"))
			id := pruneServiceCLIRun(t, reviewArgs)
			rawID, err := pruneExternalID("transfer-id", id)
			if err != nil {
				t.Fatal(err)
			}
			run := append(append([]string(nil), shared...), "--action", "transfer", "--transfer-id", id, "--out", report)
			run = append(run, "--mode", "run", "--expected-review-id", pruneServiceCLIReview(t, run))
			before := snapshotPruneTransferTree(t, source)
			r := f.config.Runtime
			journals := map[string]map[string]pruneTransferFile{}
			for _, path := range append(pruneServiceRuntimeRoots(r), r.InventoryPath) {
				if path != r.ChainPath { // Pebble manages its own reopen/compaction metadata.
					journals[path] = snapshotPruneTransferTree(t, path)
				}
			}
			chainRoot, err := os.Stat(r.ChainPath)
			if err != nil {
				t.Fatal(err)
			}
			executor := pruneFailureSnapshot(t, f)
			guard, err := f.guard.Position()
			if err != nil {
				t.Fatal(err)
			}
			cut := pruneTransferCut{
				Source: source, Target: target, Bundle: bundle, Stage: tc.stage,
				DescriptorID: did, ReviewID: rawID, Position: position,
				Report: report, Inputs: []string{f.descriptorPath, posPath},
			}
			cutPruneTransfer(t, binary, cut)
			if tc.stage == "transfer-record-partial" {
				path := filepath.Join(source, "transfer-"+id)
				prefix := pruneServiceCLIRead(t, path)
				inode, err := os.Stat(path)
				if err != nil || len(prefix) == 0 {
					t.Fatal("expected original partial record", err)
				}
				cutPruneTransfer(t, binary, cut)
				longer := pruneServiceCLIRead(t, path)
				after, err := os.Stat(path)
				if err != nil || !os.SameFile(inode, after) || len(longer) <= len(prefix) || !bytes.HasPrefix(longer, prefix) {
					t.Fatal("interrupted continuation lost or replaced its original prefix", err)
				}
			}
			// The OS has now dropped every lock from the killed process.
			// Pending transfer records must still exclude ordinary execution.
			if tc.stage != "transfer-before-record" && tc.stage != "transfer-committed-created" && tc.stage != "transfer-committed-durable" {
				for _, root := range []string{source, target} {
					if o, err := service.Open(t.Context(), root, did, position, nil); err == nil {
						o.Close()
						t.Fatal("uncommitted placement reopened after SIGKILL", root)
					}
				}
			}
			if tc.stage == "transfer-record-created" {
				otherTarget := filepath.Join(targetParent, "different-target")
				otherReport := filepath.Join(f.public, "different-transfer.json")
				alternate := replaceRemoteCLIFlag(reviewArgs, "--destination", otherTarget)
				alternate = replaceRemoteCLIFlag(alternate, "--out", otherReport)
				// Request a fresh review of a different destination. A zero-byte
				// transfer marker already reserves the originally approved ID.
				publicReview := pruneServiceCLIReview(t, alternate)
				alternate = append(alternate, "--mode", "run", "--expected-review-id", publicReview)
				if err := runPruneServiceCLIContext(t.Context(), alternate, io.Discard); err == nil {
					t.Fatal("empty reservation allowed a fresh review of a different destination")
				}
				if _, err := os.Lstat(otherReport); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused redirect published a report", err)
				}
				if _, err := os.Lstat(otherTarget); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused redirect created the other destination", err)
				}
			}
			if tc.bundle && tc.stage == "transfer-renamed" {
				rel, err := filepath.Rel(bundle.Source, r.ExecutorPinsPath)
				if err != nil || !filepath.IsLocal(rel) {
					t.Fatal("invalid fixture pin path", err)
				}
				refusePruneTransferPinCopy(t, filepath.Join(bundle.Destination, rel), report, target, run)
			}
			restartPruneTransferCLI(t, run)
			bytesAfterRestart := pruneServiceCLIRead(t, report)
			restartPruneTransferCLI(t, run)
			if !bytes.Equal(bytesAfterRestart, pruneServiceCLIRead(t, report)) {
				t.Fatal("retry changed completed transfer report")
			}
			if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("former owner path is still accessible", err)
			}
			if tc.bundle {
				if _, err = os.Lstat(bundle.Source); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("former storage path is still accessible", err)
				}
				useTransferredPruneBundle(t, f, bundle)
			} else {
				f.root = target
			}
			newChain, err := os.Stat(f.config.Runtime.ChainPath)
			if err != nil || !os.SameFile(chainRoot, newChain) {
				t.Fatal("original storage directory was replaced", err)
			}
			checkPruneTransferTree(t, target, before, id)
			for path, tree := range journals {
				if tc.bundle {
					rel, err := filepath.Rel(bundle.Source, path)
					if err != nil || !filepath.IsLocal(rel) {
						t.Fatal("fixture journal outside storage", path, err)
					}
					path = filepath.Join(bundle.Destination, rel)
				}
				checkPruneTransferTree(t, path, tree, "")
			}
			if !reflect.DeepEqual(executor, pruneFailureSnapshot(t, f)) || !reflect.DeepEqual(accounting, pruneFailureAuthorities(t, f)) {
				t.Fatal("transfer changed original executor or replica accounting")
			}
			now, err := f.guard.Position()
			if err != nil || now != guard {
				t.Fatal("transfer changed guard choice", err)
			}
			if _, found := pruneFailureEffect(t, f); found != (tc.state == "completed" || tc.state == "observed") {
				t.Fatal("changed protected storage effect")
			}
			if tc.state == "held" || tc.state == "completed" {
				f.stopNetwork()
				for _, archived := range f.config.Runtime.Sources {
					for _, path := range []string{archived.Directory, archived.JournalPath} {
						if err := os.Rename(path, path+".offline"); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			o := f.open(t, position, nil)
			snapshot, err := o.Snapshot()
			if err != nil || snapshot.Position != position {
				t.Fatal("moved owner lost external cursor", err)
			}
			calls := 0
			response, err := o.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
				calls++
				return approvePruneTransfer(ctx, ch)
			})
			switch tc.state {
			case "admitted":
				if err != nil || calls != 1 || response.Result == nil || response.Effect.Report.RemovedNodes == 0 {
					t.Fatal("admitted work failed to execute at destination", calls, err)
				}
			case "held", "observed":
				if !errors.Is(err, service.ErrHeld) || calls != 0 || snapshot.Intent == nil || *snapshot.Intent != f.request {
					t.Fatal("destination retried held work", err)
				}
			case "completed":
				raw, encodeErr := response.CanonicalBytes()
				if err != nil || encodeErr != nil || calls != 0 || !bytes.Equal(raw, result) {
					t.Fatal("historical response changed or requested another approval", err, encodeErr)
				}
			}
			if err = o.Close(); err != nil {
				t.Fatal(err)
			}
			f.assertObligations(t)
			if tc.state == "admitted" {
				now, err = f.guard.Position()
				if err != nil || now.Sequence != guard.Sequence+1 {
					t.Fatal("expected one guard choice at new placement", now, guard, err)
				}
			}
			if tc.state == "observed" {
				apply, _, out := preparePruneServiceSettlementCLI(t, f, position)
				pruneServiceCLIRun(t, apply)
				r, err := wire.DecodeResponse(pruneServiceCLIRead(t, out))
				if err != nil || r.Verify(f.descriptor, f.request) != nil || r.Settlement == nil || r.Result != nil {
					t.Fatal("destination failed to settle the original observed effect", err)
				}
				completePruneServiceSettlement(t, f, r, accounting)
				now, err := f.guard.Position()
				if err != nil || now != guard {
					t.Fatal("settlement repeated the guarded effect", err)
				}
			}
		})
	}
}
