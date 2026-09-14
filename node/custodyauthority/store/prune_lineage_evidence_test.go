package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func lineageEvidenceFixture(t testing.TB, renewals []int) (*archivePruneFixture, ArchivePruneInventory, ArchivePruneLineageEvidence) {
	t.Helper()
	p := newArchivePruneFixtureWithRenewals(t, renewals)
	inventory := retainArchiveInventory(t, p)
	evidence, err := PrepareArchivePruneLineageEvidence(context.Background(), inventory, p.inventoryID, p.policyID, p.lineages)
	if err != nil {
		t.Fatal(err)
	}
	return p, inventory, evidence
}

func lineageEvidenceBytes(evidence ArchivePruneLineageEvidence) []byte {
	return bytes.Join(evidence.parts, nil) // small disposable fixtures only
}

func TestPruneLineageEvidenceRoundTripAndExecution(t *testing.T) {
	for _, renewals := range [][]int{{0, 0}, {2, 0}, {2, 1}} {
		p, inventory, evidence := lineageEvidenceFixture(t, renewals)
		before := pruneSnapshot(t, p.f.executor)
		storageBefore, err := p.f.chain.StorageProtection()
		if err != nil {
			t.Fatal(err)
		}
		id, _ := evidence.ID()
		encoded := lineageEvidenceBytes(evidence)
		if id != types.DomainHash(archivePruneLineageEvidenceDomain, encoded) || int64(len(encoded)) != evidence.size {
			t.Fatal("stream hash/framing mismatch")
		}
		p.lineages[0], p.lineages[1] = p.lineages[1], p.lineages[0]
		reordered, err := PrepareArchivePruneLineageEvidence(t.Context(), inventory, p.inventoryID, p.policyID, p.lineages)
		if err != nil || reordered.id != id {
			t.Fatal("caller order changed canonical evidence", err)
		}
		// Preparation and all getters own their buffers, including nested entries.
		for i := range p.lineages {
			p.lineages[i].Manifest[0] ^= 1
			p.lineages[i].Policy.TrustedAuditors[0][0] ^= 1
			for _, entry := range p.lineages[i].Entries {
				entry[0] ^= 1
			}
		}
		copy, err := evidence.Lineages(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		copy[0].Manifest[0] ^= 1
		copy[0].Policy.TrustedAuditors[0][0] ^= 1
		for _, entry := range copy[0].Entries {
			entry[0] ^= 1
		}
		if !bytes.Equal(encoded, lineageEvidenceBytes(evidence)) {
			t.Fatal("public buffer changed immutable evidence")
		}
		path := filepath.Join(t.TempDir(), "renewals.omple")
		for range 2 {
			if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, p.inventoryID, p.policyID, id)
			if err != nil || !bytes.Equal(encoded, lineageEvidenceBytes(loaded)) {
				t.Fatal("file roundtrip", err)
			}
			p.lineages, err = loaded.Lineages(t.Context())
			if err != nil {
				t.Fatal(err)
			}
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatal("evidence file permissions", err)
		}
		storageAfter, err := p.f.chain.StorageProtection()
		if err != nil || !reflect.DeepEqual(storageBefore, storageAfter) || !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
			t.Fatal("preparation/load changed live owners", err)
		}
		if result, err := p.execute(t.Context()); err != nil || !result.Applied {
			t.Fatal("retained lineage did not feed existing guarded executor", err)
		}
		if state := inspectPreparedArchive(t, p); state.ArchiveInventoryID != p.inventoryID {
			t.Fatal("file ID replaced inventory start binding")
		}
		for _, op := range p.operations {
			if testCoordination(t, op.Coordinator).Authority.Pending != 1 {
				t.Fatal("evidence completed a ticket")
			}
		}
	}
}

func TestPruneLineageEvidenceRejectsPreparation(t *testing.T) {
	p, inventory, evidence := lineageEvidenceFixture(t, []int{2, 1})
	before := pruneSnapshot(t, p.f.executor)
	for _, mode := range []string{"inventory-pin", "policy-pin", "zero-pin", "missing", "duplicate", "assignment", "gap", "reorder", "manifest", "initial", "policy", "auditors", "entry-budget", "aggregate-entries", "aggregate-bytes", "empty-entry", "nil-context", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			lineages, _ := evidence.Lineages(t.Context())
			inventoryID, policyID, ctx := p.inventoryID, p.policyID, t.Context()
			switch mode {
			case "inventory-pin":
				inventoryID = testHash(99)
			case "policy-pin":
				policyID = testHash(99)
			case "zero-pin":
				inventoryID = types.Hash{}
			case "missing":
				lineages = lineages[:1]
			case "duplicate":
				lineages[1] = lineages[0]
			case "assignment":
				lineages[0].AssignmentID = testHash(99)
			case "gap":
				lineages[0].Entries = lineages[0].Entries[1:]
			case "reorder":
				lineages[0].Entries[0], lineages[0].Entries[1] = lineages[0].Entries[1], lineages[0].Entries[0]
			case "manifest":
				lineages[0].Manifest[0] ^= 1
			case "initial":
				lineages[0].InitialReceipt = p.replicas[0].Receipt
			case "policy":
				lineages[0].Policy.MaximumProofAge++
			case "auditors":
				lineages[0].Policy.TrustedAuditors = make([][32]byte, custodyauthority.MaximumMembers+1)
			case "entry-budget":
				lineages[0].Entries = make([][]byte, workarchive.MaximumReceiptLineageEntries+1)
			case "aggregate-entries":
				for i := range lineages {
					entry := lineages[i].Entries[0]
					lineages[i].Entries = make([][]byte, 513)
					for j := range lineages[i].Entries {
						lineages[i].Entries[j] = entry
					}
				}
			case "aggregate-bytes":
				chunk := make([]byte, 1<<20)
				for i := range lineages {
					lineages[i].Entries = make([][]byte, 129)
					for j := range lineages[i].Entries {
						lineages[i].Entries[j] = chunk
					}
				}
			case "empty-entry":
				lineages[0].Entries[0] = nil
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			got, err := PrepareArchivePruneLineageEvidence(ctx, inventory, inventoryID, policyID, lineages)
			if err == nil || !got.id.IsZero() {
				t.Fatal("invalid preparation returned usable evidence", err)
			}
		})
	}
	initial := archiveInventoryFixture(t, newArchivePruneFixture(t))
	id, _ := initial.ID()
	policyID, _ := initial.PolicyID()
	if _, err := PrepareArchivePruneLineageEvidence(t.Context(), initial, id, policyID, nil); err == nil {
		t.Fatal("initial-only inventory silently opted into lineage")
	}
	if !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
		t.Fatal("rejection changed executor")
	}
	// Historical load remains possible after completion but cannot authorize it.
	path := filepath.Join(t.TempDir(), "evidence")
	if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, evidence.id); err != nil {
		t.Fatal(err)
	}
	c := p.operations[1].Coordinator
	appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Complete, types.Hash{}, p.operations[1].Binding.TicketID, testHash(98)))
	loaded, err := LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, p.inventoryID, p.policyID, evidence.id)
	if err != nil {
		t.Fatal(err)
	}
	p.lineages, _ = loaded.Lineages(t.Context())
	if result, err := p.execute(t.Context()); err == nil || result.Applied {
		t.Fatal("historical evidence bypassed completed secondary")
	}
}

func TestPruneLineageEvidenceDecoder(t *testing.T) {
	p, inventory, evidence := lineageEvidenceFixture(t, []int{2, 1})
	encoded := lineageEvidenceBytes(evidence)
	decode := func(data []byte, size int64) error {
		_, err := decodeLineageEvidence(t.Context(), bytes.NewReader(data), size, inventory, p.inventoryID, p.policyID,
			types.DomainHash(archivePruneLineageEvidenceDomain, data))
		return err
	}
	for size := 0; size < len(encoded); size++ {
		if size > 160 && size < len(encoded)-64 && size%128 != 0 {
			continue
		}
		if decode(encoded[:size], int64(size)) == nil {
			t.Fatal("truncation accepted", size)
		}
	}
	if decode(append(bytes.Clone(encoded), 0), int64(len(encoded)+1)) == nil || decode(encoded, MaximumArchivePruneLineageEvidenceBytes+1) == nil {
		t.Fatal("trailing or oversized envelope accepted")
	}
	// Rehash mutated bytes deliberately: a self-consistent file hash alone does
	// not replace semantic verification or length/count validation.
	offsets := []int{0, 8, 10, 42, 74, 75, 76}
	offset := 0
	for i, part := range evidence.parts {
		if i > 1 {
			offsets = append(offsets, offset)
		}
		offset += len(part)
	}
	for _, offset := range offsets {
		bad := bytes.Clone(encoded)
		bad[offset] ^= 0xff
		if decode(bad, int64(len(bad))) == nil {
			t.Fatal("self-hashed invalid framing/body accepted", offset)
		}
	}
	// No declared field allocation or body read if the aggregate budget or
	// remaining file length cannot satisfy it, even if the per-object cap can.
	for _, budget := range []int{0, 4, workarchive.MaximumReceiptLineageBytes} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], workarchive.MaximumManifestBytes)
		r := &lineageEvidenceReader{ctx: t.Context(), reader: bytes.NewReader(prefix[:]), remaining: 4}
		if r.body(workarchive.MaximumManifestBytes, &budget) != nil || r.err == nil {
			t.Fatal("allocated absent or over-budget body")
		}
	}
}

func TestPruneLineageEvidencePublication(t *testing.T) {
	p, inventory, evidence := lineageEvidenceFixture(t, []int{2, 1})
	id, _ := evidence.ID()
	for _, stage := range []string{"before-file-sync", "file-synced", "lineage-evidence-published", "lineage-evidence-before-directory-sync", "lineage-evidence-directory-synced"} {
		for _, cancelAtStage := range []bool{false, true} {
			path := filepath.Join(t.TempDir(), "evidence")
			ctx, cancel := context.WithCancel(t.Context())
			fault := errors.New("injected lineage publication failure")
			err := saveArchivePruneLineageEvidenceFile(ctx, path, evidence, id, storeHooks{at: func(at string) error {
				if at == stage {
					if cancelAtStage {
						cancel()
						return nil
					}
					return fault
				}
				return nil
			}})
			cancel()
			want := fault
			if cancelAtStage {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatal("missed publication interruption", stage, err)
			}
			_, err = LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, p.inventoryID, p.policyID, id)
			published := stage != "before-file-sync" && stage != "file-synced"
			if (err == nil) != published {
				t.Fatal("partial/complete evidence misclassified", stage, err)
			}
			if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id); err != nil {
				t.Fatal("exact retry failed", err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal("handled failure leaked temporary", err)
			}
		}
	}
	path := filepath.Join(t.TempDir(), "concurrent")
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	other := cloneInventory(t, inventory)
	other.Policy.ExecutorBindingID = testHash(99)
	otherID, _ := other.ID()
	otherPolicy, _ := other.PolicyID()
	different, err := PrepareArchivePruneLineageEvidence(t.Context(), other, otherID, otherPolicy, p.lineages)
	if err != nil || different.id == id {
		t.Fatal("evidence failed to bind exact inventory/policy", err)
	}
	path = filepath.Join(t.TempDir(), "conflict")
	results := make(chan error, 2)
	go func() { results <- SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id) }()
	go func() { results <- SaveArchivePruneLineageEvidenceFile(t.Context(), path, different, different.id) }()
	if first, second := <-results, <-results; (first == nil) == (second == nil) {
		t.Fatal("conflicting publishers did not retain exactly one winner", first, second)
	}
	_, first := LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, p.inventoryID, p.policyID, id)
	_, second := LoadArchivePruneLineageEvidenceFile(t.Context(), path, other, otherID, otherPolicy, different.id)
	if (first == nil) == (second == nil) {
		t.Fatal("no exact retained winner", first, second)
	}
}

func TestPruneLineageEvidenceFileRejects(t *testing.T) {
	p, inventory, evidence := lineageEvidenceFixture(t, []int{2, 1})
	id, _ := evidence.ID()
	encoded := lineageEvidenceBytes(evidence)
	for _, mode := range []string{"corrupt", "truncated", "trailing", "oversized", "directory", "symlink", "parent-symlink", "missing-parent", "zero-id", "wrong-id", "zero-value", "nil-context", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "evidence")
			ctx, wantID, value := t.Context(), id, evidence
			var preserved []byte
			switch mode {
			case "corrupt":
				preserved = bytes.Clone(encoded)
				preserved[len(preserved)-1] ^= 1
			case "truncated":
				preserved = encoded[:len(encoded)-1]
			case "trailing":
				preserved = append(bytes.Clone(encoded), 0)
			case "oversized":
				file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(MaximumArchivePruneLineageEvidenceBytes + 1)
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink", "parent-symlink":
				target := filepath.Join(t.TempDir(), "target")
				writeTestFile(t, target, encoded)
				if mode == "parent-symlink" {
					target = filepath.Dir(target)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				if mode == "parent-symlink" {
					path = filepath.Join(path, "target")
				}
			case "missing-parent":
				path = filepath.Join(path, "evidence")
			case "zero-id":
				wantID = types.Hash{}
			case "wrong-id":
				wantID = testHash(99)
			case "zero-value":
				value = ArchivePruneLineageEvidence{}
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if preserved != nil {
				writeTestFile(t, path, preserved)
			}
			if err := SaveArchivePruneLineageEvidenceFile(ctx, path, value, wantID); err == nil {
				t.Fatal("invalid save accepted")
			}
			if got, err := LoadArchivePruneLineageEvidenceFile(ctx, path, inventory, p.inventoryID, p.policyID, wantID); err == nil || !got.id.IsZero() {
				t.Fatal("invalid load returned usable evidence", err)
			}
			if preserved != nil {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(preserved, after) {
					t.Fatal("changed rejected destination", err)
				}
			}
		})
	}
	path := filepath.Join(t.TempDir(), "evidence")
	if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id); err != nil {
		t.Fatal(err)
	}
	for _, pins := range [][3]types.Hash{{{}, p.policyID, id}, {p.inventoryID, {}, id}, {p.inventoryID, p.policyID, {}},
		{testHash(99), p.policyID, id}, {p.inventoryID, testHash(99), id}, {p.inventoryID, p.policyID, testHash(99)}} {
		if _, err := LoadArchivePruneLineageEvidenceFile(t.Context(), path, inventory, pins[0], pins[1], pins[2]); err == nil {
			t.Fatal("existing evidence bypassed one of three independent pins")
		}
	}
	info, _ := os.Stat(path)
	if err := SaveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(info, after) {
		t.Fatal("exact retry replaced inode")
	}
	// A named-file replacement after hash verification cannot be acknowledged
	// by syncing the now-unlinked old inode and parent.
	err := saveArchivePruneLineageEvidenceFile(t.Context(), path, evidence, id, storeHooks{at: func(at string) error {
		if at == "lineage-evidence-before-directory-sync" {
			if err := os.Rename(path, path+".original"); err != nil {
				return err
			}
			writeTestFile(t, path, encoded)
		}
		return nil
	}})
	if !errors.Is(err, ErrPruneLineageEvidence) {
		t.Fatal("replacement inode acknowledged", err)
	}
}

type shortLineageWriter struct{}

func (shortLineageWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type cancellingLineageStream struct {
	cancel context.CancelFunc
	bytes  int
}

func (s *cancellingLineageStream) Write(p []byte) (int, error) {
	s.bytes += len(p)
	s.cancel()
	return len(p), nil
}

func (s *cancellingLineageStream) Read(p []byte) (int, error) {
	clear(p)
	s.bytes += len(p)
	s.cancel()
	return len(p), nil
}

func TestPruneLineageEvidenceCancellationAndShortWrite(t *testing.T) {
	if !errors.Is(writeLineageEvidencePart(t.Context(), shortLineageWriter{}, []byte{1}), io.ErrShortWrite) {
		t.Fatal("short write accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(writeLineageEvidencePart(ctx, io.Discard, make([]byte, 128<<10)), context.Canceled) {
		t.Fatal("cancelled stream continued")
	}
	r := &lineageEvidenceReader{ctx: ctx, reader: bytes.NewReader([]byte{1}), remaining: 1}
	if r.fixed(1) != nil || !errors.Is(r.err, context.Canceled) {
		t.Fatal("cancelled read continued")
	}
	if _, err := (ArchivePruneLineageEvidence{}).ID(); err == nil {
		t.Fatal("zero value has usable ID")
	}
	if _, err := (ArchivePruneLineageEvidence{}).Lineages(t.Context()); err == nil {
		t.Fatal("zero value has usable bodies")
	}
	for _, read := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		stream := &cancellingLineageStream{cancel: cancel}
		var err error
		if read {
			r := &lineageEvidenceReader{ctx: ctx, reader: stream, remaining: 128 << 10}
			_ = r.fixed(128 << 10)
			err = r.err
		} else {
			err = writeLineageEvidencePart(ctx, stream, make([]byte, 128<<10))
		}
		cancel()
		if !errors.Is(err, context.Canceled) || stream.bytes != 64<<10 {
			t.Fatal("mid-stream cancellation was not bounded to one chunk", stream.bytes, err)
		}
	}
}
