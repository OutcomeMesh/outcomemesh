package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func archiveInventoryFixture(t testing.TB, p *archivePruneFixture) ArchivePruneInventory {
	t.Helper()
	inventory := ArchivePruneInventory{Request: p.f.request, Policy: p.policy, Availability: workarchive.AvailabilityBundle{
		StatementID: p.f.request.Boundary.StatementID, ManifestID: p.f.request.Boundary.ManifestID, AnchorID: p.f.request.Boundary.Anchor.ID}}
	if p.lineages != nil {
		inventory.Mode = ArchivePruneLineage
	}
	for _, replica := range p.replicas {
		inventory.Availability.Receipts = append(inventory.Availability.Receipts, replica.Receipt)
	}
	resignArchiveInventory(t, &inventory)
	for i, entry := range inventory.Admissions {
		id, _ := entry.ID()
		if id != p.operations[i].Binding.TicketID {
			t.Fatal("fixture did not retain original admission")
		}
	}
	return cloneInventory(t, inventory)
}

// Fresh local TEST signatures let semantic rejection tests get past signature
// validation. This is not an admission API and never appends to an authority.
func resignArchiveInventory(t testing.TB, inventory *ArchivePruneInventory) {
	t.Helper()
	id, err := inventory.Request.ID()
	if err != nil {
		t.Fatal(err)
	}
	inventory.Policy.RequestID = id
	inventory.Admissions = nil
	for _, assignment := range inventory.Policy.Assignments {
		aid, err := assignment.ID()
		if err != nil {
			t.Fatal(err)
		}
		command, err := (custodyauthority.Command{AssignmentID: aid, ExpectedHead: aid, Kind: custodyauthority.Admit,
			Purpose: custodyauthority.Prune, OperationID: id}).Sign(testKey(4))
		if err != nil {
			t.Fatal(err)
		}
		entry, err := custodyauthority.SignEntry(command, testKey(1))
		if err != nil {
			t.Fatal(err)
		}
		inventory.Admissions = append(inventory.Admissions, entry)
	}
}

func cloneInventory(t testing.TB, inventory ArchivePruneInventory) ArchivePruneInventory {
	t.Helper()
	encoded, err := inventory.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	clone, err := DecodeArchivePruneInventory(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return clone
}

func TestArchivePruneInventoryRoundTripBothModes(t *testing.T) {
	for _, lineage := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "lineage"}[lineage], func(t *testing.T) {
			var p *archivePruneFixture
			if lineage {
				p = newArchivePruneFixtureWithRenewals(t, []int{2, 1})
			} else {
				p = newArchivePruneFixture(t)
			}
			inventory := archiveInventoryFixture(t, p)
			before := pruneSnapshot(t, p.f.executor)
			storageBefore, err := p.f.chain.StorageProtection()
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := inventory.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := inventory.ID()
			decoded := cloneInventory(t, inventory)
			again, _ := decoded.CanonicalBytes()
			if !bytes.Equal(encoded, again) || !reflect.DeepEqual(inventory, decoded) || decoded.Verify(id, p.policyID) != nil {
				t.Fatal("roundtrip or independent pins")
			}
			if lineage {
				wrongMode := inventory
				wrongMode.Mode = ArchivePruneInitial
				if _, err := wrongMode.CanonicalBytes(); err == nil {
					t.Fatal("renewal package accepted as initial-only")
				}
			}
			path := filepath.Join(t.TempDir(), "prepared.ompi")
			for range 2 {
				if err := SaveArchivePruneInventoryFile(path, inventory, id, p.policyID); err != nil {
					t.Fatal(err)
				}
				loaded, err := LoadArchivePruneInventoryFile(path, id, p.policyID)
				if err != nil || !reflect.DeepEqual(inventory, loaded) {
					t.Fatal("file roundtrip", err)
				}
			}
			for _, pins := range [][2]types.Hash{{{}, p.policyID}, {id, {}}, {testHash(99), p.policyID}, {id, testHash(99)}} {
				if decoded.Verify(pins[0], pins[1]) == nil {
					t.Fatal("wrong independent pins accepted")
				}
				if _, err := LoadArchivePruneInventoryFile(path, pins[0], pins[1]); err == nil {
					t.Fatal("existing package bypassed load pins")
				}
				if err := SaveArchivePruneInventoryFile(path, decoded, pins[0], pins[1]); err == nil {
					t.Fatal("existing package bypassed publication pins")
				}
			}
			storageAfter, err := p.f.chain.StorageProtection()
			if err != nil || !reflect.DeepEqual(storageBefore, storageAfter) || !reflect.DeepEqual(before, pruneSnapshot(t, p.f.executor)) {
				t.Fatal("preparation changed an execution owner")
			}
			for _, operation := range p.operations {
				state := testCoordination(t, operation.Coordinator)
				if state.Pending != nil || state.Authority.Pending != 1 || state.Authority.Sequence != 1 {
					t.Fatal("preparation changed an authority")
				}
			}
			// A prepared package remains historical after a ticket completes. It
			// is intentionally not a live-authority or execution-success check.
			c := p.operations[1].Coordinator
			appendCoordinated(t, c, testEntry(t, testCoordination(t, c).Authority, custodyauthority.Complete,
				types.Hash{}, p.operations[1].Binding.TicketID, testHash(98)))
			if _, err := LoadArchivePruneInventoryFile(path, id, p.policyID); err != nil {
				t.Fatal("historical package acquired live-owner semantics", err)
			}
			if _, err := p.execute(t.Context()); err == nil {
				t.Fatal("historical inventory bypassed completed secondary ticket")
			}
		})
	}
}

func TestArchivePruneInventoryRejectsSubstitutions(t *testing.T) {
	p := newArchivePruneFixture(t)
	good := archiveInventoryFixture(t, p)
	for name, mutate := range map[string]func(*ArchivePruneInventory){
		"version":              func(v *ArchivePruneInventory) { v.Version = 1 },
		"mode":                 func(v *ArchivePruneInventory) { v.Mode = 2 },
		"missing-admission":    func(v *ArchivePruneInventory) { v.Admissions = v.Admissions[:1] },
		"duplicate-admission":  func(v *ArchivePruneInventory) { v.Admissions[1] = v.Admissions[0] },
		"reordered-admissions": func(v *ArchivePruneInventory) { v.Admissions[0], v.Admissions[1] = v.Admissions[1], v.Admissions[0] },
		"missing-replica":      func(v *ArchivePruneInventory) { v.Availability.Receipts = v.Availability.Receipts[:1] },
		"reordered-replicas": func(v *ArchivePruneInventory) {
			v.Availability.Receipts[0], v.Availability.Receipts[1] = v.Availability.Receipts[1], v.Availability.Receipts[0]
		},
		"reordered-assignments": func(v *ArchivePruneInventory) {
			v.Policy.Assignments[0], v.Policy.Assignments[1] = v.Policy.Assignments[1], v.Policy.Assignments[0]
		},
		"command-signature":    func(v *ArchivePruneInventory) { v.Admissions[1].Command.Signature[0] ^= 1 },
		"authority-signature":  func(v *ArchivePruneInventory) { v.Admissions[1].Signature[0] ^= 1 },
		"receipt-signature":    func(v *ArchivePruneInventory) { v.Availability.Receipts[1].Signature[0] ^= 1 },
		"checkpoint-signature": func(v *ArchivePruneInventory) { v.Policy.Checkpoint.Attestations[0].Signature[0] ^= 1 },
		"policy-binding":       func(v *ArchivePruneInventory) { v.Policy.CheckpointPolicy.Binding.NetworkID++ },
		"no-storage":           func(v *ArchivePruneInventory) { v.Request.StorageID = types.Hash{} },
		"no-executor-pair":     func(v *ArchivePruneInventory) { v.Policy.ExecutorBindingID = types.Hash{} },
		"no-storage-pair":      func(v *ArchivePruneInventory) { v.Policy.StoragePairID = types.Hash{} },
		"request-pin":          func(v *ArchivePruneInventory) { v.Policy.RequestID = testHash(99) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneInventory(t, good)
			mutate(&bad)
			if _, err := bad.CanonicalBytes(); err == nil {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
	for _, mode := range []string{"anchor", "ancestry", "availability", "retention", "future-receipt", "expired-receipt", "primary", "initial", "secondary-consumer", "secondary-operation", "secondary-purpose", "secondary-actor", "secondary-authority"} {
		t.Run(mode, func(t *testing.T) {
			bad := cloneInventory(t, good)
			switch mode {
			case "anchor":
				bad.Request.Boundary.Anchor.ID = testHash(99)
			case "ancestry":
				bad.Request.Boundary.AncestryRoot = testHash(99)
			case "availability":
				bad.Request.Boundary.AvailabilityID = testHash(99)
			case "retention":
				bad.Request.Boundary.RetainUntil++
			case "future-receipt":
				bad.Request.Boundary.VerifiedAt--
			case "expired-receipt":
				bad.Request.Boundary.VerifiedAt += 1_001
			case "primary":
				bad.Request.AssignmentID = testHash(99)
			case "initial":
				bad.Policy.Assignments[1].InitialReceiptID = testHash(99)
			case "secondary-consumer":
				bad.Policy.Assignments[1].Consumers[0].PublicKey = testPublic(5)
			}
			resignArchiveInventory(t, &bad)
			command := bad.Admissions[1].Command
			actor, authority := testKey(4), testKey(1)
			switch mode {
			case "secondary-operation":
				command.OperationID = testHash(99)
			case "secondary-purpose":
				command.Purpose = custodyauthority.Serve
			case "secondary-actor":
				actor = testKey(5)
				command.ActorPublicKey = [32]byte{}
			case "secondary-authority":
				authority = testKey(9)
			}
			command, err := command.Sign(actor)
			if err != nil {
				t.Fatal(err)
			}
			bad.Admissions[1], err = custodyauthority.SignEntry(command, authority)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bad.CanonicalBytes(); err == nil {
				t.Fatal("semantically unrelated but signed inventory accepted")
			}
		})
	}
}

func TestArchivePruneInventoryCodecBoundsAndDetachment(t *testing.T) {
	good := archiveInventoryFixture(t, newArchivePruneFixture(t))
	encoded, _ := good.CanonicalBytes()
	for _, input := range [][]byte{nil, append(bytes.Clone(encoded), 0), make([]byte, MaximumArchivePruneInventoryBytes+1),
		append(bytes.Clone(encoded[:12]), 0xff, 0xff, 0xff, 0x7f)} {
		if _, err := DecodeArchivePruneInventory(input); err == nil {
			t.Fatal("accepted malformed framing")
		}
	}
	for _, n := range []int{0, 8, 9, 10, 11, 12, 13, 100, len(encoded) / 2, len(encoded) - 1} {
		if _, err := DecodeArchivePruneInventory(encoded[:n]); err == nil {
			t.Fatal("accepted truncated package", n)
		}
	}
	for _, offset := range []int{0, 8, 9, 10} {
		bad := bytes.Clone(encoded)
		bad[offset] = 0xff
		if _, err := DecodeArchivePruneInventory(bad); err == nil {
			t.Fatal("accepted envelope mutation", offset)
		}
	}
	for _, count := range []uint64{65, ^uint64(0)} {
		e := codec.NewEncoder(16)
		e.Uvarint(count)
		if _, err := decodeInventoryKeys(codec.NewDecoder(e.Bytes())); err == nil {
			t.Fatal("unbounded key count")
		}
	}
	if _, err := decodeInventoryKeys(codec.NewDecoder([]byte{64})); err == nil {
		t.Fatal("allocated missing key bytes")
	}
	decoded, err := DecodeArchivePruneInventory(encoded)
	if err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	if _, err := decoded.CanonicalBytes(); err != nil {
		t.Fatal("decoder retained input buffer", err)
	}
	decoded.Policy.Assignments[0].Consumers[0].Purposes ^= custodyauthority.Prune
	decoded.Policy.Checkpoint.Attestations[0].Signature[0] ^= 1
	decoded.Policy.CheckpointPolicy.TrustedAttestors[0][0] ^= 1
	decoded.Policy.ReplicaPolicy.TrustedReplicas[0][0] ^= 1
	decoded.Request.Boundary.Anchor.CumulativeWork[0] ^= 1
	if _, err := good.CanonicalBytes(); err != nil {
		t.Fatal("decoder retained caller-owned slices", err)
	}
	// Declaring lineage on an initial-only package changes BOTH independent IDs.
	id, _ := good.ID()
	policyID, _ := good.PolicyID()
	good.Mode = ArchivePruneLineage
	newID, err := good.ID()
	newPolicy, _ := good.PolicyID()
	if err != nil || id == newID || policyID == newPolicy || good.Verify(id, newPolicy) == nil || good.Verify(newID, policyID) == nil {
		t.Fatal("mode pins were interchangeable", err)
	}
}

func TestArchivePruneInventoryPublication(t *testing.T) {
	good := archiveInventoryFixture(t, newArchivePruneFixture(t))
	id, _ := good.ID()
	policyID, _ := good.PolicyID()
	encoded, _ := good.CanonicalBytes()
	for _, mode := range []string{"corrupt", "truncated", "oversized", "different", "symlink", "directory", "wrong-id", "wrong-policy", "zero-id", "zero-policy", "missing-parent"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory")
			wantID, wantPolicy := id, policyID
			var preserved []byte
			switch mode {
			case "corrupt":
				preserved = bytes.Clone(encoded)
				preserved[len(preserved)-1] ^= 1
			case "truncated":
				preserved = encoded[:len(encoded)-1]
			case "oversized":
				preserved = make([]byte, MaximumArchivePruneInventoryBytes+1)
			case "different":
				other := cloneInventory(t, good)
				other.Mode = ArchivePruneLineage
				preserved, _ = other.CanonicalBytes()
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				writeTestFile(t, target, encoded)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "wrong-id":
				wantID = testHash(99)
			case "wrong-policy":
				wantPolicy = testHash(99)
			case "zero-id":
				wantID = types.Hash{}
			case "zero-policy":
				wantPolicy = types.Hash{}
			case "missing-parent":
				path = filepath.Join(path, "missing", "inventory")
			}
			if preserved != nil {
				writeTestFile(t, path, preserved)
			}
			if err := SaveArchivePruneInventoryFile(path, good, wantID, wantPolicy); err == nil {
				t.Fatal("invalid publication accepted")
			}
			if _, err := LoadArchivePruneInventoryFile(path, wantID, wantPolicy); err == nil {
				t.Fatal("invalid load accepted")
			}
			if preserved != nil {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, preserved) {
					t.Fatal("destination replaced", err)
				}
			}
		})
	}
	for _, stage := range []string{"before-file-sync", "file-synced", "inventory-published", "inventory-before-directory-sync", "inventory-directory-synced"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "inventory")
			fault := errors.New("injected publication interruption")
			err := saveArchivePruneInventoryFile(path, good, id, policyID, storeHooks{at: func(at string) error {
				if at == stage {
					return fault
				}
				return nil
			}})
			if !errors.Is(err, fault) {
				t.Fatal("fault missed", err)
			}
			_, err = LoadArchivePruneInventoryFile(path, id, policyID)
			published := stage != "before-file-sync" && stage != "file-synced"
			if (err == nil) != published {
				t.Fatal("partial file was accepted or exact publication lost", err)
			}
			if err := SaveArchivePruneInventoryFile(path, good, id, policyID); err != nil {
				t.Fatal("exact retry failed", err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal("handled fault leaked temporary file", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "race")
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if err := SaveArchivePruneInventoryFile(path, good, id, policyID); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if _, err := LoadArchivePruneInventoryFile(path, id, policyID); err != nil {
		t.Fatal(err)
	}
	// Two valid but different packages cannot both replace the same name.
	path = filepath.Join(t.TempDir(), "conflicting-publishers")
	other := cloneInventory(t, good)
	other.Mode = ArchivePruneLineage
	otherID, _ := other.ID()
	otherPolicy, _ := other.PolicyID()
	results := make(chan error, 2)
	go func() { results <- SaveArchivePruneInventoryFile(path, good, id, policyID) }()
	go func() { results <- SaveArchivePruneInventoryFile(path, other, otherID, otherPolicy) }()
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatal("conflicting publishers did not choose exactly one complete package", first, second)
	}
	_, initialErr := LoadArchivePruneInventoryFile(path, id, policyID)
	_, lineageErr := LoadArchivePruneInventoryFile(path, otherID, otherPolicy)
	if (initialErr == nil) == (lineageErr == nil) {
		t.Fatal("published package was neither exact winner")
	}
}

func FuzzDecodeArchivePruneInventory(f *testing.F) {
	good := fixedArchivePruneInventory(f)
	for _, mode := range []ArchivePruneMode{ArchivePruneInitial, ArchivePruneLineage} {
		good.Mode = mode
		encoded, err := good.CanonicalBytes()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		inventory, err := DecodeArchivePruneInventory(input)
		if err != nil {
			return
		}
		encoded, err := inventory.CanonicalBytes()
		if err != nil || !bytes.Equal(encoded, input) {
			t.Fatal("noncanonical prepared inventory")
		}
		id, _ := inventory.ID()
		policyID, _ := inventory.PolicyID()
		if id.IsZero() || inventory.Verify(id, policyID) != nil {
			t.Fatal("lost inventory commitment")
		}
	})
}
