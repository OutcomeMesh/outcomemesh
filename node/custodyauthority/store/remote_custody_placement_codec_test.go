package store

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Codec fixtures contain synthetic native identities and grant no placement.
func placementCodecSeed(t testing.TB) []byte {
	t.Helper()
	base := filepath.Join(os.TempDir(), "omesh-placement-codec")
	bindings := map[string]string{}
	names, err := placementNames("audit")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		bindings[name] = filepath.Join(base, name)
	}
	paths, err := placementPaths("audit", bindings)
	if err != nil {
		t.Fatal(err)
	}
	n := RemoteCustodyPlacement{AssignmentID: testHash(201), Role: "audit", Path: filepath.Join(base, "anchor", "placement"), Anchor: RemoteCustodyPlacementEntry{Name: "anchor", Path: filepath.Join(base, "anchor"), Device: 1, Inode: 1, User: 1, Mode: uint32(os.ModeDir | 0o700)}}
	for name, path := range paths {
		mode, size := uint32(os.ModeDir|0o700), uint64(0)
		if name == "key" || strings.HasSuffix(name, "-key") {
			mode, size = 0o600, 32
		} else if strings.HasSuffix(name, "-lock") {
			mode = 0o600
		}
		n.Entries = append(n.Entries, RemoteCustodyPlacementEntry{Name: name, Path: path, Device: 1, Inode: 2, User: 1, Mode: mode, Size: size})
	}
	sort.Slice(n.Entries, func(i, j int) bool { return n.Entries[i].Name < n.Entries[j].Name })
	b, err := n.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func FuzzDecodeRemoteCustodyPlacement(f *testing.F) {
	f.Add(placementCodecSeed(f))
	f.Add([]byte("OMCRPLC0"))
	f.Fuzz(func(t *testing.T, input []byte) {
		n, err := DecodeRemoteCustodyPlacement(input)
		if err != nil {
			return
		}
		got, err := n.CanonicalBytes()
		if err != nil || !bytes.Equal(got, input) {
			t.Fatal("noncanonical placement", err)
		}
	})
}
