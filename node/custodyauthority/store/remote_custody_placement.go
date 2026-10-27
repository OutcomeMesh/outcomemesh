package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

var ErrRemotePlacement = errors.New("remote custody original placement or private key file changed")

const MaximumRemotePlacementBytes = 128 << 10

type RemoteCustodyPlacementEntry struct {
	Name, Path          string
	Device, Inode, User uint64
	Mode                uint32
	Size                uint64 // Only fixed key/lock files; directory contents may grow.
}

// RemoteCustodyPlacement detects ordinary copies/restores of a selected local
// installation. Its independently retained ID is essential. Native file IDs
// are not hardware attestation, a distributed lease, or fencing of a full VM copy.
type RemoteCustodyPlacement struct {
	Version      uint16
	AssignmentID types.Hash
	Role, Path   string
	Anchor       RemoteCustodyPlacementEntry
	Entries      []RemoteCustodyPlacementEntry
}

type RemoteCustodyPlacementConfig struct {
	Path     string
	ID       types.Hash
	Bindings map[string]string
}

func placementNames(role string) ([]string, error) {
	var names []string
	switch role {
	case "audit":
		names = []string{"authority", "authority-pins", "journal", "artifacts", "authority-key", "auditor-key", "control-key", "key"}
	case "serve":
		names = []string{"worker", "journal", "objects", "replica-key", "control-key", "key"}
	default:
		return nil, ErrRemotePlacement
	}
	sort.Strings(names)
	return names, nil
}

func placementPaths(role string, bindings map[string]string) (map[string]string, error) {
	names, err := placementNames(role)
	if err != nil || len(bindings) != len(names) {
		return nil, ErrRemotePlacement
	}
	paths := make(map[string]string)
	for _, name := range names {
		p, ok := bindings[name]
		if !ok || !filepath.IsAbs(p) || filepath.Clean(p) != p || len(p) > 4096 {
			return nil, ErrRemotePlacement
		}
		paths[name] = p
	}
	locks := map[string]string{"journal": "journal.lock"}
	if role == "audit" {
		locks["authority"] = lockName
		locks["authority-pins"] = intentLockName
		locks["artifacts"] = "custody.lock"
	} else {
		locks["worker"] = "worker.lock"
	}
	for root, name := range locks {
		paths[root+"-lock"] = filepath.Join(paths[root], name)
	}
	return paths, nil
}

func placementEntry(name, path string) (RemoteCustodyPlacementEntry, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return RemoteCustodyPlacementEntry{}, ErrRemotePlacement
	}
	info, err := os.Lstat(path)
	if err != nil {
		return RemoteCustodyPlacementEntry{}, errors.Join(ErrRemotePlacement, err)
	}
	if (!info.IsDir() && !info.Mode().IsRegular()) || info.Mode().Perm()&0o077 != 0 {
		return RemoteCustodyPlacementEntry{}, ErrRemotePlacement
	}
	dev, ino, uid, err := remotePlacementIdentity(info)
	if err != nil || uid != uint64(os.Geteuid()) || ino == 0 {
		return RemoteCustodyPlacementEntry{}, ErrRemotePlacement
	}
	size := uint64(0)
	if info.Mode().IsRegular() {
		size = uint64(info.Size())
	}
	return RemoteCustodyPlacementEntry{Name: name, Path: path, Device: dev, Inode: ino, User: uid, Mode: uint32(info.Mode()), Size: size}, nil
}

// Prepare reads metadata only; it never loads a seed or opens/initializes an
// owner. The anchor parent must already exist outside all selected owner roots
// and key directories. Creation is a separate no-replace publication step.
func PrepareRemoteCustodyPlacement(assignment types.Hash, role, path string, bindings map[string]string) (RemoteCustodyPlacement, error) {
	if assignment.IsZero() || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 {
		return RemoteCustodyPlacement{}, ErrRemotePlacement
	}
	paths, err := placementPaths(role, bindings)
	if err != nil {
		return RemoteCustodyPlacement{}, err
	}
	var ownerRoots []string
	for name, p := range bindings {
		if name != "key" && !strings.HasSuffix(name, "-key") {
			ownerRoots = append(ownerRoots, p)
		}
	}
	for i, p := range ownerRoots {
		for _, q := range ownerRoots[i+1:] {
			if _, _, err := coordinatorPaths(p, q); err != nil {
				return RemoteCustodyPlacement{}, ErrRemotePlacement
			}
		}
	}
	for name, p := range bindings {
		if name == "key" || strings.HasSuffix(name, "-key") {
			for _, root := range ownerRoots {
				if _, _, err := coordinatorPaths(filepath.Dir(p), root); err != nil {
					return RemoteCustodyPlacement{}, ErrRemotePlacement
				}
			}
		}
	}
	anchor, err := placementEntry("anchor", filepath.Dir(path))
	if err != nil || anchor.Mode&uint32(os.ModeDir) == 0 {
		return RemoteCustodyPlacement{}, ErrRemotePlacement
	}
	n := RemoteCustodyPlacement{AssignmentID: assignment, Role: role, Path: path, Anchor: anchor}
	for name, p := range paths {
		entry, err := placementEntry(name, p)
		if err != nil {
			return RemoteCustodyPlacement{}, err
		}
		if name == "key" || name == "control-key" || name == "authority-key" || name == "auditor-key" || name == "replica-key" {
			if entry.Mode&uint32(os.ModeDir) != 0 || entry.Size != 32 {
				return RemoteCustodyPlacement{}, ErrRemotePlacement
			}
		}
		if p == path {
			return RemoteCustodyPlacement{}, ErrRemotePlacement
		}
		protected := p
		if entry.Mode&uint32(os.ModeDir) == 0 {
			protected = filepath.Dir(p)
		}
		if _, _, err := coordinatorPaths(filepath.Dir(path), protected); err != nil {
			return RemoteCustodyPlacement{}, ErrRemotePlacement
		}
		n.Entries = append(n.Entries, entry)
	}
	sort.Slice(n.Entries, func(i, j int) bool { return n.Entries[i].Name < n.Entries[j].Name })
	if _, err := n.CanonicalBytes(); err != nil {
		return RemoteCustodyPlacement{}, err
	}
	return n, nil
}

func (n RemoteCustodyPlacement) CanonicalBytes() ([]byte, error) {
	names, err := placementNames(n.Role)
	if err != nil || n.Version != 0 || n.AssignmentID.IsZero() || len(n.Entries) < len(names) || len(n.Entries) > 16 || n.Anchor.Name != "anchor" || n.Anchor.Path != filepath.Dir(n.Path) || !filepath.IsAbs(n.Path) || filepath.Clean(n.Path) != n.Path || len(n.Path) > 4096 || !utf8.ValidString(n.Path) || strings.ContainsRune(n.Path, 0) {
		return nil, ErrRemotePlacement
	}
	bindings := make(map[string]string)
	for _, name := range names {
		for _, entry := range n.Entries {
			if entry.Name == name {
				bindings[name] = entry.Path
			}
		}
	}
	paths, err := placementPaths(n.Role, bindings)
	if err != nil || len(paths) != len(n.Entries) {
		return nil, ErrRemotePlacement
	}
	for _, entry := range n.Entries {
		if paths[entry.Name] != entry.Path {
			return nil, ErrRemotePlacement
		}
		dir := entry.Name == "authority" || entry.Name == "authority-pins" || entry.Name == "journal" || entry.Name == "artifacts" || entry.Name == "worker" || entry.Name == "objects"
		if dir != (entry.Mode&uint32(os.ModeDir) != 0) || entry.Mode & ^uint32(os.ModeDir|os.ModePerm) != 0 || entry.Mode&0o077 != 0 {
			return nil, ErrRemotePlacement
		}
		if dir && entry.Size != 0 {
			return nil, ErrRemotePlacement
		}
		if !dir {
			expected := uint64(32)
			if len(entry.Name) > 5 && entry.Name[len(entry.Name)-5:] == "-lock" {
				expected = 0
			}
			if entry.Size != expected {
				return nil, ErrRemotePlacement
			}
		}
	}
	if n.Anchor.Mode&uint32(os.ModeDir) == 0 || n.Anchor.Mode & ^uint32(os.ModeDir|os.ModePerm) != 0 || n.Anchor.Size != 0 || n.Anchor.Mode&0o077 != 0 {
		return nil, ErrRemotePlacement
	}
	e := codec.NewEncoder(2048)
	e.Fixed([]byte("OMCRPLC0"))
	e.U16(n.Version)
	e.Fixed(n.AssignmentID[:])
	e.BytesField([]byte(n.Role))
	e.BytesField([]byte(n.Path))
	e.U16(uint16(len(n.Entries)))
	all := append([]RemoteCustodyPlacementEntry{n.Anchor}, n.Entries...)
	for i, v := range all {
		if v.Name == "" || len(v.Name) > 32 || !utf8.ValidString(v.Path) || strings.ContainsRune(v.Path, 0) || !filepath.IsAbs(v.Path) || filepath.Clean(v.Path) != v.Path || len(v.Path) > 4096 || v.Inode == 0 || (i > 1 && all[i-1].Name >= v.Name) {
			return nil, ErrRemotePlacement
		}
		e.BytesField([]byte(v.Name))
		e.BytesField([]byte(v.Path))
		e.U64(v.Device)
		e.U64(v.Inode)
		e.U64(v.User)
		e.U32(v.Mode)
		e.U64(v.Size)
	}
	b := e.Bytes()
	if len(b) > MaximumRemotePlacementBytes {
		return nil, ErrRemotePlacement
	}
	return b, nil
}

func (n RemoteCustodyPlacement) ID() (types.Hash, error) {
	b, err := n.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash("OMESH/local/remote-custody-placement/id/v0", b), nil
}

func DecodeRemoteCustodyPlacement(input []byte) (RemoteCustodyPlacement, error) {
	bad := func() (RemoteCustodyPlacement, error) { return RemoteCustodyPlacement{}, ErrRemotePlacement }
	if len(input) == 0 || len(input) > MaximumRemotePlacementBytes {
		return bad()
	}
	d := codec.NewDecoder(input)
	magic, err := d.Fixed(8)
	if err != nil || !bytes.Equal(magic, []byte("OMCRPLC0")) {
		return bad()
	}
	var n RemoteCustodyPlacement
	n.Version, err = d.U16()
	if err != nil {
		return bad()
	}
	b, err := d.Fixed(types.HashSize)
	if err != nil {
		return bad()
	}
	copy(n.AssignmentID[:], b)
	b, err = d.BytesField(8)
	if err != nil {
		return bad()
	}
	n.Role = string(b)
	b, err = d.BytesField(4096)
	if err != nil {
		return bad()
	}
	n.Path = string(b)
	count, err := d.U16()
	if err != nil || count > 16 {
		return bad()
	}
	for i := 0; i <= int(count); i++ {
		var v RemoteCustodyPlacementEntry
		b, err = d.BytesField(32)
		if err != nil {
			return bad()
		}
		v.Name = string(b)
		b, err = d.BytesField(4096)
		if err != nil {
			return bad()
		}
		v.Path = string(b)
		if v.Device, err = d.U64(); err != nil {
			return bad()
		}
		if v.Inode, err = d.U64(); err != nil {
			return bad()
		}
		if v.User, err = d.U64(); err != nil {
			return bad()
		}
		if v.Mode, err = d.U32(); err != nil {
			return bad()
		}
		if v.Size, err = d.U64(); err != nil {
			return bad()
		}
		if i == 0 {
			n.Anchor = v
		} else {
			n.Entries = append(n.Entries, v)
		}
	}
	if d.Finish() != nil {
		return bad()
	}
	if _, err := n.CanonicalBytes(); err != nil {
		return bad()
	}
	return n, nil
}

func (n RemoteCustodyPlacement) Check() error {
	for _, want := range append([]RemoteCustodyPlacementEntry{n.Anchor}, n.Entries...) {
		got, err := placementEntry(want.Name, want.Path)
		if err != nil || got != want {
			return errors.Join(ErrRemotePlacement, err)
		}
	}
	return nil
}

func PublishRemoteCustodyPlacement(ctx context.Context, n RemoteCustodyPlacement, expected types.Hash) error {
	id, err := n.ID()
	if err != nil || expected.IsZero() || id != expected {
		return ErrRemotePlacement
	}
	if err := n.Check(); err != nil {
		return err
	}
	if info, err := os.Lstat(n.Path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return ErrRemotePlacement
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	b, _ := n.CanonicalBytes()
	return errors.Join(publishCustodyArtifactBytes(ctx, n.Path, b), n.Check())
}

type remotePlacementGuard struct {
	placement RemoteCustodyPlacement
	bytes     []byte
	info      os.FileInfo
}

func openRemotePlacement(c *RemoteCustodyPlacementConfig, assignment types.Hash, role string, roots map[string]string) (*remotePlacementGuard, error) {
	if c == nil {
		return nil, nil
	}
	if c.ID.IsZero() {
		return nil, ErrRemotePlacement
	}
	b, err := readRegular(c.Path, MaximumRemotePlacementBytes)
	if err != nil {
		return nil, err
	}
	n, err := DecodeRemoteCustodyPlacement(b)
	if err != nil {
		return nil, err
	}
	id, _ := n.ID()
	if id != c.ID || n.Path != c.Path || n.Role != role || n.AssignmentID != assignment {
		return nil, ErrRemotePlacement
	}
	paths, err := placementPaths(role, c.Bindings)
	if err != nil || len(paths) != len(n.Entries) {
		return nil, ErrRemotePlacement
	}
	for _, v := range n.Entries {
		if paths[v.Name] != v.Path {
			return nil, ErrRemotePlacement
		}
	}
	for name, path := range roots {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		canonical, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, err
		}
		if c.Bindings[name] != canonical {
			return nil, ErrRemotePlacement
		}
	}
	current, err := PrepareRemoteCustodyPlacement(assignment, role, c.Path, c.Bindings)
	if err != nil {
		return nil, err
	}
	currentID, err := current.ID()
	if err != nil || currentID != c.ID {
		return nil, ErrRemotePlacement
	}
	info, err := os.Lstat(c.Path)
	if err != nil {
		return nil, err
	}
	g := &remotePlacementGuard{placement: n, bytes: b, info: info}
	return g, g.check()
}

func CheckRemoteCustodyPlacement(c *RemoteCustodyPlacementConfig, assignment types.Hash, role string) error {
	if c == nil {
		return ErrRemotePlacement
	}
	_, err := openRemotePlacement(c, assignment, role, nil)
	return err
}

func (g *remotePlacementGuard) check() error {
	if g == nil {
		return nil
	}
	info, err := os.Lstat(g.placement.Path)
	if err != nil || !os.SameFile(g.info, info) || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return ErrRemotePlacement
	}
	b, err := readRegular(g.placement.Path, MaximumRemotePlacementBytes)
	if err != nil || !bytes.Equal(b, g.bytes) {
		return ErrRemotePlacement
	}
	return g.placement.Check()
}
