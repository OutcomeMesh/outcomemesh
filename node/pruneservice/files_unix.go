//go:build linux || darwin

package pruneservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodygateway"
	"golang.org/x/sys/unix"
)

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// A partial named artifact remains evidence. No overwrite, truncation or
// automatic cleanup is used to turn an uncertain publication into a retry.
// ownerHooks are private fault seams. No option, environment variable or peer
// input can install them in an ordinary binary.
type ownerHooks struct {
	at    func(string) error
	write func(*os.File, []byte) (int, error)
}

func (h ownerHooks) reach(stage string) error {
	if h.at != nil {
		return h.at(stage)
	}
	return nil
}
func publish(path string, raw []byte) error { return publishWithHooks(path, raw, ownerHooks{}, "") }
func publishWithHooks(path string, raw []byte, h ownerHooks, stage string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	return syncPublication(f, path, raw, h, stage)
}
func syncPublication(f *os.File, path string, raw []byte, h ownerHooks, stage string) (returnErr error) {
	defer func() { returnErr = errors.Join(returnErr, f.Close()) }()
	if err := h.reach(stage + "-created"); err != nil {
		return err
	}
	write := f.Write
	if h.write != nil {
		write = func(b []byte) (int, error) { return h.write(f, b) }
	}
	n, err := write(raw)
	if n != len(raw) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	if err != nil {
		return err
	}
	if err = h.reach(stage + "-written"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = h.reach(stage + "-file-synced"); err != nil {
		return err
	}
	if err = syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return h.reach(stage + "-durable")
}

func privateRead(path string, limit int) ([]byte, error) {
	before, err := custodygateway.PlacementID(path, false)
	if err != nil {
		return nil, errors.Join(ErrOwner, err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	a, e1 := f.Stat()
	b, e2 := os.Lstat(path)
	if e1 != nil || e2 != nil || !os.SameFile(a, b) || a.Size() > int64(limit) {
		return nil, ErrOwner
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	after, e2 := custodygateway.PlacementID(path, false)
	if err != nil || e2 != nil || before != after || len(raw) > limit {
		return nil, ErrOwner
	}
	return raw, nil
}

func lockRoot(root string) (*os.File, error) {
	path := filepath.Join(root, "lock")
	before, err := custodygateway.PlacementID(path, false)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.Join(ErrOwner, err)
	}
	a, e1 := f.Stat()
	b, e2 := os.Lstat(path)
	after, e3 := custodygateway.PlacementID(path, false)
	if e1 != nil || e2 != nil || e3 != nil || before != after || !os.SameFile(a, b) || a.Size() != 0 {
		f.Close()
		return nil, ErrOwner
	}
	return f, nil
}

func rootID(root string) (types.Hash, error) {
	var raw []byte
	for _, v := range []struct {
		path string
		dir  bool
	}{{root, true}, {filepath.Join(root, "lock"), false}, {filepath.Join(root, "key"), false}, {filepath.Join(root, "transport-key"), false}, {filepath.Join(root, "events"), true}} {
		id, err := custodygateway.PlacementID(v.path, v.dir)
		if err != nil {
			return types.Hash{}, err
		}
		raw = append(raw, id[:]...)
	}
	return types.DomainHash(domain+"root/v0", raw), nil
}

func CreateIdentity(root string) (id Identity, returnErr error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return id, ErrOwner
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return id, err
	}
	if _, err := custodygateway.PlacementID(root, true); err != nil {
		return id, err
	}
	if err := publish(filepath.Join(root, "lock"), nil); err != nil {
		return id, err
	}
	lock, err := lockRoot(root)
	if err != nil {
		return id, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if err = os.Mkdir(filepath.Join(root, "events"), 0700); err != nil {
		return id, err
	}
	for i, name := range []string{"key", "transport-key"} {
		pub, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return id, e
		}
		err = publish(filepath.Join(root, name), key)
		clear(key)
		if err != nil {
			return id, err
		}
		if i == 0 {
			copy(id.Service[:], pub)
		} else {
			copy(id.Transport[:], pub)
		}
	}
	id.OwnerUID = uint32(os.Geteuid())
	id.RootID, err = rootID(root)
	if err != nil {
		return id, err
	}
	raw, _ := json.Marshal(id)
	if err = publish(filepath.Join(root, "identity"), raw); err != nil {
		return id, err
	}
	return id, syncDirectory(filepath.Dir(root))
}

func readKey(path string) (ed25519.PrivateKey, error) {
	raw, err := privateRead(path, ed25519.PrivateKeySize)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		clear(raw)
		return nil, ErrOwner
	}
	key := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
	defer clear(key)
	if !bytes.Equal(key, raw) {
		clear(raw)
		return nil, ErrOwner
	}
	return ed25519.PrivateKey(raw), nil
}

func ReadIdentity(root string) (Identity, error) {
	var id Identity
	raw, err := privateRead(filepath.Join(root, "identity"), 1024)
	if err != nil {
		return id, err
	}
	if err = json.Unmarshal(raw, &id); err != nil {
		return Identity{}, err
	}
	canonical, _ := json.Marshal(id)
	actual, err := rootID(root)
	if err != nil || actual != id.RootID || id.OwnerUID != uint32(os.Geteuid()) || !bytes.Equal(raw, canonical) {
		return Identity{}, ErrOwner
	}
	for i, name := range []string{"key", "transport-key"} {
		key, e := readKey(filepath.Join(root, name))
		if e != nil {
			return Identity{}, e
		}
		want := id.Service
		if i == 1 {
			want = id.Transport
		}
		ok := bytes.Equal(key[32:], want[:])
		clear(key)
		if !ok {
			return Identity{}, ErrOwner
		}
	}
	return id, nil
}

func nested(a, b string) bool {
	r, e := filepath.Rel(a, b)
	return e == nil && (r == "." || r != ".." && !bytes.HasPrefix([]byte(r), []byte(".."+string(filepath.Separator))))
}

// The root is private even when a storage engine creates readable descendants.
// Every descendant must still belong to the owner, be non-writable by others,
// and have no alternate hard-link or symlink route from a participant account.
func privateTree(path string) error {
	return privateTreeContext(context.Background(), path)
}

func privateTreeContext(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if _, err = custodygateway.PlacementID(path, st.IsDir()); err != nil {
		return err
	}
	return filepath.WalkDir(path, func(p string, d os.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		i, err := d.Info()
		if err != nil {
			return err
		}
		n, ok := i.Sys().(*syscall.Stat_t)
		if !ok || n.Uid != uint32(os.Geteuid()) || i.Mode().Perm()&0022 != 0 || (!i.IsDir() && (!i.Mode().IsRegular() || n.Nlink != 1)) {
			return ErrOwner
		}
		return nil
	})
}

func validatePlacement(ctx context.Context, root string, c Config) error {
	for _, path := range originalPaths(c) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || nested(root, path) || nested(path, root) {
			return ErrOwner
		}
		if err := privateTreeContext(ctx, path); err != nil {
			return err
		}
	}
	return nil
}
