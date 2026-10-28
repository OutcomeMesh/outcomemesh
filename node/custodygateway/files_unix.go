//go:build linux || darwin

package custodygateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/outcomemesh/outcomemesh/core/types"
	"golang.org/x/sys/unix"
)

var ErrOwner = errors.New("custody gateway owner blocked")

// PlacementID pins canonical paths and native identities. It is a local
// replacement detector, not an uncloneable hardware identity.
func PlacementID(path string, directory bool) (types.Hash, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return types.Hash{}, ErrOwner
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return types.Hash{}, ErrOwner
	}
	st, e := os.Lstat(path)
	if e != nil || st.IsDir() != directory || !directory && !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return types.Hash{}, ErrOwner
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || !directory && native.Nlink != 1 {
		return types.Hash{}, ErrOwner
	}
	// A participant must not be able to replace an ancestor. Root-owned sticky
	// temporary directories are permitted; private descendants still pin the leaf.
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, e := os.Lstat(parent)
		if e != nil || !info.IsDir() {
			return types.Hash{}, ErrOwner
		}
		v, ok := info.Sys().(*syscall.Stat_t)
		if !ok || v.Uid != 0 && v.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 && !(v.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return types.Hash{}, ErrOwner
		}
		if parent == "/" {
			break
		}
	}
	var sec, ns int64
	if !directory {
		sec, ns, e = changeIdentity(st)
		if e != nil {
			return types.Hash{}, e
		}
	}
	raw := fmt.Sprintf("%s\n%d/%d/%d/%d/%d/%d", path, native.Dev, native.Ino, native.Uid, st.Mode(), sec, ns)
	return types.DomainHash("OMESH/custody-gateway/v1/placement", []byte(raw)), nil
}
func privateRead(path string, limit int) ([]byte, error) {
	if _, e := PlacementID(path, false); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	a, e := f.Stat()
	b, e2 := os.Lstat(path)
	if e != nil || e2 != nil || !os.SameFile(a, b) || a.Size() > int64(limit) {
		return nil, ErrOwner
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(raw) > limit {
		return nil, ErrOwner
	}
	return raw, nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}

// publish never replaces evidence. A partial named file after a crash blocks
// reopening; no reset, truncation or automatic deletion is provided.
func publish(path string, raw []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	e = errors.Join(e, f.Sync(), f.Close())
	if e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func lockExisting(path string) (*os.File, error) {
	if _, e := PlacementID(path, false); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.Join(ErrOwner, e)
	}
	return f, nil
}
func strictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrOwner
	}
	return nil
}
