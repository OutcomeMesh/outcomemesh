//go:build linux || darwin

package keystore

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
)

// ReadPrivate rejects links, devices, group/world access, and oversized files.
// The descriptor is checked after O_NOFOLLOW|O_NONBLOCK open to avoid path races
// and blocking on a FIFO. Parent directory ownership remains the operator's duty.
func ReadPrivate(path string, maximum int) ([]byte, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > int64(maximum) {
		return nil, errors.New("private file must be regular, mode 0600 or stricter, and within size limit")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if e != nil || len(b) > maximum {
		clear(b)
		return nil, ErrKey
	}
	return b, nil
}

// WriteNew never replaces a key, even after a partial write. An error leaves
// the file for explicit inspection; callers must not assume it is durable.
func WriteNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
