package custodyregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type witnessStamp struct {
	Device, Inode uint64
	User, Mode    uint32
}

func witnessCanonical(path string) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return "", ErrRegistry
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil || !utf8.ValidString(parent) {
		return "", errors.Join(ErrRegistry, err)
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

func witnessPrivate(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0
}

func witnessRead(path string, maximum int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !witnessPrivate(info) || info.Size() > int64(maximum) {
		return nil, ErrRegistry
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(info, held) {
		return nil, errors.Join(ErrRegistry, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if len(raw) > maximum {
		return nil, ErrRegistry
	}
	return raw, err
}

func witnessSyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// Records are immutable. A failed publish is an unknown write, including a full
// file left before sync. Only cold validated open may stabilize such bytes.
func witnessPublish(dir, name string, raw []byte, hook func(string) error) (returnErr error) {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		old, err := witnessRead(path, len(raw))
		if err != nil || !bytes.Equal(old, raw) {
			return errors.Join(ErrRegistry, err)
		}
		f, err = os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		n, err := f.Write(raw)
		if err != nil || n != len(raw) {
			_ = f.Close()
			return errors.Join(io.ErrShortWrite, err)
		}
	}
	defer func() { returnErr = errors.Join(returnErr, f.Close()) }()
	if hook != nil {
		if err := hook(name + "-before-sync"); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := witnessSyncDir(dir); err != nil {
		return err
	}
	if hook != nil {
		return hook(name + "-durable")
	}
	return nil
}

func witnessPlacement(path string) ([]byte, error) {
	stamps := map[string]witnessStamp{}
	for _, p := range []string{path, filepath.Join(path, "owner.lock")} {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(ErrRegistry, err)
		}
		stamp, err := witnessStampFile(info)
		if err != nil {
			return nil, err
		}
		stamps[p] = stamp
	}
	return json.Marshal(stamps)
}
