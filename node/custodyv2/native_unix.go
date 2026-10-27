//go:build darwin || linux

package custodyv2

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func lockRoot(f *os.File) error {
	e := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(e, unix.EWOULDBLOCK) || errors.Is(e, unix.EINTR) {
		return ErrProtocol
	}
	return e
}
func stampFile(i os.FileInfo) (fileStamp, error) {
	s, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStamp{}, ErrProtocol
	}
	return fileStamp{Device: uint64(s.Dev), Inode: s.Ino, User: s.Uid, Mode: uint32(i.Mode())}, nil
}
func nilContext() context.Context { return context.Background() }
