//go:build darwin || linux

package custodyregistry

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func witnessLock(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return ErrRegistry
	}
	return err
}

func witnessStampFile(info os.FileInfo) (witnessStamp, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return witnessStamp{}, ErrRegistry
	}
	return witnessStamp{Device: uint64(stat.Dev), Inode: stat.Ino, User: stat.Uid, Mode: uint32(info.Mode())}, nil
}
