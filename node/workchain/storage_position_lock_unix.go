//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package workchain

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func tryPositionLock(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return false, nil
	}
	return err == nil, err
}
