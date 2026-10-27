//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package custodyfence

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
)

func lockWitness(file *os.File) error {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
		return ErrBusy
	}
	return err
}
