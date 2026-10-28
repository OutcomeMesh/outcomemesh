//go:build darwin || linux

package custodycutover

import (
	"errors"
	"os"
	"syscall"
)

func lockPreparation(f *os.File) error {
	if e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.Join(ErrPreparation, e)
	}
	return nil
}
