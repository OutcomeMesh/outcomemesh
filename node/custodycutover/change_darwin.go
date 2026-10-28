//go:build darwin

package custodycutover

import (
	"os"
	"syscall"
)

func lockChangeIdentity(info os.FileInfo) (int64, int64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrPreparation
	}
	return s.Ctimespec.Sec, s.Ctimespec.Nsec, nil
}
