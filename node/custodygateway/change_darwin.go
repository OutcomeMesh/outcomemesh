//go:build darwin

package custodygateway

import (
	"os"
	"syscall"
)

func changeIdentity(info os.FileInfo) (int64, int64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrOwner
	}
	return s.Ctimespec.Sec, s.Ctimespec.Nsec, nil
}
