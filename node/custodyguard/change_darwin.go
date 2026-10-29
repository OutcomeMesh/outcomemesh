//go:build darwin

package custodyguard

import (
	"os"
	"syscall"
)

func changeIdentity(info os.FileInfo) (int64, int64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrStore
	}
	return s.Ctimespec.Sec, s.Ctimespec.Nsec, nil
}
