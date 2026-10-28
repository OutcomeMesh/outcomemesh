package custodyv2

import (
	"os"
	"syscall"
)

func importedLockChange(info os.FileInfo) (int64, int64, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrAdmission
	}
	return s.Ctimespec.Sec, s.Ctimespec.Nsec, nil
}
