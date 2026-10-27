//go:build darwin || linux

package store

import (
	"os"
	"syscall"
)

func remotePlacementIdentity(info os.FileInfo) (uint64, uint64, uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, ErrRemotePlacement
	}
	return uint64(stat.Dev), uint64(stat.Ino), uint64(stat.Uid), nil
}
