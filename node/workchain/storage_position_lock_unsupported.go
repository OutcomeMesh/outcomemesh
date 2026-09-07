//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package workchain

import "os"

func tryPositionLock(*os.File) (bool, error) { return false, ErrStoragePosition }
