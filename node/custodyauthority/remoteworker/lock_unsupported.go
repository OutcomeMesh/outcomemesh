//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !windows

package remoteworker

import "os"

func tryLock(*os.File) (bool, error) { return false, ErrStore }
