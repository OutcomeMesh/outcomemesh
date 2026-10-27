//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package custodyfence

import "os"

func lockWitness(*os.File) error { return ErrWitness }
