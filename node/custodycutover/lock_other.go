//go:build !darwin && !linux

package custodycutover

import "os"

func lockPreparation(*os.File) error { return ErrPreparation }
