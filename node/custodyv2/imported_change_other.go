//go:build !darwin && !linux

package custodyv2

import "os"

func importedLockChange(os.FileInfo) (int64, int64, error) { return 0, 0, ErrAdmission }
