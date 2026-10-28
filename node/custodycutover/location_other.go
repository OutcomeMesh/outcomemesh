//go:build !darwin && !linux

package custodycutover

import "os"

func fileIdentity(os.FileInfo) (uint64, uint64, uint64, error) { return 0, 0, 0, ErrPreparation }

func lockChangeIdentity(info os.FileInfo) (int64, int64, error) { return 0, 0, ErrPreparation }
