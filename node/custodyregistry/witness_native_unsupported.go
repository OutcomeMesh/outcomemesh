//go:build !darwin && !linux

package custodyregistry

import "os"

func witnessLock(*os.File) error                         { return ErrRegistry }
func witnessStampFile(os.FileInfo) (witnessStamp, error) { return witnessStamp{}, ErrRegistry }
