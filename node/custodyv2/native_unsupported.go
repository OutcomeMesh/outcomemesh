//go:build !darwin && !linux

package custodyv2

import (
	"context"
	"os"
)

func lockRoot(*os.File) error                  { return ErrProtocol }
func stampFile(os.FileInfo) (fileStamp, error) { return fileStamp{}, ErrProtocol }
func nilContext() context.Context              { return context.Background() }
