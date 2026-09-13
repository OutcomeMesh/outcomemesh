//go:build !darwin && !linux

package main

import (
	"errors"
	"io"
	"os"
)

func preparePruneControlPipe(*os.File) (io.ReadCloser, error) {
	return nil, errors.New("live stdin maintenance is supported only on macOS/Linux; use explicit offline maintenance after service shutdown")
}
