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

func preparePruneEffectOutputPipe(*os.File) (io.WriteCloser, error) {
	return nil, errors.New("archive effect control pipes are supported only on macOS/Linux; use explicit offline review")
}
