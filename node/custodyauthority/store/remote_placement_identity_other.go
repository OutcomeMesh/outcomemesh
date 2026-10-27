//go:build !darwin && !linux

package store

import "os"

func remotePlacementIdentity(os.FileInfo) (uint64, uint64, uint64, error) {
	return 0, 0, 0, ErrRemotePlacement
}
