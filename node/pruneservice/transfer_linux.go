//go:build linux

package pruneservice

import "golang.org/x/sys/unix"

func renameTransfer(from int, source string, to int, destination string) error {
	return unix.Renameat2(from, source, to, destination, unix.RENAME_NOREPLACE)
}
