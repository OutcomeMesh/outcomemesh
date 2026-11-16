//go:build darwin

package pruneservice

import "golang.org/x/sys/unix"

func renameTransfer(from int, source string, to int, destination string) error {
	return unix.RenameatxNp(from, source, to, destination, unix.RENAME_EXCL)
}
