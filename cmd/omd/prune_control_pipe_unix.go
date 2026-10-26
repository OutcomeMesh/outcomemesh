//go:build darwin || linux

package main

import (
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Inherited os.Stdin may be blocking and absent from Go's poller. Closing that
// os.File can wait forever behind Read. Adopt an atomic close-on-exec duplicate
// in nonblocking mode, then verify poller support BEFORE opening journal owners.
// O_NONBLOCK is shared with the original pipe endpoint: opt-in transfers the
// whole dedicated read endpoint; it must not have another reader or user.
func preparePruneControlPipe(source *os.File) (io.ReadCloser, error) {
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var adoptErr error
	err = raw.Control(func(original uintptr) {
		fd, adoptErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
		if adoptErr == nil {
			adoptErr = unix.SetNonblock(fd, true)
		}
	})
	if err != nil || adoptErr != nil {
		if fd >= 0 {
			adoptErr = errors.Join(adoptErr, unix.Close(fd))
		}
		return nil, errors.Join(err, adoptErr)
	}
	reader := os.NewFile(uintptr(fd), "outcomemesh-maintenance-stdin")
	if err := reader.SetReadDeadline(time.Time{}); err != nil {
		return nil, errors.Join(errors.New("maintenance pipe cannot support interruptible reads"), err, reader.Close())
	}
	return &pruneNativeControlPipe{reader, source}, nil
}

type pruneNativeControlPipe struct {
	*os.File
	source *os.File
}

// Control stdout must be just as interruptible as stdin. Adopt its dedicated
// write endpoint before opening long-lived owners so cancellation can unblock
// a full output pipe, then drain the effect before releasing its journals.
func preparePruneEffectOutputPipe(source *os.File) (io.WriteCloser, error) {
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var adoptErr error
	err = raw.Control(func(original uintptr) {
		fd, adoptErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
		if adoptErr == nil {
			adoptErr = unix.SetNonblock(fd, true)
		}
	})
	if err != nil || adoptErr != nil {
		if fd >= 0 {
			adoptErr = errors.Join(adoptErr, unix.Close(fd))
		}
		return nil, errors.Join(err, adoptErr)
	}
	writer := os.NewFile(uintptr(fd), "outcomemesh-effect-stdout")
	if err := writer.SetWriteDeadline(time.Time{}); err != nil {
		return nil, errors.Join(errors.New("effect output pipe cannot support interruptible writes"), err, writer.Close())
	}
	return &pruneNativeControlPipe{writer, source}, nil
}

func (pipe *pruneNativeControlPipe) Close() error {
	return errors.Join(pipe.File.Close(), pipe.source.Close())
}
