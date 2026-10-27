package remoteworker

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	lockName       = "worker.lock"
	assignmentName = "assignment.omcaa"
	planName       = "plan.omcrp"
	beginName      = "begin.omcae"
	readyName      = "ready.omcrw"
	startName      = "01-start.omcrw"
	sealingName    = "02-sealing.omcrw"
	sealName       = "03-seal.omcrw"
	maximumFiles   = 11
)

type artifact struct {
	name  string
	bytes []byte
}

func metadata(c Config) []artifact {
	a, _ := c.Assignment.CanonicalBytes()
	p, _ := c.Plan.CanonicalBytes()
	b, _ := c.Begin.CanonicalBytes()
	return []artifact{{assignmentName, a}, {planName, p}, {beginName, b}, {readyName, idsBytes("OMCRRDY0", c.Plan.AssignmentID, c.PlanID, c.BeginID)}}
}
func confirmName(stage Stage) string {
	switch stage {
	case Started:
		return "01-start.confirm"
	case Sealing:
		return "02-sealing.confirm"
	case Sealed:
		return "03-seal.confirm"
	}
	return ""
}
func idsBytes(magic string, ids ...types.Hash) []byte {
	e := codec.NewEncoder(10 + len(ids)*types.HashSize)
	e.Fixed([]byte(magic))
	e.U16(Version0)
	for _, id := range ids {
		e.Fixed(id[:])
	}
	return e.Bytes()
}
func startBytes(plan, begin types.Hash) []byte { return idsBytes("OMCRSTRT", plan, begin) }
func sealingBytes(plan, begin, start types.Hash) []byte {
	return idsBytes("OMCRSING", plan, begin, start)
}
func confirmationBytes(plan, begin, id types.Hash) []byte {
	return idsBytes("OMCRCNFM", plan, begin, id)
}
func recordID(name string, b []byte) types.Hash {
	return types.DomainHash("OMESH/custody-remote-worker/record/"+name+"/v0", b)
}

func journalPath(path string) (string, error) {
	if path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) {
		return "", ErrStore
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() {
		return "", errors.Join(ErrStore, err)
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

func readRegular(path string, maximum int) (b []byte, returnErr error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > int64(maximum) {
		return nil, errors.Join(ErrStore, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { returnErr = errors.Join(returnErr, f.Close()) }()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.Join(ErrStore, err)
	}
	b, err = io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || int64(len(b)) != before.Size() || after.Size() != before.Size() {
		return nil, errors.Join(ErrStore, err)
	}
	return b, nil
}

func inspect(path string, lock *os.File) (map[string]os.FileInfo, error) {
	root, err := os.Lstat(path)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrStore, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(root, opened) {
		return nil, errors.Join(ErrStore, err)
	}
	names, err := f.Readdirnames(maximumFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) < 5 || len(names) > maximumFiles {
		return nil, ErrStore
	}
	allowed := map[string]bool{lockName: true, assignmentName: true, planName: true, beginName: true, readyName: true, startName: true, sealingName: true, sealName: true, confirmName(Started): true, confirmName(Sealing): true, confirmName(Sealed): true}
	identity := map[string]os.FileInfo{"": root}
	for _, name := range names {
		if !allowed[name] {
			return nil, ErrStore
		}
		info, err := os.Lstat(filepath.Join(path, name))
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.Join(ErrStore, err)
		}
		identity[name] = info
	}
	for _, name := range []string{lockName, assignmentName, planName, beginName, readyName} {
		if identity[name] == nil {
			return nil, ErrStore
		}
	}
	info, err := lock.Stat()
	if err != nil || identity[lockName].Size() != 0 || !os.SameFile(info, identity[lockName]) {
		return nil, errors.Join(ErrStore, err)
	}
	return identity, nil
}

func (j *Journal) refresh() error {
	identity, err := inspect(j.path, j.lock)
	if err != nil {
		return err
	}
	// Owned transitions may add exact immutable records, never replace any
	// already retained root, lock, metadata, record or confirmation inode.
	for name, before := range j.identity {
		after, ok := identity[name]
		if !ok || !os.SameFile(before, after) {
			return ErrStore
		}
	}
	retained := make(map[string][]byte)
	for _, item := range metadata(j.config) {
		b, err := readRegular(filepath.Join(j.path, item.name), len(item.bytes))
		if err != nil || !bytes.Equal(b, item.bytes) {
			return errors.Join(ErrStore, err)
		}
		retained[item.name] = b
	}
	s := Snapshot{PlanID: j.config.PlanID, BeginID: j.config.BeginID, Stage: Prepared}
	for _, transition := range []struct {
		name  string
		stage Stage
	}{{startName, Started}, {sealingName, Sealing}, {sealName, Sealed}} {
		_, exists := identity[transition.name]
		_, confirmed := identity[confirmName(transition.stage)]
		if !exists {
			if confirmed {
				return ErrStore
			}
			continue
		}
		if s.Pending != 0 {
			return ErrStore
		}
		var want []byte
		switch transition.stage {
		case Started:
			want = startBytes(s.PlanID, s.BeginID)
			s.Started = true
		case Sealing:
			var start types.Hash
			if s.Started {
				start = recordID(startName, retained[startName])
			}
			want = sealingBytes(s.PlanID, s.BeginID, start)
		case Sealed:
			if s.Stage != Sealing {
				return ErrStore
			}
			b, err := readRegular(filepath.Join(j.path, transition.name), SealBytes)
			if err != nil {
				return err
			}
			seal, err := DecodeSeal(b)
			if err != nil {
				return err
			}
			if err := seal.validateBinding(s.PlanID, s.BeginID, s.SealingID, s.Started); err != nil {
				return err
			}
			want = b
			s.Seal = &seal
			s.SealID, _ = seal.ID()
		}
		b, err := readRegular(filepath.Join(j.path, transition.name), len(want))
		if err != nil || !bytes.Equal(b, want) {
			return errors.Join(ErrStore, err)
		}
		retained[transition.name] = b
		id := recordID(transition.name, b)
		if transition.stage == Sealing {
			s.SealingID = id
		}
		s.Stage = transition.stage
		if !confirmed {
			s.Pending = transition.stage
			continue
		}
		want = confirmationBytes(s.PlanID, s.BeginID, id)
		pin, err := readRegular(filepath.Join(j.path, confirmName(transition.stage)), len(want))
		if err != nil || !bytes.Equal(pin, want) {
			return errors.Join(ErrStore, err)
		}
		retained[confirmName(transition.stage)] = pin
	}
	for name, before := range j.retained {
		after, ok := retained[name]
		if !ok || !bytes.Equal(before, after) {
			return ErrStore
		}
	}
	j.identity, j.retained, j.state = identity, retained, s
	return nil
}

func (j *Journal) publish(name string, b []byte) (returnErr error) {
	path := filepath.Join(j.path, name)
	if existing, err := readRegular(path, len(b)); err == nil {
		if !bytes.Equal(existing, b) {
			return ErrStore
		}
		if err := syncFile(path); err != nil {
			return err
		}
		return syncDirectory(j.path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := j.hooks.reach(name + "-before-create"); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, f.Close()) }()
	if n, err := f.Write(b); err != nil || n != len(b) {
		return errors.Join(io.ErrShortWrite, err)
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := j.hooks.reach(name + "-file-synced"); err != nil {
		return err
	}
	if err := syncDirectory(j.path); err != nil {
		return err
	}
	return j.hooks.reach(name + "-directory-synced")
}

func syncFile(path string) (returnErr error) {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, f.Close()) }()
	return f.Sync()
}
func syncDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(ErrStore, err)
	}
	return syncFile(path)
}

func openWorkerLock(path string, create bool) (_ *os.File, returnErr error) {
	root, err := os.Lstat(path)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(ErrStore, err)
	}
	name := filepath.Join(path, lockName)
	flags := os.O_RDWR
	var before os.FileInfo
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	} else {
		before, err = os.Lstat(name)
		if err != nil || !before.Mode().IsRegular() || before.Size() != 0 {
			return nil, errors.Join(ErrStore, err)
		}
	}
	f, err := os.OpenFile(name, flags, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, f.Close())
		}
	}()
	locked, err := tryLock(f)
	if err != nil {
		return nil, err
	}
	if !locked {
		return nil, ErrBusy
	}
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(name)
	if err != nil || !after.Mode().IsRegular() || after.Size() != 0 || !os.SameFile(opened, after) || (before != nil && !os.SameFile(before, opened)) {
		return nil, errors.Join(ErrStore, err)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(root, current) {
		return nil, errors.Join(ErrStore, err)
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	return f, nil
}
