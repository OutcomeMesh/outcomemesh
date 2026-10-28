package custodycutover

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"github.com/outcomemesh/outcomemesh/core/types"
	a "github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var ErrUncertain = errors.New("cutover preparation write is uncertain; retain the original root and exact pins")

// Pins are independently retained, not adopted from an incoming proposal.
type Pins struct {
	AnchorID, DescriptorID, LegacyID types.Hash
	Retired                          a.Position
	ProposalID                       types.Hash
}
type Preparation struct {
	mu                 sync.Mutex
	path               string
	lock               *os.File
	raw, placed        []byte
	pins               Pins
	rootInfo, lockInfo os.FileInfo
	failed             bool
}
type prepareStamp struct {
	Path                             string
	Device, Inode, User              uint64
	Mode                             uint32
	ChangeSeconds, ChangeNanoseconds int64
}

func preparationPlacement(path string) ([]byte, error) {
	var result []prepareStamp
	for _, p := range []string{path, filepath.Join(path, "owner.lock")} {
		info, e := os.Lstat(p)
		if e != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return nil, ErrPreparation
		}
		dev, ino, uid, e := fileIdentity(info)
		if e != nil || uid != uint64(os.Geteuid()) {
			return nil, ErrPreparation
		}
		stamp := prepareStamp{Path: p, Device: dev, Inode: ino, User: uid, Mode: uint32(info.Mode())}
		if info.Mode().IsRegular() {
			stamp.ChangeSeconds, stamp.ChangeNanoseconds, e = lockChangeIdentity(info)
			if e != nil {
				return nil, e
			}
		}
		result = append(result, stamp)
	}
	return json.Marshal(result)
}
func preparePath(path string) (string, error) {
	if !utf8.ValidString(path) || len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ErrPreparation
	}
	parent, e := canonicalPath(filepath.Dir(path))
	if e != nil {
		return "", e
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}
func verifyPrepared(p Proposal, pins Pins) ([]byte, error) {
	if pins.ProposalID.IsZero() {
		return nil, ErrPreparation
	}
	raw, e := p.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	p, e = DecodeProposal(raw)
	if e != nil {
		return nil, e
	}
	id, _ := p.ID()
	if id != pins.ProposalID {
		return nil, ErrPreparation
	}
	if _, e := p.Verify(pins.AnchorID, pins.DescriptorID, pins.LegacyID, pins.Retired); e != nil {
		return nil, e
	}
	return raw, nil
}
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func writePreparation(path, name string, raw []byte, hook func(string) error) (err error) {
	f, err := os.OpenFile(filepath.Join(path, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	n, err := f.Write(raw)
	if err != nil || n != len(raw) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if hook != nil {
		if err := hook(name + "-before-sync"); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := syncDirectory(path); err != nil {
		return err
	}
	if hook != nil {
		return hook(name + "-durable")
	}
	return nil
}
func prepareReady(pins Pins) []byte {
	b := append([]byte("OMCXRDY1"), pins.ProposalID[:]...)
	b = append(b, pins.AnchorID[:]...)
	return append(b, pins.DescriptorID[:]...)
}
func CreatePreparation(path string, p Proposal, pins Pins) error {
	return createPreparation(path, p, pins, nil)
}
func createPreparation(path string, p Proposal, pins Pins, hook func(string) error) (err error) {
	raw, e := verifyPrepared(p, pins)
	if e != nil {
		return e
	}
	path, e = preparePath(path)
	if e != nil {
		return e
	}
	if e := os.Mkdir(path, 0700); e != nil {
		return e
	}
	defer func() {
		if err != nil {
			err = errors.Join(ErrUncertain, err)
		}
	}()
	if e := syncDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.Join(ErrUncertain, e)
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if e := lockPreparation(lock); e != nil {
		return e
	}
	if e := lock.Sync(); e != nil {
		return errors.Join(ErrUncertain, e)
	}
	placed, e := preparationPlacement(path)
	if e != nil {
		return e
	}
	for _, item := range []struct {
		name string
		raw  []byte
	}{{"placement", placed}, {"proposal", raw}, {"ready", prepareReady(pins)}} {
		if e := writePreparation(path, item.name, item.raw, hook); e != nil {
			return errors.Join(ErrUncertain, e)
		}
	}
	return nil
}
func readPreparationFile(path string, limit int) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 0 || info.Size() > int64(limit) {
		return nil, errors.Join(ErrPreparation, e)
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, ErrPreparation
	}
	raw, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if e != nil || len(raw) > limit {
		return nil, errors.Join(ErrPreparation, e)
	}
	return raw, nil
}
func OpenPreparation(path string, pins Pins) (*Preparation, error) {
	return openPreparation(path, pins, false)
}

// RecoverPreparation only finishes ready publication after the complete exact
// original proposal and placement already exist. It never reconstructs a missing
// proposal or chooses a new one. Recovery creates no runtime grant.
func RecoverPreparation(path string, pins Pins) (*Preparation, error) {
	return openPreparation(path, pins, true)
}
func openPreparation(path string, pins Pins, recover bool) (p *Preparation, err error) {
	path, e := canonicalPath(path)
	if e != nil {
		return nil, e
	}
	rootInfo, e := os.Lstat(path)
	if e != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0077 != 0 {
		return nil, ErrPreparation
	}
	li, e := os.Lstat(filepath.Join(path, "owner.lock"))
	if e != nil || !li.Mode().IsRegular() || li.Mode().Perm()&0077 != 0 || li.Size() != 0 {
		return nil, ErrPreparation
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()
	held, e := lock.Stat()
	if e != nil || !os.SameFile(li, held) {
		return nil, ErrPreparation
	}
	if e := lockPreparation(lock); e != nil {
		return nil, e
	}
	placed, e := preparationPlacement(path)
	if e != nil {
		return nil, e
	}
	old, e := readPreparationFile(filepath.Join(path, "placement"), 32768)
	if e != nil || !bytes.Equal(placed, old) {
		return nil, ErrPreparation
	}
	raw, e := readPreparationFile(filepath.Join(path, "proposal"), MaximumProposalBytes)
	if e != nil {
		return nil, e
	}
	proposal, e := DecodeProposal(raw)
	if e != nil {
		return nil, e
	}
	if _, e := verifyPrepared(proposal, pins); e != nil {
		return nil, e
	}
	ready, e := readPreparationFile(filepath.Join(path, "ready"), 104)
	missing := errors.Is(e, os.ErrNotExist)
	if e != nil && (!missing || !recover) {
		return nil, e
	}
	if !missing && !bytes.Equal(ready, prepareReady(pins)) {
		return nil, ErrPreparation
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	names, scan := f.ReadDir(5)
	closeErr := f.Close()
	if scan != nil && !errors.Is(scan, io.EOF) || closeErr != nil || len(names) > 4 {
		return nil, ErrPreparation
	}
	allowed := map[string]bool{"owner.lock": true, "placement": true, "proposal": true, "ready": true}
	for _, name := range names {
		if !allowed[name.Name()] {
			return nil, ErrPreparation
		}
	}
	for _, name := range []string{"owner.lock", "placement", "proposal"} {
		file, e := os.Open(filepath.Join(path, name))
		if e != nil {
			return nil, e
		}
		if e := errors.Join(file.Sync(), file.Close()); e != nil {
			return nil, e
		}
	}
	if missing {
		if e := writePreparation(path, "ready", prepareReady(pins), nil); e != nil {
			return nil, errors.Join(ErrUncertain, e)
		}
	} else {
		file, e := os.Open(filepath.Join(path, "ready"))
		if e != nil {
			return nil, e
		}
		if e := errors.Join(file.Sync(), file.Close()); e != nil {
			return nil, e
		}
	}
	if e := syncDirectory(path); e != nil {
		return nil, e
	}
	if e := syncDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	p = &Preparation{path: path, lock: lock, raw: raw, placed: placed, pins: pins, rootInfo: rootInfo, lockInfo: held}
	if err := p.check(); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *Preparation) check() error {
	if p == nil || p.lock == nil || p.failed {
		return ErrPreparation
	}
	for _, v := range []struct {
		path string
		info os.FileInfo
	}{{p.path, p.rootInfo}, {filepath.Join(p.path, "owner.lock"), p.lockInfo}} {
		info, e := os.Lstat(v.path)
		if e != nil || !os.SameFile(info, v.info) {
			return ErrPreparation
		}
	}
	placed, e := preparationPlacement(p.path)
	if e != nil || !bytes.Equal(placed, p.placed) {
		return ErrPreparation
	}
	for name, want := range map[string][]byte{"proposal": p.raw, "placement": p.placed, "ready": prepareReady(p.pins)} {
		raw, e := readPreparationFile(filepath.Join(p.path, name), len(want))
		if e != nil || !bytes.Equal(raw, want) {
			return ErrPreparation
		}
	}
	directory, e := os.Open(p.path)
	if e != nil {
		return e
	}
	names, scanErr := directory.ReadDir(5)
	if scanErr == io.EOF {
		scanErr = nil
	}
	e = errors.Join(scanErr, directory.Close())
	if e != nil || len(names) != 4 {
		return ErrPreparation
	}
	return nil
}
func (p *Preparation) Read(ctx context.Context) (Proposal, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx == nil {
		return Proposal{}, ErrPreparation
	}
	if e := ctx.Err(); e != nil {
		return Proposal{}, e
	}
	if e := p.check(); e != nil {
		p.failed = true
		return Proposal{}, e
	}
	return DecodeProposal(p.raw)
}
func (p *Preparation) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lock == nil {
		return nil
	}
	e := p.lock.Close()
	p.lock = nil
	return e
}
