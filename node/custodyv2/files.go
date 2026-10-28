package custodyv2

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

type Sources struct{ Journal, Objects string }
type fileStamp struct {
	Device, Inode uint64
	User, Mode    uint32
}
type placement struct {
	Role    string
	Sources Sources
	Files   map[string]fileStamp
}
type root struct {
	mu           sync.Mutex
	path         string
	ctx          Context
	scopeID      types.Hash
	lock         *os.File
	identity     map[string]os.FileInfo
	placement    []byte
	sources      Sources
	decision     *workarchive.CustodyJournalDecision
	objects      *workarchive.ObjectStore
	failed       bool
	binding      *AdmissionBinding
	bindingBytes []byte
	bindingID    types.Hash
	hook         func(string) error
}

func createRoot(path string, c Context, pin types.Hash, role string, sources Sources) error {
	return createRootBound(path, c, pin, role, sources, nil)
}
func createRootBound(path string, c Context, pin types.Hash, role string, sources Sources, binding *AdmissionBinding) (returnErr error) {
	c, e := c.freeze()
	if e != nil {
		return e
	}
	bound, boundRaw, _, e := freezeRequiredBinding(c, binding)
	if e != nil {
		return e
	}
	s, e := c.Scope()
	if e != nil {
		return e
	}
	id, _ := s.ID()
	if id != pin {
		return ErrProtocol
	}
	path, e = canonical(path)
	if e != nil {
		return e
	}
	sources, e = canonicalSources(sources, role)
	if e != nil {
		return e
	}
	if e := disjoint(path, sources); e != nil {
		return e
	}
	journal, _, e := workarchive.OpenExistingCustodyJournalWithLimits(nilContext(), sources.Journal, c.Manifest, c.Initial, c.CustodyPolicy, workarchive.DefaultCustodyJournalLimits())
	if e != nil {
		return e
	}
	decision, e := journal.AcquireDecision()
	if e != nil {
		return e
	}
	defer func() { returnErr = errors.Join(returnErr, decision.Close()) }()
	state, e := decision.State()
	if e != nil || !atPredecessor(c, state) {
		return errors.Join(ErrProtocol, e)
	}
	if e := os.Mkdir(path, 0o700); e != nil {
		return e
	}
	if e := syncDir(filepath.Dir(path)); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		return e
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if e := lockRoot(lock); e != nil {
		return e
	}
	if e := lock.Sync(); e != nil {
		return e
	}
	p, e := sourcePlacement(role, sources, path)
	if e != nil {
		return e
	}
	raw, _ := c.CanonicalBytes()
	if e := publish(path, "context", raw, nil); e != nil {
		return e
	}
	if e := publish(path, "placement", p, nil); e != nil {
		return e
	}
	if bound != nil {
		if e := publish(path, "admission", boundRaw, nil); e != nil {
			return e
		}
	}
	return publish(path, "ready", append([]byte("OMCVRDY2"), pin[:]...), nil)
}
func openRoot(path string, c Context, pin types.Hash, role string, sources Sources) (*root, error) {
	return openRootBound(path, c, pin, role, sources, nil)
}
func openRootBound(path string, c Context, pin types.Hash, role string, sources Sources, binding *AdmissionBinding) (r *root, returnErr error) {
	c, e := c.freeze()
	if e != nil {
		return nil, e
	}
	bound, boundRaw, boundID, e := freezeRequiredBinding(c, binding)
	if e != nil {
		return nil, e
	}
	s, e := c.Scope()
	if e != nil {
		return nil, e
	}
	id, _ := s.ID()
	if pin.IsZero() || id != pin {
		return nil, ErrProtocol
	}
	path, e = canonical(path)
	if e != nil {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.Join(ErrProtocol, e)
	}
	sources, e = canonicalSources(sources, role)
	if e != nil {
		return nil, e
	}
	if e := disjoint(path, sources); e != nil {
		return nil, e
	}
	li, e := os.Lstat(filepath.Join(path, "owner.lock"))
	if e != nil || !privateFile(li) || li.Size() != 0 {
		return nil, errors.Join(ErrProtocol, e)
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	held, e := lock.Stat()
	if e != nil || !os.SameFile(li, held) {
		return nil, errors.Join(ErrProtocol, e)
	}
	if e := lockRoot(lock); e != nil {
		return nil, e
	}
	want, _ := c.CanonicalBytes()
	raw, e := readFile(filepath.Join(path, "context"), MaximumContextBytes)
	if e != nil || !bytes.Equal(want, raw) {
		return nil, errors.Join(ErrProtocol, e)
	}
	raw, e = readFile(filepath.Join(path, "ready"), 40)
	if e != nil || !bytes.Equal(raw, append([]byte("OMCVRDY2"), pin[:]...)) {
		return nil, errors.Join(ErrProtocol, e)
	}
	p, e := sourcePlacement(role, sources, path)
	if e != nil {
		return nil, e
	}
	raw, e = readFile(filepath.Join(path, "placement"), 32768)
	if e != nil || !bytes.Equal(raw, p) {
		return nil, errors.Join(ErrProtocol, e)
	}
	journal, _, e := workarchive.OpenExistingCustodyJournalWithLimits(nilContext(), sources.Journal, c.Manifest, c.Initial, c.CustodyPolicy, workarchive.DefaultCustodyJournalLimits())
	if e != nil {
		return nil, e
	}
	decision, e := journal.AcquireDecision()
	if e != nil {
		return nil, e
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, decision.Close())
		}
	}()
	r = &root{path: path, ctx: c, scopeID: pin, lock: lock, identity: map[string]os.FileInfo{path: info, filepath.Join(path, "owner.lock"): held}, placement: p, sources: sources, decision: decision, binding: bound, bindingBytes: boundRaw, bindingID: boundID}
	for name := range placementFiles(sources) {
		info, e := os.Lstat(name)
		if e != nil {
			return nil, e
		}
		r.identity[name] = info
	}
	if role == "target" && bound == nil {
		r.objects, e = workarchive.OpenExistingObjectStoreContext(nilContext(), sources.Objects, workarchive.DefaultObjectStorePolicy())
		if e != nil {
			return nil, e
		}
		missing, e := r.objects.Missing(c.Manifest)
		if e != nil || len(missing) != 0 {
			return nil, errors.Join(ErrProtocol, e)
		}
	}
	return r, r.check()
}
func (r *root) check() error {
	if r.lock == nil || r.failed {
		return ErrUncertain
	}
	for path, old := range r.identity {
		now, e := os.Lstat(path)
		if e != nil || !os.SameFile(old, now) || now.Mode()&os.ModeSymlink != 0 {
			return errors.Join(ErrProtocol, e)
		}
	}
	p, e := readFile(filepath.Join(r.path, "placement"), 32768)
	if e != nil || !bytes.Equal(p, r.placement) {
		return errors.Join(ErrProtocol, e)
	}
	p, e = sourcePlacementFromRoot(r.placement, r.sources, r.path)
	if e != nil || !bytes.Equal(p, r.placement) {
		return errors.Join(ErrProtocol, e)
	}
	f, e := os.Open(r.path)
	if e != nil {
		return e
	}
	entries, scanErr := f.ReadDir(10)
	closeErr := f.Close()
	if scanErr != nil && !errors.Is(scanErr, io.EOF) {
		return errors.Join(scanErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	maximum := 8
	if r.ctx.Assignment.Policy.Version == PolicyVersionAdmission {
		maximum++
	}
	if len(entries) > maximum {
		return ErrProtocol
	}
	allowed := map[string]bool{"context": true, "placement": true, "ready": true, "owner.lock": true, "serve.pending": true, "serve.settled": true}
	if r.ctx.Assignment.Policy.Version == PolicyVersionAdmission {
		allowed["admission"] = true
	}
	if e := r.checkAdmission(); e != nil {
		return e
	}
	var placed placement
	if json.Unmarshal(r.placement, &placed) != nil {
		return ErrProtocol
	}
	if placed.Role == "target" {
		allowed["consumed"] = true
		allowed["result"] = true
	} else if placed.Role == "acceptor" {
		allowed["pending"] = true
		allowed["accepted"] = true
	} else {
		return ErrProtocol
	}
	contextBytes, _ := r.ctx.CanonicalBytes()
	for name, wanted := range map[string][]byte{"context": contextBytes, "ready": append([]byte("OMCVRDY2"), r.scopeID[:]...)} {
		actual, e := readFile(filepath.Join(r.path, name), len(wanted))
		if e != nil || !bytes.Equal(actual, wanted) {
			return errors.Join(ErrProtocol, e)
		}
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return ErrProtocol
		}
	}
	return nil
}

// stabilize flushes already validated retained bytes after a cold open. A full
// file left at a failed sync boundary is not yet durable merely because read
// returned it. This creates no files, signatures, source appends or new grants.
func (r *root) stabilize() (returnErr error) {
	defer func() {
		if returnErr != nil {
			r.failed = true
			returnErr = errors.Join(ErrUncertain, returnErr)
		}
	}()
	if e := r.check(); e != nil {
		return e
	}
	for _, name := range []string{"context", "placement", "ready", "owner.lock", "consumed", "result", "pending", "accepted", "serve.pending", "serve.settled", "admission"} {
		path := filepath.Join(r.path, name)
		info, e := os.Lstat(path)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || !privateFile(info) {
			return errors.Join(ErrProtocol, e)
		}
		f, e := os.OpenFile(path, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		current, e := f.Stat()
		if e != nil || !os.SameFile(info, current) {
			_ = f.Close()
			return errors.Join(ErrProtocol, e)
		}
		if e := errors.Join(f.Sync(), f.Close()); e != nil {
			return e
		}
	}
	if e := syncDir(r.path); e != nil {
		return e
	}
	return r.check()
}
func (r *root) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lock == nil {
		return nil
	}
	e := errors.Join(r.decision.Close(), r.lock.Close())
	r.lock = nil
	return e
}
func (r *root) write(name string, b []byte) error {
	if e := publish(r.path, name, b, r.hook); e != nil {
		r.failed = true
		return errors.Join(ErrUncertain, e)
	}
	return r.check()
}
func publish(dir, name string, b []byte, hook func(string) error) (returnErr error) {
	path := filepath.Join(dir, name)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(e, os.ErrExist) {
		old, e := readFile(path, len(b))
		if e != nil || !bytes.Equal(old, b) {
			return errors.Join(ErrProtocol, e)
		}
		f, e = os.OpenFile(path, os.O_RDWR, 0)
		if e != nil {
			return e
		}
	} else if e != nil {
		return e
	} else {
		n, e := f.Write(b)
		if e != nil || n != len(b) {
			_ = f.Close()
			return errors.Join(io.ErrShortWrite, e)
		}
	}
	defer func() { returnErr = errors.Join(returnErr, f.Close()) }()
	if hook != nil {
		if e := hook(name + "-before-sync"); e != nil {
			return e
		}
	}
	if e := f.Sync(); e != nil {
		return e
	}
	if e := syncDir(dir); e != nil {
		return e
	}
	if hook != nil {
		return hook(name + "-durable")
	}
	return nil
}
func readFile(path string, limit int) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !privateFile(info) || info.Size() > int64(limit) {
		return nil, ErrProtocol
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	now, e := f.Stat()
	if e != nil || !os.SameFile(info, now) {
		return nil, errors.Join(ErrProtocol, e)
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(b) > limit {
		return nil, ErrProtocol
	}
	return b, e
}
func privateFile(i os.FileInfo) bool {
	return i != nil && i.Mode().IsRegular() && i.Mode().Perm()&0o077 == 0
}
func syncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}
func canonical(p string) (string, error) {
	if p == "" {
		return "", ErrProtocol
	}
	abs, e := filepath.Abs(p)
	if e != nil {
		return "", e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(abs))
	if e != nil {
		return "", e
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}
func canonicalSources(s Sources, role string) (Sources, error) {
	var e error
	s.Journal, e = filepath.EvalSymlinks(s.Journal)
	if e != nil {
		return s, e
	}
	s.Journal, e = filepath.Abs(s.Journal)
	if e != nil {
		return s, e
	}
	if role == "target" {
		s.Objects, e = filepath.EvalSymlinks(s.Objects)
		if e != nil {
			return s, e
		}
		s.Objects, e = filepath.Abs(s.Objects)
	} else if role != "acceptor" || s.Objects != "" {
		return s, ErrProtocol
	}
	return s, e
}
func disjoint(root string, s Sources) error {
	paths := []string{root, s.Journal}
	if s.Objects != "" {
		paths = append(paths, s.Objects)
	}
	for i, p := range paths {
		for j, q := range paths {
			if i == j {
				continue
			}
			rel, e := filepath.Rel(p, q)
			if e != nil || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return ErrProtocol
			}
		}
	}
	return nil
}
func placementFiles(s Sources) map[string]bool {
	out := map[string]bool{s.Journal: true, filepath.Join(s.Journal, "journal.lock"): true}
	if s.Objects != "" {
		out[s.Objects] = true
	}
	return out
}
func sourcePlacement(role string, s Sources, rootPath string) ([]byte, error) {
	p := placement{Role: role, Sources: s, Files: map[string]fileStamp{}}
	files := placementFiles(s)
	files[rootPath] = true
	files[filepath.Join(rootPath, "owner.lock")] = true
	for path := range files {
		info, e := os.Lstat(path)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(ErrProtocol, e)
		}
		stamp, e := stampFile(info)
		if e != nil {
			return nil, e
		}
		p.Files[path] = stamp
	}
	return json.Marshal(p)
}
func sourcePlacementFromRoot(raw []byte, s Sources, rootPath string) ([]byte, error) {
	var p placement
	if e := json.Unmarshal(raw, &p); e != nil {
		return nil, e
	}
	return sourcePlacement(p.Role, s, rootPath)
}
func atPredecessor(c Context, s workarchive.CustodyJournalState) bool {
	rid, _ := s.CurrentReceipt.ID()
	return s.InitialReceipt == c.Initial && s.Sequence == c.Plan.Intent.PriorSequence && s.HeadEntryID == c.Plan.Intent.PriorHeadID && rid == c.Plan.Intent.PriorReceiptID
}
