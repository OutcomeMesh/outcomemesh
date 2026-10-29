package custodyfence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

var (
	ErrWitness   = errors.New("invalid or replaced custody witness journal")
	ErrBusy      = errors.New("custody witness journal already owned")
	ErrUncertain = errors.New("custody witness persistence uncertain; close and explicitly recover")
)

// WitnessPin must be retained independently of this witness root. A historical
// pin detects a different prefix, not a rollback of every copy of that pin.
type WitnessPin struct {
	Position  Position
	PendingID types.Hash
}

// Witness is one independently keyed, permanent single-writer vote journal.
// Vote never releases a signature until its exact proposal is durably locked.
// Commit requires a quorum, not merely the local witness's vote. There are at
// most three transitions; no expiry, unlock, force-reset or view change exists.
type Witness struct {
	guard              guard.Chooser
	mu                 sync.Mutex
	path               string
	key                ed25519.PrivateKey
	public             [32]byte
	lock               *os.File
	rootInfo, lockInfo os.FileInfo
	state              *State
	pending            *Command
	files              map[string][]byte
	failed             bool
	hook               func(string) error // private test-only durability boundary
}

// Create explicitly enrolls a new witness root. It must not be used as recovery
// for a lost root/key. Only the deployment's independently protected enrollment
// process can ensure that the same witness key is not enrolled twice.
func Create(path string, s Scope, pin types.Hash, key ed25519.PrivateKey) (_ *Witness, returnErr error) {
	state, err := NewState(s, pin)
	if err != nil {
		return nil, err
	}
	public, err := witnessKey(s, key)
	if err != nil {
		return nil, err
	}
	path, err = canonicalPath(path)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(path, "witness.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	if err := lockWitness(lock); err != nil {
		return nil, err
	}
	w := &Witness{path: path, key: append(ed25519.PrivateKey(nil), key...), public: public, lock: lock, state: state, files: make(map[string][]byte)}
	if err := lock.Sync(); err != nil {
		return nil, err
	}
	b, _ := s.CanonicalBytes()
	if err := w.publish("scope", b); err != nil {
		return nil, err
	}
	ready := append(append([]byte(nil), pin[:]...), public[:]...)
	if err := w.publish("ready", ready); err != nil {
		return nil, err
	}
	w.rootInfo, err = os.Lstat(path)
	if err != nil {
		return nil, err
	}
	w.lockInfo, err = lock.Stat()
	if err != nil {
		return nil, err
	}
	return w, w.check()
}

// Open only replays a complete existing root at an independently retained exact
// position including any pending vote. It never creates files or signs.
func Open(path string, s Scope, pin types.Hash, key ed25519.PrivateKey, expected WitnessPin) (*Witness, error) {
	return openWitness(path, s, pin, key, func(w *Witness) error {
		if w.pin() != expected {
			return ErrTransition
		}
		return nil
	})
}

// RecoverVote permits only the retained pre-attempt state or its exact pending
// proposal. It signs nothing; the caller must explicitly call Vote afterward.
// The full attempted command and before pin must have been retained separately.
func RecoverVote(path string, s Scope, pin types.Hash, key ed25519.PrivateKey, before WitnessPin, attempt Command) (*Witness, error) {
	id, err := attempt.ID()
	if err != nil {
		return nil, err
	}
	if err := attempt.Verify(s); err != nil {
		return nil, err
	}
	if attempt.ExpectedSequence != before.Position.Sequence || attempt.ExpectedHead != before.Position.HeadID || (!before.PendingID.IsZero() && before.PendingID != id) {
		return nil, ErrTransition
	}
	return openWitness(path, s, pin, key, func(w *Witness) error {
		x := w.pin()
		if x.Position != before.Position || (x.PendingID != before.PendingID && x.PendingID != id) {
			return ErrTransition
		}
		return w.state.ValidateNext(attempt)
	})
}

// RecoverCommit accepts only the pre-attempt state or its one-transition quorum
// extension. A later prefix is rejected, even if otherwise validly signed.
func RecoverCommit(path string, s Scope, pin types.Hash, key ed25519.PrivateKey, before WitnessPin, attempt Certificate) (*Witness, error) {
	if err := attempt.Verify(s); err != nil {
		return nil, err
	}
	c := attempt.Command
	id, _ := c.ID()
	if c.ExpectedSequence != before.Position.Sequence || c.ExpectedHead != before.Position.HeadID {
		return nil, ErrTransition
	}
	return openWitness(path, s, pin, key, func(w *Witness) error {
		x := w.pin()
		if x == before {
			return w.state.ValidateNext(c)
		}
		if x.Position.Sequence == before.Position.Sequence+1 && x.Position.HeadID == id && x.PendingID.IsZero() {
			if !w.historicalPendingMatches(before) {
				return ErrTransition
			}
			return nil
		}
		return ErrTransition
	})
}

func openWitness(path string, s Scope, pin types.Hash, key ed25519.PrivateKey, accept func(*Witness) error) (_ *Witness, returnErr error) {
	public, err := witnessKey(s, key)
	if err != nil {
		return nil, err
	}
	return openMember(path, s, pin, public, key, accept)
}

func openMember(path string, s Scope, pin types.Hash, public [32]byte, key ed25519.PrivateKey, accept func(*Witness) error) (_ *Witness, returnErr error) {
	state, err := NewState(s, pin)
	if err != nil {
		return nil, err
	}
	member := false
	for _, k := range state.scope.Witnesses {
		member = member || k == public
	}
	if !member {
		return nil, ErrWitness
	}
	path, err = canonicalPath(path)
	if err != nil {
		return nil, err
	}
	root, err := os.Lstat(path)
	if err != nil || !privateDir(root) {
		return nil, errors.Join(ErrWitness, err)
	}
	lockPath := filepath.Join(path, "witness.lock")
	lockInfo, err := os.Lstat(lockPath)
	if err != nil || !privateFile(lockInfo) || lockInfo.Size() != 0 {
		return nil, errors.Join(ErrWitness, err)
	}
	lock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	held, err := lock.Stat()
	if err != nil || !os.SameFile(lockInfo, held) {
		return nil, errors.Join(ErrWitness, err)
	}
	if err := lockWitness(lock); err != nil {
		return nil, err
	}
	w := &Witness{path: path, key: append(ed25519.PrivateKey(nil), key...), public: public, lock: lock, rootInfo: root, lockInfo: held, state: state, files: make(map[string][]byte)}
	b, err := readFile(filepath.Join(path, "scope"), MaximumScopeBytes)
	expected, _ := s.CanonicalBytes()
	if err != nil || !bytes.Equal(b, expected) {
		return nil, errors.Join(ErrScope, err)
	}
	w.files["scope"] = b
	b, err = readFile(filepath.Join(path, "ready"), 64)
	expected = append(append([]byte(nil), pin[:]...), public[:]...)
	if err != nil || !bytes.Equal(b, expected) {
		return nil, errors.Join(ErrWitness, err)
	}
	w.files["ready"] = b
	for sequence := uint64(1); sequence <= 3; sequence++ {
		voteName := recordName(sequence, "vote")
		vote, err := readFile(filepath.Join(path, voteName), CommandBytes)
		if err == nil {
			c, err := DecodeCommand(vote)
			if err != nil {
				return nil, err
			}
			if err := state.ValidateNext(c); err != nil {
				return nil, err
			}
			w.pending = &c
			w.files[voteName] = vote
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		certName := recordName(sequence, "certificate")
		b, err := readFile(filepath.Join(path, certName), MaximumCertificateBytes)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, err
		}
		cert, err := DecodeCertificate(b)
		if err != nil {
			return nil, err
		}
		if err := state.Apply(cert); err != nil {
			return nil, err
		}
		w.files[certName] = b
		w.pending = nil
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	if err := accept(w); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Witness) Vote(command Command) (Vote, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.voteLocked(command)
}

func (w *Witness) voteLocked(command Command) (Vote, error) {
	if !validKey(w.key) {
		return Vote{}, ErrWitness
	}
	if err := w.check(); err != nil {
		return Vote{}, err
	}
	if err := w.state.ValidateNext(command); err != nil {
		return Vote{}, err
	}
	if w.pending != nil && *w.pending != command {
		return Vote{}, ErrLocked
	}
	b, _ := command.CanonicalBytes()
	name := recordName(command.ExpectedSequence+1, "vote")
	if err := w.publish(name, b); err != nil {
		w.failed = true
		return Vote{}, errors.Join(ErrUncertain, err)
	}
	copy := command
	w.pending = &copy
	if err := w.check(); err != nil {
		w.failed = true
		return Vote{}, err
	}
	v, e := signVote(command, w.key)
	if e != nil {
		return Vote{}, e
	}
	if w.state.scope.Guard != ([32]byte{}) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		v.GuardSeal, e = guard.Obtain(ctx, w.guard, w.state.scope.Guard, VoteGuardRequest(command, w.public), w.key)
		if e != nil {
			return Vote{}, e
		}
	}
	return v, nil
}

// Commit accepts a quorum certificate even if this witness locked a competing
// proposal. Such a witness may be outside the quorum. Its old vote stays on
// disk and can never be reused to vote differently at that historical position.
func (w *Witness) Commit(cert Certificate) error {
	b, err := cert.CanonicalBytes()
	if err != nil {
		return err
	}
	cert, err = DecodeCertificate(b)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.commitLocked(cert, b)
}

func (w *Witness) commitLocked(cert Certificate, b []byte) error {
	if err := w.check(); err != nil {
		return err
	}
	if err := cert.Verify(w.state.scope); err != nil {
		return err
	}
	c := cert.Command
	id, _ := c.ID()
	x := w.state.Snapshot()
	if c.ExpectedSequence < x.Position.Sequence {
		prior, err := DecodeCertificate(w.files[recordName(c.ExpectedSequence+1, "certificate")])
		if err != nil || prior.Command != c {
			return ErrTransition
		}
		return nil
	}
	if err := w.state.ValidateNext(c); err != nil {
		return err
	}
	if err := w.publish(recordName(c.ExpectedSequence+1, "certificate"), b); err != nil {
		w.failed = true
		return errors.Join(ErrUncertain, err)
	}
	if err := w.state.Apply(cert); err != nil {
		w.failed = true
		return errors.Join(ErrUncertain, err)
	}
	w.pending = nil
	if w.state.Snapshot().Position.HeadID != id {
		w.failed = true
		return ErrWitness
	}
	return w.check()
}

func (w *Witness) Snapshot() (Snapshot, WitnessPin, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return Snapshot{}, WitnessPin{}, err
	}
	return w.state.Snapshot(), w.pin(), nil
}
func (w *Witness) pin() WitnessPin {
	p := WitnessPin{Position: w.state.Snapshot().Position}
	if w.pending != nil {
		p.PendingID, _ = w.pending.ID()
	}
	return p
}
func (w *Witness) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lock == nil {
		return nil
	}
	err := w.lock.Close()
	w.lock = nil
	clear(w.key)
	return err
}

func (w *Witness) check() error {
	if w.lock == nil || w.failed {
		return ErrUncertain
	}
	root, err := os.Lstat(w.path)
	if err != nil || !privateDir(root) || !os.SameFile(w.rootInfo, root) {
		return errors.Join(ErrWitness, err)
	}
	lock, err := os.Lstat(filepath.Join(w.path, "witness.lock"))
	if err != nil || !privateFile(lock) || lock.Size() != 0 || !os.SameFile(w.lockInfo, lock) {
		return errors.Join(ErrWitness, err)
	}
	directory, err := os.Open(w.path)
	if err != nil {
		return err
	}
	// Three transitions can retain at most six records plus scope/ready/lock.
	// Read one extra entry to reject overflow without allocating for an
	// unbounded directory supplied by a damaged or substituted filesystem.
	entries, readErr := directory.ReadDir(10)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) != len(w.files)+1 {
		return ErrWitness
	}
	for _, entry := range entries {
		if entry.Name() == "witness.lock" {
			continue
		}
		expected, ok := w.files[entry.Name()]
		if !ok {
			return ErrWitness
		}
		b, err := readFile(filepath.Join(w.path, entry.Name()), MaximumCertificateBytes)
		if err != nil || !bytes.Equal(b, expected) {
			return errors.Join(ErrWitness, err)
		}
	}
	return nil
}
func (w *Witness) publish(name string, b []byte) (returnErr error) {
	path := filepath.Join(w.path, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		held, err := readFile(path, MaximumCertificateBytes)
		if err != nil || !bytes.Equal(held, b) {
			return errors.Join(ErrWitness, err)
		}
		// A prior process may have died before fsync. Exact retry must confirm
		// durability again before exposing any signature.
		file, err = os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if _, err = file.Write(b); err != nil {
			_ = file.Close()
			return err
		}
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	if w.hook != nil {
		if err := w.hook("before-file-sync"); err != nil {
			return err
		}
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if w.hook != nil {
		if err := w.hook("before-directory-sync"); err != nil {
			return err
		}
	}
	if err := syncDir(w.path); err != nil {
		return err
	}
	if w.hook != nil {
		if err := w.hook("after-directory-sync"); err != nil {
			return err
		}
	}
	w.files[name] = append([]byte(nil), b...)
	return nil
}
func witnessKey(s Scope, key ed25519.PrivateKey) ([32]byte, error) {
	var public [32]byte
	if !validKey(key) {
		return public, ErrWitness
	}
	copy(public[:], key.Public().(ed25519.PublicKey))
	for _, member := range s.Witnesses {
		if member == public {
			return public, nil
		}
	}
	return public, ErrWitness
}
func recordName(sequence uint64, kind string) string { return fmt.Sprintf("%02d.%s", sequence, kind) }
func canonicalPath(path string) (string, error) {
	if path == "" {
		return "", ErrWitness
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", errors.Join(ErrWitness, err)
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}
func privateDir(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm()&0o077 == 0
}
func privateFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0
}
func readFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !privateFile(info) || info.Size() > int64(limit) {
		return nil, ErrWitness
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(info, held) {
		return nil, errors.Join(ErrWitness, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(b) > limit {
		return nil, ErrWitness
	}
	return b, err
}
func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

// SetGuard selects delivery only. The signed policy pins the verification key.
func (w *Witness) SetGuard(client guard.Chooser) { w.mu.Lock(); defer w.mu.Unlock(); w.guard = client }
