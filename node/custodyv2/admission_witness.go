package custodyv2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	guard "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

// The local byte limit is independent of the signed operation budget. Admission
// reserves room for the selected admit QC and the largest close vote/QC, so a
// normal capacity refusal cannot strand an already admitted job. Physical disk
// failures still require protected deployment and external recovery.
const MaximumAdmissionWitnessBytes = 512 << 20

var ErrAdmissionStorage = errors.New("custody V2 admission journal capacity reserved for drain")

// AdmissionWitness is one original assignment-wide witness owner. The same
// assignment, not each new Plan, selects this history. Enrollment must prevent
// creating another history for the same assignment/key; path stamps alone do
// not protect raw keys, rolled-back backups or deliberate re-enrollment.
// This coordinator does not activate admission in raw V2 execution runtimes.
type AdmissionWitness struct {
	guard              guard.Chooser
	mu                 sync.Mutex
	path               string
	genesis            AdmissionGenesis
	public             [32]byte
	key                ed25519.PrivateKey
	lock               *os.File
	rootInfo, lockInfo os.FileInfo
	state              *AdmissionState
	files              map[string][]byte
	pending            *AdmissionEntry
	bytes              int64
	failed             bool
	hook               func(string) error
}

func admissionRecordName(sequence uint64, kind string) string {
	return fmt.Sprintf("%08d.%s", sequence, kind)
}
func admissionMember(g AdmissionGenesis, key ed25519.PrivateKey) (pub [32]byte, err error) {
	if !validKey(key) {
		return pub, ErrAdmission
	}
	copy(pub[:], key.Public().(ed25519.PublicKey))
	for _, w := range g.Assignment.Policy.Witnesses {
		if pub == w {
			return pub, nil
		}
	}
	return pub, ErrAdmission
}
func admissionPlacement(path string) ([]byte, error) {
	m := map[string]fileStamp{}
	for _, p := range []string{path, filepath.Join(path, "owner.lock")} {
		i, e := os.Lstat(p)
		if e != nil || i.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(ErrAdmission, e)
		}
		s, e := stampFile(i)
		if e != nil {
			return nil, e
		}
		m[p] = s
	}
	return json.Marshal(m)
}
func CreateAdmissionWitness(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, enrollment ...EnrollmentBinding) (_ *AdmissionWitness, returnErr error) {
	enrolled, e := importedEnrollment(g, enrollment)
	if e != nil {
		return nil, e
	}
	state, e := NewAdmissionState(g, pin)
	if e != nil {
		return nil, e
	}
	raw, e := g.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	g, e = DecodeAdmissionGenesis(raw)
	if e != nil {
		return nil, e
	}
	pub, e := admissionMember(g, key)
	if e != nil {
		return nil, e
	}
	path, e = canonical(path)
	if e != nil {
		return nil, e
	}
	if e := os.Mkdir(path, 0700); e != nil {
		return nil, e
	}
	if e := syncDir(filepath.Dir(path)); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	w := &AdmissionWitness{path: path, genesis: g, public: pub, key: append(ed25519.PrivateKey(nil), key...), lock: lock, state: state, files: make(map[string][]byte)}
	defer func() {
		if returnErr != nil {
			clear(w.key)
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	if e := lockRoot(lock); e != nil {
		return nil, e
	}
	if e := lock.Sync(); e != nil {
		return nil, e
	}
	w.rootInfo, e = os.Lstat(path)
	if e != nil {
		return nil, e
	}
	w.lockInfo, e = lock.Stat()
	if e != nil {
		return nil, e
	}
	placement, e := admissionPlacementFor(path, g)
	if e != nil {
		return nil, e
	}
	ready := admissionReady(g, pin, pub, enrolled)
	initialFiles := []struct {
		name string
		b    []byte
	}{{"genesis", raw}, {"placement", placement}}
	if len(enrolled) > 0 {
		initialFiles = append(initialFiles, struct {
			name string
			b    []byte
		}{"enrollment", enrolled})
	}
	initialFiles = append(initialFiles, struct {
		name string
		b    []byte
	}{"ready", ready})
	for _, f := range initialFiles {
		if e := w.publish(f.name, f.b); e != nil {
			return nil, e
		}
	}
	return w, w.check()
}
func OpenAdmissionWitness(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, expected custodyfence.WitnessPin, enrollment ...EnrollmentBinding) (*AdmissionWitness, error) {
	return openAdmissionWitness(path, g, pin, key, enrollment, func(w *AdmissionWitness) error {
		if w.pin() != expected {
			return ErrAdmissionHead
		}
		return nil
	})
}
func RecoverAdmissionVote(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, before custodyfence.WitnessPin, attempt AdmissionEntry, enrollment ...EnrollmentBinding) (*AdmissionWitness, error) {
	raw, e := attempt.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	attempt, e = DecodeAdmissionEntry(raw)
	if e != nil {
		return nil, e
	}
	if e := attempt.Verify(g); e != nil {
		return nil, e
	}
	id, _ := attempt.ID()
	if attempt.ExpectedSequence != before.Position.Sequence || attempt.ExpectedHead != before.Position.HeadID || (!before.PendingID.IsZero() && before.PendingID != id) {
		return nil, ErrAdmissionHead
	}
	return openAdmissionWitness(path, g, pin, key, enrollment, func(w *AdmissionWitness) error {
		actual := w.pin()
		if actual.Position != before.Position || (actual.PendingID != before.PendingID && actual.PendingID != id) {
			return ErrAdmissionHead
		}
		return w.state.ValidateNext(attempt)
	})
}
func RecoverAdmissionCommit(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, before custodyfence.WitnessPin, attempt AdmissionCertificate, enrollment ...EnrollmentBinding) (*AdmissionWitness, error) {
	raw, e := attempt.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	attempt, e = DecodeAdmissionCertificate(raw)
	if e != nil {
		return nil, e
	}
	if e := attempt.Verify(g); e != nil {
		return nil, e
	}
	if attempt.Entry.ExpectedSequence != before.Position.Sequence || attempt.Entry.ExpectedHead != before.Position.HeadID {
		return nil, ErrAdmissionHead
	}
	return openAdmissionWitness(path, g, pin, key, enrollment, func(w *AdmissionWitness) error { return w.canCommitAt(before, attempt, raw) })
}
func openAdmissionWitness(path string, g AdmissionGenesis, pin types.Hash, key ed25519.PrivateKey, enrollment []EnrollmentBinding, accept func(*AdmissionWitness) error) (_ *AdmissionWitness, returnErr error) {
	enrolled, e := importedEnrollment(g, enrollment)
	if e != nil {
		return nil, e
	}
	state, e := NewAdmissionState(g, pin)
	if e != nil {
		return nil, e
	}
	raw, e := g.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	g, e = DecodeAdmissionGenesis(raw)
	if e != nil {
		return nil, e
	}
	pub, e := admissionMember(g, key)
	if e != nil {
		return nil, e
	}
	path, e = canonical(path)
	if e != nil {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.Join(ErrAdmission, e)
	}
	li, e := os.Lstat(filepath.Join(path, "owner.lock"))
	if e != nil || !privateFile(li) || li.Size() != 0 {
		return nil, errors.Join(ErrAdmission, e)
	}
	lock, e := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	w := &AdmissionWitness{path: path, genesis: g, public: pub, key: append(ed25519.PrivateKey(nil), key...), lock: lock, rootInfo: info, state: state, files: make(map[string][]byte)}
	defer func() {
		if returnErr != nil {
			clear(w.key)
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	held, e := lock.Stat()
	if e != nil || !os.SameFile(li, held) {
		return nil, errors.Join(ErrAdmission, e)
	}
	w.lockInfo = held
	if e := lockRoot(lock); e != nil {
		return nil, e
	}
	placement, e := admissionPlacementFor(path, g)
	if e != nil {
		return nil, e
	}
	ready := admissionReady(g, pin, pub, enrolled)
	for _, f := range []struct {
		name string
		want []byte
	}{{"genesis", raw}, {"placement", placement}, {"ready", ready}} {
		b, e := readFile(filepath.Join(path, f.name), len(f.want))
		if e != nil || !bytes.Equal(b, f.want) {
			return nil, errors.Join(ErrAdmission, e)
		}
		w.retain(f.name, b)
	}
	if len(enrolled) > 0 {
		b, e := readFile(filepath.Join(path, "enrollment"), len(enrolled))
		if e != nil || !bytes.Equal(b, enrolled) {
			return nil, errors.Join(ErrEnrollmentRequired, e)
		}
		w.retain("enrollment", b)
	}
	for seq := uint64(1); seq <= MaxAdmissionEntries(g); seq++ {
		voteName := admissionRecordName(seq, "vote")
		b, e := readFile(filepath.Join(path, voteName), MaximumAdmissionEntryBytes)
		if e == nil {
			entry, e := DecodeAdmissionEntry(b)
			if e != nil {
				return nil, e
			}
			if e := w.checkProtectedEnrollment(entry); e != nil {
				return nil, e
			}
			if e := state.ValidateNext(entry); e != nil {
				return nil, e
			}
			w.pending = &entry
			w.retain(voteName, b)
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		if w.bytes > MaximumAdmissionWitnessBytes {
			return nil, ErrAdmissionStorage
		}
		name := admissionRecordName(seq, "certificate")
		b, e = readFile(filepath.Join(path, name), MaximumAdmissionCertificateBytes)
		if errors.Is(e, os.ErrNotExist) {
			break
		}
		if e != nil {
			return nil, e
		}
		cert, e := DecodeAdmissionCertificate(b)
		if e != nil {
			return nil, e
		}
		if e := w.checkProtectedEnrollment(cert.Entry); e != nil {
			return nil, e
		}
		if e := state.Apply(cert); e != nil {
			return nil, e
		}
		w.retain(name, b)
		w.pending = nil
		if w.bytes > MaximumAdmissionWitnessBytes {
			return nil, ErrAdmissionStorage
		}
	}
	if e := w.check(); e != nil {
		return nil, e
	}
	if e := accept(w); e != nil {
		return nil, e
	}
	if e := w.stabilize(); e != nil {
		return nil, e
	}
	return w, nil
}
func (w *AdmissionWitness) retain(name string, b []byte) {
	if old, ok := w.files[name]; ok {
		w.bytes -= int64(len(old))
	}
	w.files[name] = append([]byte(nil), b...)
	w.bytes += int64(len(b))
}
func (w *AdmissionWitness) pin() custodyfence.WitnessPin {
	p := custodyfence.WitnessPin{Position: w.state.Snapshot().Position}
	if w.pending != nil {
		p.PendingID, _ = w.pending.ID()
	}
	return p
}
func (w *AdmissionWitness) Snapshot() (AdmissionSnapshot, custodyfence.WitnessPin, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.check(); e != nil {
		return AdmissionSnapshot{}, custodyfence.WitnessPin{}, e
	}
	return w.state.Snapshot(), w.pin(), nil
}
func (w *AdmissionWitness) VoteAt(before custodyfence.WitnessPin, entry AdmissionEntry) (AdmissionVote, error) {
	raw, e := entry.CanonicalBytes()
	if e != nil {
		return AdmissionVote{}, e
	}
	entry, e = DecodeAdmissionEntry(raw)
	if e != nil {
		return AdmissionVote{}, e
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.check(); e != nil {
		return AdmissionVote{}, e
	}
	id, _ := entry.ID()
	actual := w.pin()
	if actual.Position != before.Position || (!before.PendingID.IsZero() && actual.PendingID != before.PendingID) || (!actual.PendingID.IsZero() && actual.PendingID != id) {
		return AdmissionVote{}, ErrAdmissionHead
	}
	if e := w.checkProtectedEnrollment(entry); e != nil {
		return AdmissionVote{}, e
	}
	if e := w.state.ValidateNext(entry); e != nil {
		return AdmissionVote{}, e
	}
	name := admissionRecordName(entry.ExpectedSequence+1, "vote")
	if e := w.capacity(entry, name, len(raw), true); e != nil {
		return AdmissionVote{}, e
	}
	if e := w.publish(name, raw); e != nil {
		w.failed = true
		return AdmissionVote{}, errors.Join(ErrUncertain, e)
	}
	w.pending = &entry
	if e := w.check(); e != nil {
		w.failed = true
		return AdmissionVote{}, e
	}
	v, e := signAdmissionVote(entry, w.key)
	if e != nil {
		return AdmissionVote{}, e
	}
	if key := AdmissionGuard(entry); key != ([32]byte{}) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		v.GuardSeal, e = guard.Obtain(ctx, w.guard, key, AdmissionGuardRequest(entry, w.public), w.key)
		if e != nil {
			return AdmissionVote{}, e
		}
	}
	return v, nil
}
func (w *AdmissionWitness) canCommitAt(before custodyfence.WitnessPin, cert AdmissionCertificate, raw []byte) error {
	if e := w.checkProtectedEnrollment(cert.Entry); e != nil {
		return e
	}
	actual := w.pin()
	id, _ := cert.Entry.ID()
	if cert.Entry.ExpectedSequence != before.Position.Sequence || cert.Entry.ExpectedHead != before.Position.HeadID {
		return ErrAdmissionHead
	}
	if actual.Position == before.Position {
		if actual.PendingID != before.PendingID {
			return ErrAdmissionHead
		}
		return w.state.ValidateNext(cert.Entry)
	}
	if actual.Position.Sequence != before.Position.Sequence+1 || actual.Position.HeadID != id || !actual.PendingID.IsZero() {
		return ErrAdmissionHead
	}
	if !before.PendingID.IsZero() {
		vote, e := DecodeAdmissionEntry(w.files[admissionRecordName(before.Position.Sequence+1, "vote")])
		if e != nil {
			return ErrAdmissionHead
		}
		priorID, _ := vote.ID()
		if priorID != before.PendingID {
			return ErrAdmissionHead
		}
	}
	if !bytes.Equal(w.files[admissionRecordName(before.Position.Sequence+1, "certificate")], raw) {
		return ErrAdmissionHead
	}
	return nil
}
func (w *AdmissionWitness) CommitAt(before custodyfence.WitnessPin, cert AdmissionCertificate) error {
	raw, e := cert.CanonicalBytes()
	if e != nil {
		return e
	}
	cert, e = DecodeAdmissionCertificate(raw)
	if e != nil {
		return e
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if e := w.check(); e != nil {
		return e
	}
	if e := cert.Verify(w.genesis); e != nil {
		return e
	}
	if e := w.canCommitAt(before, cert, raw); e != nil {
		return e
	}
	if w.state.Snapshot().Position.Sequence == before.Position.Sequence+1 {
		return nil
	}
	name := admissionRecordName(cert.Entry.ExpectedSequence+1, "certificate")
	if e := w.capacity(cert.Entry, name, len(raw), false); e != nil {
		return e
	}
	if e := w.publish(name, raw); e != nil {
		w.failed = true
		return errors.Join(ErrUncertain, e)
	}
	if e := w.state.Apply(cert); e != nil {
		w.failed = true
		return errors.Join(ErrUncertain, e)
	}
	w.pending = nil
	return w.check()
}
func (w *AdmissionWitness) capacity(entry AdmissionEntry, name string, size int, vote bool) error {
	add := int64(size)
	if old, ok := w.files[name]; ok {
		add -= int64(len(old))
	}
	reserve := int64(0)
	if entry.Kind == AdmissionAdmit {
		reserve = int64(MaximumAdmissionEntryBytes + MaximumAdmissionCertificateBytes)
		if vote {
			reserve += int64(MaximumAdmissionCertificateBytes)
		}
	} else if vote {
		reserve = int64(MaximumAdmissionCertificateBytes)
	}
	if w.bytes+add+reserve > MaximumAdmissionWitnessBytes {
		return ErrAdmissionStorage
	}
	return nil
}
func (w *AdmissionWitness) publish(name string, b []byte) error {
	if e := publish(w.path, name, b, w.hook); e != nil {
		return e
	}
	w.retain(name, b)
	return nil
}
func (w *AdmissionWitness) check() error {
	if w.lock == nil || w.failed {
		return ErrUncertain
	}
	info, e := os.Lstat(w.path)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !os.SameFile(info, w.rootInfo) {
		return errors.Join(ErrAdmission, e)
	}
	li, e := os.Lstat(filepath.Join(w.path, "owner.lock"))
	if e != nil || !privateFile(li) || li.Size() != 0 || !os.SameFile(li, w.lockInfo) {
		return errors.Join(ErrAdmission, e)
	}
	placement, e := admissionPlacementFor(w.path, w.genesis)
	if e != nil || !bytes.Equal(placement, w.files["placement"]) {
		return errors.Join(ErrAdmission, e)
	}
	f, e := os.Open(w.path)
	if e != nil {
		return e
	}
	entries, scan := f.ReadDir(int(2*MaxAdmissionEntries(w.genesis) + 6))
	closeErr := f.Close()
	if scan != nil && !errors.Is(scan, io.EOF) {
		return errors.Join(scan, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) != len(w.files)+1 || w.bytes > MaximumAdmissionWitnessBytes {
		return ErrAdmission
	}
	for _, entry := range entries {
		if entry.Name() == "owner.lock" {
			continue
		}
		want, ok := w.files[entry.Name()]
		if !ok {
			return ErrAdmission
		}
		b, e := readFile(filepath.Join(w.path, entry.Name()), len(want))
		if e != nil || !bytes.Equal(want, b) {
			return errors.Join(ErrAdmission, e)
		}
	}
	return nil
}
func (w *AdmissionWitness) stabilize() (returnErr error) {
	defer func() {
		if returnErr != nil {
			w.failed = true
			returnErr = errors.Join(ErrUncertain, returnErr)
		}
	}()
	for name := range w.files {
		f, e := os.OpenFile(filepath.Join(w.path, name), os.O_RDWR, 0)
		if e != nil {
			return e
		}
		if e := errors.Join(f.Sync(), f.Close()); e != nil {
			return e
		}
	}
	if e := w.lock.Sync(); e != nil {
		return e
	}
	if e := syncDir(w.path); e != nil {
		return e
	}
	return w.check()
}
func (w *AdmissionWitness) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lock == nil {
		return nil
	}
	e := w.lock.Close()
	w.lock = nil
	clear(w.key)
	return e
}

func (w *AdmissionWitness) checkProtectedEnrollment(entry AdmissionEntry) error {
	if !ProtectedContext(entry.Context) {
		return nil
	}
	raw, exists := w.files["enrollment"]
	if !exists {
		return ErrEnrollmentRequired
	}
	b, e := DecodeEnrollmentBinding(raw)
	if e != nil {
		return e
	}
	id, e := b.ID()
	if e != nil || entry.Context.Plan.Deployment.EnrollmentID != id {
		return ErrEnrollmentRequired
	}
	return nil
}

// SetGuard selects delivery only. The signed policy pins the verification key.
func (w *AdmissionWitness) SetGuard(client guard.Chooser) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.guard = client
}
