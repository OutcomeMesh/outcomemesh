package custodyregistry

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

const MaximumWitnessBytes = 20 << 20

var ErrUncertain = errors.New("registry witness has an uncertain retained write")
var ErrWitnessStorage = errors.New("registry witness retained bytes exceed capacity")

// Witness owns one original registry history and one durable proposal lock.
// Its signatures select an assignment only; they are not execution grants.
// Independently protected enrollment must prohibit another history for the same
// anchor/key. Local stamps do not protect raw keys or rollback of every pin.
type Witness struct {
	mu                 sync.Mutex
	path               string
	genesis            Genesis
	key                ed25519.PrivateKey
	public             [32]byte
	lock               *os.File
	rootInfo, lockInfo os.FileInfo
	state              *State
	files              map[string][]byte
	pending            *Selection
	bytes              int64
	failed             bool
	hook               func(string) error
}

func witnessMember(g Genesis, key ed25519.PrivateKey) (pub [32]byte, err error) {
	if len(key) != ed25519.PrivateKeySize {
		return pub, ErrRegistry
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	valid := bytes.Equal(derived, key)
	clear(derived)
	if !valid {
		return pub, ErrRegistry
	}
	copy(pub[:], key.Public().(ed25519.PublicKey))
	for _, member := range g.Witnesses {
		if member == pub {
			return pub, nil
		}
	}
	return pub, ErrRegistry
}

func witnessConfig(g Genesis, pin types.Hash, key ed25519.PrivateKey) (Genesis, []byte, [32]byte, *State, error) {
	raw, err := g.CanonicalBytes()
	if err != nil {
		return Genesis{}, nil, [32]byte{}, nil, err
	}
	g, err = DecodeGenesis(raw)
	if err != nil {
		return Genesis{}, nil, [32]byte{}, nil, err
	}
	state, err := NewState(g, pin)
	if err != nil {
		return Genesis{}, nil, [32]byte{}, nil, err
	}
	pub, err := witnessMember(g, key)
	return g, raw, pub, state, err
}

func witnessReady(g Genesis, pin types.Hash, pub [32]byte) []byte {
	did, _ := g.DescriptorID()
	b := append([]byte("OMCRWRD1"), pin[:]...)
	b = append(b, did[:]...)
	return append(b, pub[:]...)
}

// CreateWitness enrolls an absent private root and closes it before return.
// An interrupted initialization remains blocked; this never repairs/replaces it.
func CreateWitness(path string, g Genesis, pin types.Hash, key ed25519.PrivateKey) (returnErr error) {
	g, raw, pub, _, err := witnessConfig(g, pin, key)
	if err != nil {
		return err
	}
	path, err = witnessCanonical(path)
	if err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	if err := witnessSyncDir(filepath.Dir(path)); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	if err := witnessLock(lock); err != nil {
		return err
	}
	if err := lock.Sync(); err != nil {
		return err
	}
	placement, err := witnessPlacement(path)
	if err != nil {
		return err
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"origin", raw}, {"placement", placement}, {"ready", witnessReady(g, pin, pub)}} {
		if err := witnessPublish(path, file.name, file.raw, nil); err != nil {
			return err
		}
	}
	return nil
}

func OpenWitness(path string, g Genesis, pin types.Hash, key ed25519.PrivateKey, expected custodyfence.WitnessPin) (*Witness, error) {
	return openWitness(path, g, pin, key, func(w *Witness) error {
		if w.pin() != expected {
			return ErrPosition
		}
		return nil
	})
}

func RecoverVote(path string, g Genesis, pin types.Hash, key ed25519.PrivateKey, before custodyfence.WitnessPin, attempt Selection) (*Witness, error) {
	attempt, raw, err := witnessSelection(attempt)
	if err != nil {
		return nil, err
	}
	_ = raw
	if err := attempt.Verify(g); err != nil {
		return nil, err
	}
	id, _ := attempt.ID()
	if before.Position != (custodyfence.Position{HeadID: pin}) || (!before.PendingID.IsZero() && before.PendingID != id) {
		return nil, ErrPosition
	}
	return openWitness(path, g, pin, key, func(w *Witness) error {
		actual := w.pin()
		if actual.Position != before.Position || (actual.PendingID != before.PendingID && actual.PendingID != id) {
			return ErrPosition
		}
		return w.state.ValidateNext(attempt)
	})
}

func RecoverCommit(path string, g Genesis, pin types.Hash, key ed25519.PrivateKey, before custodyfence.WitnessPin, attempt Certificate) (*Witness, error) {
	attempt, raw, err := witnessCertificate(attempt)
	if err != nil {
		return nil, err
	}
	if err := attempt.Verify(g); err != nil {
		return nil, err
	}
	return openWitness(path, g, pin, key, func(w *Witness) error { return w.canCommitAt(before, attempt, raw) })
}

func openWitness(path string, g Genesis, pin types.Hash, key ed25519.PrivateKey, accept func(*Witness) error) (_ *Witness, returnErr error) {
	g, raw, pub, state, err := witnessConfig(g, pin, key)
	if err != nil {
		return nil, err
	}
	path, err = witnessCanonical(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, errors.Join(ErrRegistry, err)
	}
	li, err := os.Lstat(filepath.Join(path, "owner.lock"))
	if err != nil || !witnessPrivate(li) || li.Size() != 0 {
		return nil, errors.Join(ErrRegistry, err)
	}
	lock, err := os.OpenFile(filepath.Join(path, "owner.lock"), os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	w := &Witness{path: path, genesis: g, key: append(ed25519.PrivateKey(nil), key...), public: pub, lock: lock, rootInfo: info, state: state, files: map[string][]byte{}}
	defer func() {
		if returnErr != nil {
			clear(w.key)
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	held, err := lock.Stat()
	if err != nil || !os.SameFile(li, held) {
		return nil, errors.Join(ErrRegistry, err)
	}
	w.lockInfo = held
	if err := witnessLock(lock); err != nil {
		return nil, err
	}
	placement, err := witnessPlacement(path)
	if err != nil {
		return nil, err
	}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"origin", raw}, {"placement", placement}, {"ready", witnessReady(g, pin, pub)}} {
		got, err := witnessRead(filepath.Join(path, file.name), len(file.raw))
		if err != nil || !bytes.Equal(got, file.raw) {
			return nil, errors.Join(ErrRegistry, err)
		}
		w.retain(file.name, got)
	}
	proposal, err := witnessRead(filepath.Join(path, "selection.vote"), MaximumSelectionBytes)
	if err == nil {
		selection, err := DecodeSelection(proposal)
		if err != nil {
			return nil, err
		}
		if err := state.ValidateNext(selection); err != nil {
			return nil, err
		}
		w.pending = &selection
		w.retain("selection.vote", proposal)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	certificate, err := witnessRead(filepath.Join(path, "selection.certificate"), MaximumCertificateBytes)
	if err == nil {
		cert, err := DecodeCertificate(certificate)
		if err != nil {
			return nil, err
		}
		if err := state.Apply(cert); err != nil {
			return nil, err
		}
		w.retain("selection.certificate", certificate)
		w.pending = nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := w.check(); err != nil {
		return nil, err
	}
	if err := accept(w); err != nil {
		return nil, err
	}
	if err := w.stabilize(); err != nil {
		return nil, err
	}
	return w, nil
}

func witnessSelection(s Selection) (Selection, []byte, error) {
	raw, err := s.CanonicalBytes()
	if err != nil {
		return Selection{}, nil, err
	}
	s, err = DecodeSelection(raw)
	return s, raw, err
}
func witnessCertificate(c Certificate) (Certificate, []byte, error) {
	raw, err := c.CanonicalBytes()
	if err != nil {
		return Certificate{}, nil, err
	}
	c, err = DecodeCertificate(raw)
	return c, raw, err
}
func (w *Witness) retain(name string, raw []byte) {
	if old, ok := w.files[name]; ok {
		w.bytes -= int64(len(old))
	}
	w.files[name] = append([]byte(nil), raw...)
	w.bytes += int64(len(raw))
}
func (w *Witness) pin() custodyfence.WitnessPin {
	p := custodyfence.WitnessPin{Position: w.state.Snapshot().Position}
	if w.pending != nil {
		p.PendingID, _ = w.pending.ID()
	}
	return p
}
func (w *Witness) Snapshot() (Snapshot, custodyfence.WitnessPin, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return Snapshot{}, custodyfence.WitnessPin{}, err
	}
	return w.state.Snapshot(), w.pin(), nil
}
func (w *Witness) VoteAt(before custodyfence.WitnessPin, selection Selection) (Vote, error) {
	selection, raw, err := witnessSelection(selection)
	if err != nil {
		return Vote{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return Vote{}, err
	}
	id, _ := selection.ID()
	actual := w.pin()
	if actual.Position != before.Position || (!before.PendingID.IsZero() && actual.PendingID != before.PendingID) || (!actual.PendingID.IsZero() && actual.PendingID != id) {
		return Vote{}, ErrPosition
	}
	if err := w.state.ValidateNext(selection); err != nil {
		return Vote{}, err
	}
	if err := w.write("selection.vote", raw); err != nil {
		return Vote{}, err
	}
	w.pending = &selection
	if err := w.check(); err != nil {
		w.failed = true
		return Vote{}, errors.Join(ErrUncertain, err)
	}
	return SignVote(w.genesis, selection, w.key)
}
func (w *Witness) canCommitAt(before custodyfence.WitnessPin, cert Certificate, raw []byte) error {
	rid, _ := w.genesis.ID()
	if before.Position != (custodyfence.Position{HeadID: rid}) {
		return ErrPosition
	}
	actual := w.pin()
	id, _ := cert.Selection.ID()
	if actual.Position == before.Position {
		if actual.PendingID != before.PendingID {
			return ErrPosition
		}
		return w.state.ValidateNext(cert.Selection)
	}
	if actual.Position.Sequence != 1 || actual.Position.HeadID != id || !actual.PendingID.IsZero() {
		return ErrPosition
	}
	if !before.PendingID.IsZero() {
		vote, err := DecodeSelection(w.files["selection.vote"])
		if err != nil {
			return ErrPosition
		}
		prior, _ := vote.ID()
		if prior != before.PendingID {
			return ErrPosition
		}
	}
	if !bytes.Equal(w.files["selection.certificate"], raw) {
		return ErrPosition
	}
	return nil
}
func (w *Witness) CommitAt(before custodyfence.WitnessPin, cert Certificate) error {
	cert, raw, err := witnessCertificate(cert)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(); err != nil {
		return err
	}
	if err := cert.Verify(w.genesis); err != nil {
		return err
	}
	if err := w.canCommitAt(before, cert, raw); err != nil {
		return err
	}
	if w.state.Snapshot().Position.Sequence == 1 {
		return nil
	}
	if err := w.write("selection.certificate", raw); err != nil {
		return err
	}
	if err := w.state.Apply(cert); err != nil {
		w.failed = true
		return errors.Join(ErrUncertain, err)
	}
	w.pending = nil
	if err := w.check(); err != nil {
		w.failed = true
		return errors.Join(ErrUncertain, err)
	}
	return nil
}
func (w *Witness) write(name string, raw []byte) error {
	add := int64(len(raw))
	if old, ok := w.files[name]; ok {
		add -= int64(len(old))
	}
	if w.bytes+add > MaximumWitnessBytes {
		return ErrWitnessStorage
	}
	if err := witnessPublish(w.path, name, raw, w.hook); err != nil {
		w.failed = true
		return errors.Join(ErrUncertain, err)
	}
	w.retain(name, raw)
	return nil
}
func (w *Witness) check() error {
	if w.lock == nil || w.failed {
		return ErrUncertain
	}
	info, err := os.Lstat(w.path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || !os.SameFile(info, w.rootInfo) {
		return errors.Join(ErrRegistry, err)
	}
	li, err := os.Lstat(filepath.Join(w.path, "owner.lock"))
	if err != nil || !witnessPrivate(li) || li.Size() != 0 || !os.SameFile(li, w.lockInfo) {
		return errors.Join(ErrRegistry, err)
	}
	placement, err := witnessPlacement(w.path)
	if err != nil || !bytes.Equal(placement, w.files["placement"]) {
		return errors.Join(ErrRegistry, err)
	}
	f, err := os.Open(w.path)
	if err != nil {
		return err
	}
	entries, scan := f.ReadDir(7)
	closeErr := f.Close()
	if scan != nil && !errors.Is(scan, io.EOF) || closeErr != nil {
		return errors.Join(scan, closeErr)
	}
	if len(entries) != len(w.files)+1 || w.bytes > MaximumWitnessBytes {
		return ErrRegistry
	}
	for _, entry := range entries {
		if entry.Name() == "owner.lock" {
			continue
		}
		want, ok := w.files[entry.Name()]
		if !ok {
			return ErrRegistry
		}
		actual, err := witnessRead(filepath.Join(w.path, entry.Name()), len(want))
		if err != nil || !bytes.Equal(actual, want) {
			return errors.Join(ErrRegistry, err)
		}
	}
	return nil
}
func (w *Witness) stabilize() (returnErr error) {
	defer func() {
		if returnErr != nil {
			w.failed = true
			returnErr = errors.Join(ErrUncertain, returnErr)
		}
	}()
	if err := w.check(); err != nil {
		return err
	}
	for name := range w.files {
		path := filepath.Join(w.path, name)
		before, err := os.Lstat(path)
		if err != nil || !witnessPrivate(before) {
			return errors.Join(ErrRegistry, err)
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		after, err := f.Stat()
		if err != nil || !os.SameFile(before, after) {
			_ = f.Close()
			return errors.Join(ErrRegistry, err)
		}
		if err := errors.Join(f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	if err := w.lock.Sync(); err != nil {
		return err
	}
	if err := witnessSyncDir(w.path); err != nil {
		return err
	}
	return w.check()
}
func (w *Witness) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	clear(w.key)
	if w.lock == nil {
		return nil
	}
	err := w.lock.Close()
	w.lock = nil
	return err
}
