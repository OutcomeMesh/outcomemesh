package remoteworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

var (
	ErrStore      = errors.New("invalid retained remote worker journal")
	ErrBusy       = errors.New("remote worker journal already has an owner")
	ErrClosed     = errors.New("remote worker journal is closed")
	ErrUncertain  = errors.New("remote worker publication is uncertain; close and inspect retained files before an explicit exact retry")
	ErrTransition = errors.New("remote worker record transition is forbidden")
)

type Stage uint8

const (
	Prepared Stage = 1 + iota
	Started
	Sealing
	Sealed
)

// Config requires independently pinned immutable preparation and the exact
// co-signed Begin PROPOSAL. Neither that signature nor Create/Open establishes
// that A admitted Begin, that a channel is current, or that B may execute.
type Config struct {
	Assignment custodyauthority.Assignment
	Plan       Plan
	PlanID     types.Hash
	Begin      custodyauthority.Entry
	BeginID    types.Hash
}

type Snapshot struct {
	PlanID  types.Hash
	BeginID types.Hash
	Stage   Stage
	// Pending is a complete transition record without its confirmation. Open
	// re-syncs existing bytes but never fills that confirmation. Only the exact
	// matching method may explicitly finish it. Sealing already blocks Start.
	Pending   Stage
	Started   bool
	SealingID types.Hash
	SealID    types.Hash
	Seal      *Seal
}

// Journal owns one permanent lock inode for its lifetime. All public methods
// record local history only. It exposes no proof key, execution callback, live
// permit or signed quiescence acknowledgement. Owner-controlled storage and
// independently protected deployment remain required; copying/rolling back all
// files or keys is not fenced by a local filesystem lock.
type Journal struct {
	mu       sync.Mutex
	path     string
	lock     *os.File
	config   Config
	identity map[string]os.FileInfo
	retained map[string][]byte
	state    Snapshot
	failed   bool
	hooks    journalHooks
}

type journalHooks struct{ at func(string) error }

func (h journalHooks) reach(stage string) error {
	if h.at != nil {
		return h.at(stage)
	}
	return nil
}

func freezeConfig(c Config) (Config, error) {
	b, err := c.Assignment.CanonicalBytes()
	if err != nil {
		return Config{}, err
	}
	c.Assignment, err = custodyauthority.DecodeAssignment(b)
	if err != nil {
		return Config{}, err
	}
	b, err = c.Plan.CanonicalBytes()
	if err != nil {
		return Config{}, err
	}
	c.Plan, err = DecodePlan(b)
	if err != nil {
		return Config{}, err
	}
	if err := c.Plan.Validate(c.Assignment); err != nil {
		return Config{}, err
	}
	id, err := c.Plan.ID()
	if err != nil || c.PlanID.IsZero() || id != c.PlanID {
		return Config{}, errors.Join(ErrPlan, err)
	}
	id, err = c.Begin.ID()
	if err != nil || c.BeginID.IsZero() || id != c.BeginID || c.Begin.Version != custodyauthority.Version1 || c.Begin.AuthorityPublicKey != c.Assignment.AuthorityPublicKey {
		return Config{}, errors.Join(ErrPlan, err)
	}
	command := c.Begin.Command
	draft, err := custodyauthority.BuildRemoteBeginCommand(c.Assignment, c.Plan.Admission, c.PlanID, custodyauthority.Position{Sequence: command.ExpectedSequence, HeadID: command.ExpectedHead})
	command.Signature = [64]byte{}
	if err != nil || command != draft {
		return Config{}, errors.Join(ErrPlan, err)
	}
	return c, nil
}

func Create(ctx context.Context, path string, config Config) (*Journal, error) {
	return create(ctx, path, config, journalHooks{})
}
func create(ctx context.Context, path string, config Config, hooks journalHooks) (_ *Journal, returnErr error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	c, err := freezeConfig(config)
	if err != nil {
		return nil, err
	}
	path, err = journalPath(path)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := openWorkerLock(path, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	j := &Journal{path: path, lock: lock, config: c, hooks: hooks}
	for _, artifact := range metadata(c) {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}
		if err := j.publish(artifact.name, artifact.bytes); err != nil {
			return nil, err
		}
	}
	if err := j.refresh(); err != nil {
		return nil, err
	}
	if err := j.check(ctx); err != nil {
		return nil, err
	}
	return j, nil
}

// Open uses only an existing complete bootstrap and exact independent pins.
// It never initializes missing roots, replaces a file, deletes partial evidence,
// runs work, signs, or confirms an unconfirmed transition automatically.
func Open(ctx context.Context, path string, config Config) (_ *Journal, returnErr error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	c, err := freezeConfig(config)
	if err != nil {
		return nil, err
	}
	path, err = journalPath(path)
	if err != nil {
		return nil, err
	}
	lock, err := openWorkerLock(path, false)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, lock.Close())
		}
	}()
	j := &Journal{path: path, lock: lock, config: c}
	if err := j.refresh(); err != nil {
		return nil, err
	}
	// Existing canonical records may be re-synced; no missing record or pin is
	// invented and the conservative pending stage is retained unchanged.
	for name := range j.retained {
		if err := syncFile(filepath.Join(path, name)); err != nil {
			return nil, err
		}
	}
	if err := syncDirectory(path); err != nil {
		return nil, err
	}
	if err := j.check(ctx); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *Journal) Snapshot(ctx context.Context) (Snapshot, error) {
	if j == nil {
		return Snapshot{}, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.check(ctx); err != nil {
		return Snapshot{}, err
	}
	return detached(j.state), nil
}

// Start records only a local start marker. It does not admit Begin or permit
// any signer, object access, network work, or effect. A future owned endpoint
// must separately prove current A authority before all actual execution.
func (j *Journal) Start(ctx context.Context, expectedBeginID types.Hash) (Snapshot, error) {
	if j == nil {
		return Snapshot{}, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.check(ctx); err != nil {
		return Snapshot{}, err
	}
	if expectedBeginID.IsZero() || expectedBeginID != j.config.BeginID {
		return Snapshot{}, ErrPlan
	}
	if j.state.Stage >= Sealing {
		return Snapshot{}, ErrTransition
	}
	if j.state.Pending != 0 && j.state.Pending != Started {
		return Snapshot{}, ErrUncertain
	}
	if err := j.transition(ctx, startName, Started, startBytes(j.config.PlanID, j.config.BeginID)); err != nil {
		return Snapshot{}, err
	}
	return detached(j.state), nil
}

// BeginSeal irreversibly closes the local Start branch before any caller's
// future drain procedure. It calls no drain procedure itself. Even an
// unconfirmed complete sealing record prevents Start after reopen.
func (j *Journal) BeginSeal(ctx context.Context) (Snapshot, error) {
	if j == nil {
		return Snapshot{}, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.check(ctx); err != nil {
		return Snapshot{}, err
	}
	if j.state.Stage == Sealed {
		return Snapshot{}, ErrTransition
	}
	if j.state.Pending != 0 && j.state.Pending != Sealing {
		return Snapshot{}, ErrUncertain
	}
	var startID types.Hash
	if j.state.Started {
		startID = recordID(startName, startBytes(j.config.PlanID, j.config.BeginID))
	}
	if err := j.transition(ctx, sealingName, Sealing, sealingBytes(j.config.PlanID, j.config.BeginID, startID)); err != nil {
		return Snapshot{}, err
	}
	return detached(j.state), nil
}

// CommitSeal retains a local tombstone only. Calling it does not establish
// physical handler drain or make its result a signed drain acknowledgement.
// Unseen is valid only without a Start record. NoResult means UNKNOWN after
// Start, never no-effect/success. Result freshness is outside this package.
func (j *Journal) CommitSeal(ctx context.Context, disposition Disposition, resultID types.Hash) (Seal, error) {
	if j == nil {
		return Seal{}, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.check(ctx); err != nil {
		return Seal{}, err
	}
	if j.state.Stage < Sealing || j.state.Pending != 0 && j.state.Pending != Sealed {
		return Seal{}, ErrTransition
	}
	s := Seal{Version: Version0, PlanID: j.config.PlanID, BeginID: j.config.BeginID, SealingID: j.state.SealingID, Disposition: disposition, ResultID: resultID}
	if err := s.validateBinding(j.config.PlanID, j.config.BeginID, j.state.SealingID, j.state.Started); err != nil {
		return Seal{}, err
	}
	b, _ := s.CanonicalBytes()
	if j.state.Seal != nil && *j.state.Seal != s {
		return Seal{}, ErrSeal
	}
	if err := j.transition(ctx, sealName, Sealed, b); err != nil {
		return Seal{}, err
	}
	return s, nil
}

// DrainedDraft returns only an unsigned static RemoteDrained proposal for this
// exact confirmed local tombstone and explicit authority position. It does not
// prove that Begin is live/applied, perform a drain, or sign a quiescence claim.
func (j *Journal) DrainedDraft(ctx context.Context, expectedSealID types.Hash, position custodyauthority.Position) (custodyauthority.Command, error) {
	if j == nil {
		return custodyauthority.Command{}, ErrClosed
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.check(ctx); err != nil {
		return custodyauthority.Command{}, err
	}
	if j.state.Stage != Sealed || j.state.Pending != 0 || expectedSealID.IsZero() || j.state.SealID != expectedSealID || j.state.Seal == nil {
		return custodyauthority.Command{}, ErrSeal
	}
	if err := j.state.Seal.validateBinding(j.config.PlanID, j.config.BeginID, j.state.SealingID, j.state.Started); err != nil {
		return custodyauthority.Command{}, err
	}
	return custodyauthority.BuildRemoteDrainedCommand(j.config.Assignment, j.config.Begin, expectedSealID, position)
}

func (j *Journal) transition(ctx context.Context, name string, stage Stage, b []byte) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := j.publish(name, b); err != nil {
		return j.poison(err)
	}
	if err := j.hooks.reach(name + "-record-durable"); err != nil {
		return j.poison(err)
	}
	if err := checkContext(ctx); err != nil {
		return j.poison(err)
	}
	confirmation := confirmationBytes(j.config.PlanID, j.config.BeginID, recordID(name, b))
	if err := j.publish(confirmName(stage), confirmation); err != nil {
		return j.poison(err)
	}
	if err := j.refresh(); err != nil {
		return j.poison(err)
	}
	if j.state.Stage != stage || j.state.Pending != 0 {
		return j.poison(ErrStore)
	}
	return nil
}

func (j *Journal) check(ctx context.Context) error {
	if j.lock == nil {
		return ErrClosed
	}
	if j.failed {
		return ErrUncertain
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	identities, err := inspect(j.path, j.lock)
	if err != nil {
		return j.poison(err)
	}
	if len(identities) != len(j.identity) {
		return j.poison(ErrStore)
	}
	for name, before := range j.identity {
		current, ok := identities[name]
		if !ok || !os.SameFile(before, current) {
			return j.poison(ErrStore)
		}
	}
	for name, want := range j.retained {
		got, err := readRegular(filepath.Join(j.path, name), len(want))
		if err != nil || !bytes.Equal(want, got) {
			return j.poison(errors.Join(ErrStore, err))
		}
	}
	return nil
}

func (j *Journal) poison(err error) error { j.failed = true; return errors.Join(ErrUncertain, err) }
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return nil
	}
	err := j.lock.Close()
	j.lock = nil
	return err
}
func detached(s Snapshot) Snapshot {
	if s.Seal != nil {
		copy := *s.Seal
		s.Seal = &copy
	}
	return s
}
func checkContext(ctx context.Context) error {
	if ctx == nil {
		return ErrStore
	}
	return ctx.Err()
}
