//go:build linux || darwin

package pruneservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodygateway"
	"github.com/outcomemesh/outcomemesh/node/custodyguard"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

type Owner struct {
	mu                sync.Mutex
	root              string
	identity          Identity
	descriptor        wire.Descriptor
	config            Config
	inventory         store.ScheduledPruneInventory
	key, transportKey ed25519.PrivateKey
	lock              *os.File
	stamps            map[string]types.Hash
	intent            *wire.Request
	response          []byte
	position          wire.Position
	closed            bool
	failure           error
	hooks             ownerHooks
}

func prepare(ctx context.Context, root string, c Config, id Identity, participant uint32) (wire.Descriptor, store.ScheduledPruneInventory, error) {
	var d wire.Descriptor
	if ctx == nil {
		return d, store.ScheduledPruneInventory{}, ErrOwner
	}
	cid, raw, err := configID(c)
	if err != nil {
		return d, store.ScheduledPruneInventory{}, err
	}
	c, err = DecodeConfig(raw)
	if err != nil {
		return d, store.ScheduledPruneInventory{}, err
	}
	if err = validatePlacement(ctx, root, c); err != nil {
		return d, store.ScheduledPruneInventory{}, err
	}
	v, err := store.LoadScheduledPruneInventory(c.Runtime.InventoryPath, c.Runtime.InventoryID)
	if err != nil {
		return d, v, err
	}
	b, err := inventoryBinding(v)
	if err != nil {
		return d, v, err
	}
	if v.FencePolicy.Service.Service != id.Service {
		return d, v, ErrOwner
	}
	d = wire.Descriptor{RootID: id.RootID, ConfigID: cid, Policy: *v.FencePolicy, Binding: b, Transport: id.Transport, OwnerUID: id.OwnerUID, ParticipantUID: participant}
	if err = validateNetwork(c, d); err != nil {
		return d, v, err
	}
	s, err := store.OpenScheduledPruneEffectService(ctx, c.Runtime)
	if err != nil {
		return d, v, err
	}
	r, err := s.Review(ctx)
	err = errors.Join(err, s.Close())
	if err != nil {
		return d, v, err
	}
	// A descriptor is prepared only for the original admitted, untouched attempt.
	if r.Executor.Stage != store.PruneAdmitted || r.Executor.FenceCandidate != nil || r.Executor.Protection == nil || r.Executor.Protection.Pending != nil {
		return d, v, ErrHeld
	}
	d.ScopeID, d.ReviewID = r.ScopeID, r.ReviewID
	_, err = d.SigningReviewID()
	return d, v, err
}

func Prepare(ctx context.Context, root string, c Config, participant uint32) (d wire.Descriptor, returnErr error) {
	lock, err := lockRoot(root)
	if err != nil {
		return d, err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	id, err := ReadIdentity(root)
	if err != nil {
		return d, err
	}
	if err = checkLayout(root, false); err != nil {
		return d, err
	}
	d, _, err = prepare(ctx, root, c, id, participant)
	return d, err
}

// Configure publishes an exact issuer-approved descriptor and original inventory.
// Configuration is immutable. A partial publication is blocked for inspection.
func Configure(ctx context.Context, root string, d wire.Descriptor, c Config) (returnErr error) {
	if ctx == nil {
		return ErrOwner
	}
	draw, err := d.CanonicalBytes()
	if err != nil {
		return err
	}
	lock, err := lockRoot(root)
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, lock.Close()) }()
	id, err := ReadIdentity(root)
	if err != nil {
		return err
	}
	cid, craw, err := configID(c)
	if err != nil || cid != d.ConfigID || d.RootID != id.RootID || d.Transport != id.Transport || d.OwnerUID != id.OwnerUID || d.Policy.Service.Service != id.Service {
		return ErrOwner
	}
	if _, err = os.Lstat(filepath.Join(root, "descriptor")); err == nil {
		if err = checkLayout(root, true); err != nil {
			return err
		}
		for name, want := range map[string][]byte{"descriptor": draw, "config": craw} {
			got, e := privateRead(filepath.Join(root, name), MaximumConfigBytes)
			if e != nil || !bytes.Equal(got, want) {
				return ErrOwner
			}
		}
		vraw, e := privateRead(filepath.Join(root, "inventory"), store.MaximumScheduledPruneInventoryBytes)
		if e != nil {
			return e
		}
		v, e := store.DecodeScheduledPruneInventory(vraw)
		if e != nil {
			return e
		}
		return validateInventory(v, d)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = checkLayout(root, false); err != nil {
		return err
	}
	actual, v, err := prepare(ctx, root, c, id, d.ParticipantUID)
	if err != nil {
		return err
	}
	a, err := actual.SigningReviewID()
	want, e := d.SigningReviewID()
	if err != nil || e != nil || a != want {
		return ErrOwner
	}
	iv, err := v.CanonicalBytes()
	if err != nil {
		return err
	}
	for _, f := range []struct {
		name string
		raw  []byte
	}{{"config", craw}, {"inventory", iv}, {"descriptor", draw}} {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = publish(filepath.Join(root, f.name), f.raw); err != nil {
			return err
		}
	}
	return nil
}

func checkLayout(root string, configured bool) error {
	want := map[string]bool{"identity": true, "key": true, "transport-key": true, "lock": true, "events": true}
	if configured {
		want["config"] = true
		want["inventory"] = true
		want["descriptor"] = true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) != len(want) {
		return ErrOwner
	}
	for _, e := range entries {
		if !want[e.Name()] {
			return ErrOwner
		}
	}
	events, err := os.ReadDir(filepath.Join(root, "events"))
	if err != nil {
		return err
	}
	for _, e := range events {
		if !configured || e.Name() != "intent" && e.Name() != "result" {
			return ErrOwner
		}
	}
	return nil
}

func openConfigured(ctx context.Context, root string, descriptorID types.Hash) (_ *Owner, returnErr error) {
	if ctx == nil || ctx.Err() != nil || descriptorID.IsZero() {
		return nil, ErrOwner
	}
	o := &Owner{root: root, stamps: make(map[string]types.Hash)}
	var err error
	o.lock, err = lockRoot(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, o.Close())
		}
	}()
	o.identity, err = ReadIdentity(root)
	if err != nil {
		return nil, err
	}
	if err = checkLayout(root, true); err != nil {
		return nil, err
	}
	draw, err := privateRead(filepath.Join(root, "descriptor"), wire.MaximumDescriptorBytes)
	if err != nil {
		return nil, err
	}
	o.descriptor, err = wire.DecodeDescriptor(draw)
	if err != nil {
		return nil, err
	}
	d := o.descriptor
	did, _ := d.ID()
	if did != descriptorID || d.RootID != o.identity.RootID || d.OwnerUID != o.identity.OwnerUID || d.Transport != o.identity.Transport || d.Policy.Service.Service != o.identity.Service {
		return nil, ErrOwner
	}
	craw, err := privateRead(filepath.Join(root, "config"), MaximumConfigBytes)
	if err != nil {
		return nil, err
	}
	o.config, err = DecodeConfig(craw)
	if err != nil {
		return nil, err
	}
	cid, _, err := configID(o.config)
	if err != nil || cid != d.ConfigID {
		return nil, ErrOwner
	}
	if err = validateNetwork(o.config, d); err != nil {
		return nil, err
	}
	iv, err := privateRead(filepath.Join(root, "inventory"), store.MaximumScheduledPruneInventoryBytes)
	if err != nil {
		return nil, err
	}
	o.inventory, err = store.DecodeScheduledPruneInventory(iv)
	if err != nil {
		return nil, err
	}
	if err = validateInventory(o.inventory, d); err != nil {
		return nil, err
	}
	for _, name := range []string{"identity", "key", "transport-key", "lock", "descriptor", "config", "inventory"} {
		if err = o.capture(name); err != nil {
			return nil, err
		}
	}
	o.key, err = readKey(filepath.Join(root, "key"))
	if err != nil {
		return nil, err
	}
	o.transportKey, err = readKey(filepath.Join(root, "transport-key"))
	if err != nil {
		return nil, err
	}
	return o, nil
}

func Open(ctx context.Context, root string, descriptorID types.Hash, expected wire.Position, attempt *wire.Request) (_ *Owner, returnErr error) {
	if !expected.Valid() {
		return nil, ErrPosition
	}
	o, err := openConfigured(ctx, root, descriptorID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			returnErr = errors.Join(returnErr, o.Close())
		}
	}()
	d := o.descriptor
	if err = o.loadEvents(); err != nil {
		return nil, err
	}
	if expected != o.position {
		if attempt == nil || o.intent == nil || *attempt != *o.intent || expected.Sequence > o.position.Sequence || expected.Sequence > 1 {
			return nil, ErrPosition
		}
		if expected.Sequence == 1 {
			p, _ := attempt.IntentPosition()
			if expected != p {
				return nil, ErrPosition
			}
		}
	}
	if attempt != nil {
		if attempt.Authorize(d) != nil || o.intent != nil && *attempt != *o.intent {
			return nil, ErrPosition
		}
	}
	if o.intent != nil {
		if err = o.capture("events/intent"); err != nil {
			return nil, err
		}
	}
	if len(o.response) > 0 {
		if err = o.capture("events/result"); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func (o *Owner) loadEvents() error {
	qraw, err := privateRead(filepath.Join(o.root, "events", "intent"), wire.RequestBytes)
	if err != nil {
		if _, e := os.Lstat(filepath.Join(o.root, "events", "intent")); errors.Is(e, os.ErrNotExist) {
			if _, e = os.Lstat(filepath.Join(o.root, "events", "result")); errors.Is(e, os.ErrNotExist) {
				return nil
			}
		}
		return err
	}
	q, err := wire.DecodeRequest(qraw)
	if err != nil || q.Authorize(o.descriptor) != nil {
		return ErrOwner
	}
	o.intent = &q
	o.position, _ = q.IntentPosition()
	raw, err := privateRead(filepath.Join(o.root, "events", "result"), wire.MaximumResponseBytes)
	if err != nil {
		if _, e := os.Lstat(filepath.Join(o.root, "events", "result")); errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return err
	}
	r, err := wire.DecodeResponse(raw)
	if err != nil || r.Verify(o.descriptor, q) != nil {
		return ErrOwner
	}
	o.response = raw
	o.position, err = r.Position()
	return err
}

func (o *Owner) capture(name string) error {
	v, e := custodygateway.PlacementID(filepath.Join(o.root, name), false)
	if e == nil {
		o.stamps[name] = v
	}
	return e
}
func (o *Owner) checkFiles() error {
	if o.closed {
		return ErrOwner
	}
	if o.failure != nil {
		return o.failure
	}
	id, err := rootID(o.root)
	if err != nil || id != o.identity.RootID {
		return ErrOwner
	}
	if err = checkLayout(o.root, true); err != nil {
		return err
	}
	for name, want := range o.stamps {
		actual, e := custodygateway.PlacementID(filepath.Join(o.root, name), false)
		if e != nil || actual != want {
			return ErrOwner
		}
	}
	return nil
}
func (o *Owner) check() error {
	if err := o.checkFiles(); err != nil {
		return err
	}
	return o.checkEventCount()
}
func (o *Owner) checkEventCount() error {
	events, err := os.ReadDir(filepath.Join(o.root, "events"))
	if err != nil {
		return err
	}
	n := 0
	if o.intent != nil {
		n++
	}
	if len(o.response) > 0 {
		n++
	}
	if len(events) != n {
		return ErrOwner
	}
	return nil
}

func (o *Owner) Descriptor() wire.Descriptor {
	o.mu.Lock()
	defer o.mu.Unlock()
	raw, _ := o.descriptor.CanonicalBytes()
	d, _ := wire.DecodeDescriptor(raw)
	return d
}
func (o *Owner) Snapshot() (Snapshot, error) {
	if o == nil {
		return Snapshot{}, ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.check(); err != nil {
		return Snapshot{}, err
	}
	raw, _ := o.descriptor.CanonicalBytes()
	d, _ := wire.DecodeDescriptor(raw)
	s := Snapshot{Descriptor: d, Position: o.position}
	if o.intent != nil {
		q := *o.intent
		s.Intent = &q
	}
	if len(o.response) > 0 {
		r, err := wire.DecodeResponse(o.response)
		if err != nil {
			return Snapshot{}, err
		}
		s.Response = &r
	}
	return s, nil
}
func (o *Owner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	clear(o.key)
	clear(o.transportKey)
	if o.lock != nil {
		return o.lock.Close()
	}
	return nil
}

func (o *Owner) socketAllowed(path string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.check(); err != nil {
		return err
	}
	for _, p := range append(originalPaths(o.config), o.root) {
		if nested(p, path) || nested(path, p) {
			return ErrOwner
		}
	}
	return nil
}

func (o *Owner) retain(name string, raw []byte) error {
	if err := publishWithHooks(filepath.Join(o.root, "events", name), raw, o.hooks, name); err != nil {
		o.failure = errors.Join(ErrHeld, err)
		return o.failure
	}
	if err := o.capture("events/" + name); err != nil {
		o.failure = err
		return err
	}
	return nil
}
func (o *Owner) finish(q wire.Request, r wire.Response) (wire.Response, error) {
	r.DescriptorID = q.DescriptorID
	r.RequestID, _ = q.ID()
	r, err := r.Sign(o.descriptor, q, o.key)
	if err != nil {
		return wire.Response{}, err
	}
	raw, err := r.CanonicalBytes()
	if err != nil {
		return wire.Response{}, err
	}
	if err = o.retain("result", raw); err != nil {
		return wire.Response{}, err
	}
	o.response = raw
	o.position, _ = r.Position()
	return wire.DecodeResponse(raw)
}

// Execute is a trusted local owner entry point. Serve additionally authenticates
// the participant's kernel UID. A retained intent can only be recovered, never
// executed again, even if no signature or witness reply was received.
func (o *Owner) Execute(ctx context.Context, q wire.Request, approve func(context.Context, wire.Challenge) (custodyfence.Command, error)) (_ wire.Response, returnErr error) {
	if o == nil {
		return wire.Response{}, ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil {
		return wire.Response{}, ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return wire.Response{}, err
	}
	if err := o.check(); err != nil {
		return wire.Response{}, err
	}
	if err := q.Authorize(o.descriptor); err != nil {
		return wire.Response{}, err
	}
	if o.intent != nil {
		if q != *o.intent {
			return wire.Response{}, ErrPosition
		}
		if len(o.response) > 0 {
			return wire.DecodeResponse(o.response)
		}
		return wire.Response{}, ErrHeld
	}
	if approve == nil {
		return wire.Response{}, ErrOwner
	}
	if err := validatePlacement(ctx, o.root, o.config); err != nil {
		return wire.Response{}, err
	}
	identity, err := prunefence.NewServiceIdentity(*o.descriptor.Policy.Service, o.key, &custodyguard.Client{URL: o.config.GuardURL})
	if err != nil {
		return wire.Response{}, err
	}
	defer identity.Close()
	c := o.config.Runtime
	c.ServiceIdentity = identity
	c.CollectPruneCandidate = func(ctx context.Context, candidate prunefence.Candidate) (custodyfence.Certificate, error) {
		scope, draft, e := candidate.Draft()
		if e != nil {
			return custodyfence.Certificate{}, e
		}
		qid, _ := q.ID()
		p, _ := q.IntentPosition()
		challenge := wire.Challenge{DescriptorID: q.DescriptorID, RequestID: qid, Before: p, Candidate: candidate}
		challenge, e = challenge.Sign(o.descriptor, q, o.key)
		if e != nil {
			return custodyfence.Certificate{}, e
		}
		// No caller receives a mutable alias to the candidate used for approval.
		encoded, e := challenge.CanonicalBytes()
		if e != nil {
			return custodyfence.Certificate{}, e
		}
		challenge, e = wire.DecodeChallenge(encoded)
		if e != nil {
			return custodyfence.Certificate{}, e
		}
		if e = o.hooks.reach("candidate-retained"); e != nil {
			return custodyfence.Certificate{}, e
		}
		command, e := approve(ctx, challenge)
		if e != nil {
			return custodyfence.Certificate{}, e
		}
		unsigned := command
		unsigned.Signature = [64]byte{}
		if unsigned != draft || command.Verify(scope) != nil {
			return custodyfence.Certificate{}, ErrOwner
		}
		if e = ctx.Err(); e != nil {
			return custodyfence.Certificate{}, e
		}
		hc := libp2ptransport.DefaultConfig()
		hc.Listen = []string{"/ip4/0.0.0.0/udp/0/quic-v1"}
		key := append(ed25519.PrivateKey(nil), o.transportKey...)
		defer clear(key)
		host, e := libp2ptransport.New(ctx, key, hc, nil)
		if e != nil {
			return custodyfence.Certificate{}, e
		}
		cert, e := prunenet.CollectSignedClaim(ctx, host, o.identity.Transport, o.config.Witnesses, o.config.WitnessTimeout, scope, command)
		return cert, errors.Join(e, host.Close())
	}
	s, err := store.OpenScheduledPruneEffectService(ctx, c)
	if err != nil {
		return wire.Response{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, s.Close()) }()
	review, err := s.Review(ctx)
	if err != nil {
		return wire.Response{}, err
	}
	if review.ScopeID != o.descriptor.ScopeID || review.ReviewID != o.descriptor.ReviewID {
		return wire.Response{}, ErrPosition
	}
	if err = o.check(); err != nil {
		return wire.Response{}, err
	}
	if err = ctx.Err(); err != nil {
		return wire.Response{}, err
	}
	raw, _ := q.CanonicalBytes()
	if err = o.retain("intent", raw); err != nil {
		return wire.Response{}, err
	}
	o.intent = &q
	o.position, _ = q.IntentPosition()
	if err = o.hooks.reach("intent-confirmed"); err != nil {
		return wire.Response{}, errors.Join(ErrHeld, err)
	}
	result, err := s.Execute(ctx, o.descriptor.ReviewID)
	if err != nil {
		return wire.Response{}, errors.Join(ErrHeld, err)
	}
	if result.Commit == nil || result.FenceResult == nil || result.FenceSettlement != nil {
		return wire.Response{}, ErrHeld
	}
	if err = o.hooks.reach("original-result-confirmed"); err != nil {
		return wire.Response{}, errors.Join(ErrHeld, err)
	}
	return o.finish(q, wire.Response{Effect: result.Commit.Effect, Result: result.FenceResult})
}

// Recover reads a confirmed original executor outcome. It cannot use a bare
// storage effect to recreate a lost session or issue a missing signature.
func (o *Owner) Recover(ctx context.Context, q wire.Request) (_ wire.Response, returnErr error) {
	if o == nil {
		return wire.Response{}, ErrOwner
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if ctx == nil {
		return wire.Response{}, ErrOwner
	}
	if err := ctx.Err(); err != nil {
		return wire.Response{}, err
	}
	if err := o.check(); err != nil {
		return wire.Response{}, err
	}
	if q.Authorize(o.descriptor) != nil || o.intent == nil || q != *o.intent {
		return wire.Response{}, ErrPosition
	}
	if len(o.response) > 0 {
		return wire.DecodeResponse(o.response)
	}
	return o.withRetainedResponse(ctx, q, func(r wire.Response) (wire.Response, error) { return o.finish(q, r) })
}

// Keep the original executor and pin owners until the caller's publication ends.
func (o *Owner) withRetainedResponse(ctx context.Context, q wire.Request, use func(wire.Response) (wire.Response, error)) (_ wire.Response, returnErr error) {
	c := o.config.Runtime
	for _, p := range []string{c.ExecutorPath, c.ExecutorPinsPath} {
		if err := privateTreeContext(ctx, p); err != nil {
			return wire.Response{}, err
		}
	}
	var assignment custodyauthority.Assignment
	for _, replica := range o.inventory.Replicas {
		id, _ := replica.Assignment.ID()
		if id == o.descriptor.Binding.AssignmentID {
			assignment = replica.Assignment
		}
	}
	executor, err := store.OpenPinnedPruneExecutor(c.ExecutorPath, c.ExecutorPinsPath, assignment, o.descriptor.Binding.RequestID)
	if err != nil {
		return wire.Response{}, err
	}
	defer func() { returnErr = errors.Join(returnErr, executor.Close()) }()
	snapshot, err := executor.Snapshot()
	if err != nil {
		return wire.Response{}, err
	}
	if _, err = store.RetainedScheduledPruneOutcome(o.inventory, snapshot); err != nil || snapshot.Stage != store.PruneSucceeded || snapshot.Effect == nil {
		return wire.Response{}, errors.Join(ErrHeld, err)
	}
	r := wire.Response{Effect: *snapshot.Effect, Result: snapshot.FenceResult}
	if snapshot.FenceSettlement != nil {
		r.Settlement = &snapshot.FenceSettlement.Decision
	}
	if err = ctx.Err(); err != nil {
		return wire.Response{}, err
	}
	return use(r)
}
