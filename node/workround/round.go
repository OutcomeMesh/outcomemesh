package workround

import (
	"context"
	"errors"
	"sync"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workminer"
	"github.com/outcomemesh/outcomemesh/node/workpool"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

var (
	ErrConfiguration = errors.New("invalid WorkGraph round configuration")
	ErrRetired       = errors.New("WorkGraph round timestamp generation retired")
)

// Round owns objective work for one timestamp generation. Timestamp may roll
// forward over a shared pool, but a new parent, target, payload or MTP must
// create an unrelated Round; shares are never carried across that boundary.
type Round struct {
	payload *workblock.Payload
	pool    *workpool.Pool
	session *worksession.Node
	context workgraph.Context

	lifecycleMu sync.Mutex
	lifecycle   context.Context
	cancel      context.CancelFunc
	retired     bool
	active      sync.WaitGroup
}

func New(payload *workblock.Payload, sessionConfig worksession.Config) (*Round, error) {
	if payload == nil {
		return nil, ErrConfiguration
	}
	miningContext, err := payload.MiningContext()
	if err != nil {
		return nil, ErrConfiguration
	}
	pool, err := workpool.New(miningContext)
	if err != nil {
		return nil, ErrConfiguration
	}
	session, err := worksession.New(pool, sessionConfig)
	if err != nil {
		return nil, ErrConfiguration
	}
	return newGeneration(payload, pool, session, miningContext), nil
}

func (round *Round) Context() (workgraph.Context, error) {
	if round == nil || round.pool == nil {
		return workgraph.Context{}, ErrConfiguration
	}
	return round.context, nil
}

func (round *Round) Status() (workpool.Status, error) {
	if round == nil || round.pool == nil {
		return workpool.Status{}, ErrConfiguration
	}
	return round.pool.Status(), nil
}

func (round *Round) Add(share workgraph.Share) (types.Hash, error) {
	if round == nil || round.pool == nil {
		return types.Hash{}, ErrConfiguration
	}
	return round.pool.Add(share)
}

// IDs returns the full sorted local inventory for bounded gossip handoff.
func (round *Round) IDs() ([]types.Hash, error) {
	if round == nil || round.pool == nil {
		return nil, ErrConfiguration
	}
	return round.pool.IDs(), nil
}

// Template returns the current hard/weak work preimage with the round's latest
// accepted pool tips. Workers may search it directly, then return weak results
// through Add or hard results through Finalize.
func (round *Round) Template(miner types.Address, inclusionRoot types.Hash) (workgraph.Share, error) {
	if round == nil || round.payload == nil || round.pool == nil {
		return workgraph.Share{}, ErrConfiguration
	}
	if round.isRetired() {
		return workgraph.Share{}, ErrRetired
	}
	return round.payload.SealTemplate(miner, inclusionRoot, round.pool.Parents())
}

// Mine searches the shared weak/hard nonce space and returns a finalized block
// whose share body is the canonical closure selected from this round's pool.
func (round *Round) Mine(
	ctx context.Context,
	miner types.Address,
	inclusionRoot types.Hash,
	startNonce uint64,
	publish workminer.PublishFunc,
) (workminer.Result, error) {
	if round == nil || round.payload == nil || round.pool == nil {
		return workminer.Result{}, ErrConfiguration
	}
	miningContext, finish, err := round.begin(ctx)
	if err != nil {
		return workminer.Result{}, err
	}
	defer finish()
	minerLoop, err := workminer.New(round.payload, round.pool, miner, inclusionRoot, publish)
	if err != nil {
		return workminer.Result{}, err
	}
	return minerLoop.Mine(miningContext, startNonce)
}

// Finalize validates a hard solution against the same pool and payload. This
// is the admission path for a hard anchor produced by another local worker or,
// after authenticated transport, a remote worker assigned this exact round.
func (round *Round) Finalize(anchor workgraph.Share) (workblock.Block, workblock.Result, error) {
	if round == nil || round.payload == nil || round.pool == nil {
		return workblock.Block{}, workblock.Result{}, ErrConfiguration
	}
	_, finish, err := round.begin(context.Background())
	if err != nil {
		return workblock.Block{}, workblock.Result{}, err
	}
	defer finish()
	shares, err := round.pool.CommittedShares(anchor)
	if err != nil {
		return workblock.Block{}, workblock.Result{}, err
	}
	return round.payload.Finalize(anchor, shares)
}

// RollForward retires objective work for this timestamp, waits until an
// in-flight miner/finalizer has stopped, then creates a new timestamp
// generation over the same pool and stable wire session.
func (round *Round) RollForward(payload *workblock.Payload) (*Round, error) {
	if round == nil || round.payload == nil || round.pool == nil || round.session == nil || payload == nil {
		return nil, ErrConfiguration
	}
	next, err := payload.MiningContext()
	if err != nil || !compatibleContext(round.context, next) || next.AnchorTimestamp <= round.context.AnchorTimestamp {
		return nil, ErrConfiguration
	}
	if !round.retire() {
		return nil, ErrRetired
	}
	if err := round.pool.RollForward(next); err != nil {
		return nil, err
	}
	return newGeneration(payload, round.pool, round.session, next), nil
}

func (round *Round) Relay(ctx context.Context, stream worksession.Stream) (worksession.Stats, error) {
	if round == nil || round.session == nil {
		return worksession.Stats{}, ErrConfiguration
	}
	return round.session.Relay(ctx, stream)
}

func (round *Round) Probe(ctx context.Context, stream worksession.Stream) error {
	if round == nil || round.session == nil {
		return ErrConfiguration
	}
	return round.session.Probe(ctx, stream)
}

func (round *Round) RelayInventory(
	ctx context.Context,
	stream worksession.Stream,
	ids []types.Hash,
) (worksession.Stats, error) {
	if round == nil || round.session == nil {
		return worksession.Stats{}, ErrConfiguration
	}
	return round.session.RelayInventory(ctx, stream, ids)
}

func (round *Round) Serve(ctx context.Context, stream worksession.Stream) error {
	if round == nil || round.session == nil {
		return ErrConfiguration
	}
	return round.session.Serve(ctx, stream)
}

func (round *Round) ServeAccepted(ctx context.Context, stream worksession.Stream, observe worksession.AcceptFunc) error {
	if round == nil || round.session == nil {
		return ErrConfiguration
	}
	return round.session.ServeAccepted(ctx, stream, observe)
}

func newGeneration(
	payload *workblock.Payload,
	pool *workpool.Pool,
	session *worksession.Node,
	miningContext workgraph.Context,
) *Round {
	lifecycle, cancel := context.WithCancel(context.Background())
	return &Round{
		payload: payload, pool: pool, session: session, context: miningContext,
		lifecycle: lifecycle, cancel: cancel,
	}
}

func (round *Round) begin(parent context.Context) (context.Context, func(), error) {
	if parent == nil {
		return nil, nil, ErrConfiguration
	}
	round.lifecycleMu.Lock()
	if round.retired {
		round.lifecycleMu.Unlock()
		return nil, nil, ErrRetired
	}
	round.active.Add(1)
	lifecycle := round.lifecycle
	round.lifecycleMu.Unlock()
	activity, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(lifecycle, cancel)
	return activity, func() {
		stop()
		cancel()
		round.active.Done()
	}, nil
}

func (round *Round) retire() bool {
	round.lifecycleMu.Lock()
	if round.retired {
		round.lifecycleMu.Unlock()
		return false
	}
	round.retired = true
	round.cancel()
	round.lifecycleMu.Unlock()
	round.active.Wait()
	return true
}

func (round *Round) isRetired() bool {
	round.lifecycleMu.Lock()
	defer round.lifecycleMu.Unlock()
	return round.retired
}

func compatibleContext(left, right workgraph.Context) bool {
	left.AnchorMiner = types.Address{}
	right.AnchorMiner = types.Address{}
	left.AnchorTimestamp = 0
	right.AnchorTimestamp = 0
	return left == right
}
