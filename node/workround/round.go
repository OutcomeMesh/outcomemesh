package workround

import (
	"context"
	"errors"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/core/workblock"
	"github.com/outcomemesh/outcomemesh/core/workgraph"
	"github.com/outcomemesh/outcomemesh/node/workminer"
	"github.com/outcomemesh/outcomemesh/node/workpool"
	"github.com/outcomemesh/outcomemesh/node/worksession"
)

var ErrConfiguration = errors.New("invalid WorkGraph round configuration")

// Round owns all ephemeral work for one immutable parent/target/payload
// context. A new chain parent or payload must create a new Round; shares are
// never carried across that boundary.
type Round struct {
	payload *workblock.Payload
	pool    *workpool.Pool
	session *worksession.Node
	context workgraph.Context
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
	return &Round{payload: payload, pool: pool, session: session, context: miningContext}, nil
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

// Template returns the current hard/weak work preimage with the round's latest
// accepted pool tips. Workers may search it directly, then return weak results
// through Add or hard results through Finalize.
func (round *Round) Template(miner types.Address, inclusionRoot types.Hash) (workgraph.Share, error) {
	if round == nil || round.payload == nil || round.pool == nil {
		return workgraph.Share{}, ErrConfiguration
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
	minerLoop, err := workminer.New(round.payload, round.pool, miner, inclusionRoot, publish)
	if err != nil {
		return workminer.Result{}, err
	}
	return minerLoop.Mine(ctx, startNonce)
}

// Finalize validates a hard solution against the same pool and payload. This
// is the admission path for a hard anchor produced by another local worker or,
// after authenticated transport, a remote worker assigned this exact round.
func (round *Round) Finalize(anchor workgraph.Share) (workblock.Block, workblock.Result, error) {
	if round == nil || round.payload == nil || round.pool == nil {
		return workblock.Block{}, workblock.Result{}, ErrConfiguration
	}
	shares, err := round.pool.CommittedShares(anchor)
	if err != nil {
		return workblock.Block{}, workblock.Result{}, err
	}
	return round.payload.Finalize(anchor, shares)
}

func (round *Round) Relay(ctx context.Context, stream worksession.Stream) (worksession.Stats, error) {
	if round == nil || round.session == nil {
		return worksession.Stats{}, ErrConfiguration
	}
	return round.session.Relay(ctx, stream)
}

func (round *Round) Serve(ctx context.Context, stream worksession.Stream) error {
	if round == nil || round.session == nil {
		return ErrConfiguration
	}
	return round.session.Serve(ctx, stream)
}
