package syncer

import (
	"bytes"
	"errors"
	"math/big"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/block"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/chain"
	"github.com/outcomemesh/outcomemesh/node/wire"
	"github.com/outcomemesh/outcomemesh/storage"
)

var (
	ErrConfiguration    = errors.New("invalid sync service configuration")
	ErrNetwork          = errors.New("peer belongs to a different network")
	ErrGenesis          = errors.New("peer has a different genesis")
	ErrNoCommonAncestor = errors.New("no common canonical ancestor")
	ErrBatch            = errors.New("invalid block sync batch")
)

type Service struct {
	ledger     storage.Ledger
	chain      *chain.Chain
	networkID  uint32
	genesisID  types.Hash
	parameters block.Parameters
}

func New(ledger storage.Ledger, chainService *chain.Chain, document genesis.Document) (*Service, error) {
	if ledger == nil || chainService == nil || document.Validate() != nil {
		return nil, ErrConfiguration
	}
	genesisID, err := document.ID()
	if err != nil {
		return nil, err
	}
	return &Service{
		ledger:     ledger,
		chain:      chainService,
		networkID:  document.NetworkID,
		genesisID:  genesisID,
		parameters: block.ParametersFromGenesis(document),
	}, nil
}

func (service *Service) Status() (wire.Status, error) {
	tip, err := service.ledger.Tip()
	if err != nil {
		return wire.Status{}, err
	}
	return wire.Status{
		Version:        wire.Version0,
		NetworkID:      service.networkID,
		GenesisID:      service.genesisID,
		TipID:          tip.ID,
		StateRoot:      tip.StateRoot,
		TipHeight:      tip.Height,
		CumulativeWork: append([]byte(nil), tip.CumulativeWork...),
		MaxFrameBytes:  uint32(wire.MaxFrameBodyBytes),
	}, nil
}

func (service *Service) ValidatePeer(status wire.Status) error {
	if err := status.Validate(); err != nil {
		return err
	}
	if status.NetworkID != service.networkID {
		return ErrNetwork
	}
	if status.GenesisID != service.genesisID {
		return ErrGenesis
	}
	return nil
}

func (service *Service) PeerIsBetter(status wire.Status) (bool, error) {
	if err := service.ValidatePeer(status); err != nil {
		return false, err
	}
	current, err := service.ledger.Tip()
	if err != nil {
		return false, err
	}
	order := new(big.Int).SetBytes(status.CumulativeWork).Cmp(new(big.Int).SetBytes(current.CumulativeWork))
	if order != 0 {
		return order > 0, nil
	}
	return bytes.Compare(status.TipID[:], current.ID[:]) < 0, nil
}

// Locators returns the current tip, then ancestors at exponentially increasing
// distance, and always ends with genesis when space permits.
func (service *Service) Locators() ([]types.Hash, error) {
	tip, err := service.ledger.Tip()
	if err != nil {
		return nil, err
	}
	result := make([]types.Hash, 0, wire.MaxLocators)
	height := tip.Height
	step := uint64(1)
	for len(result) < wire.MaxLocators-1 && height > 0 {
		candidate, err := service.ledger.Block(height)
		if err != nil {
			return nil, err
		}
		id, err := candidate.Header.ID()
		if err != nil {
			return nil, err
		}
		result = append(result, id)
		if height <= step {
			break
		}
		height -= step
		if len(result) > 10 && step <= ^uint64(0)/2 {
			step *= 2
		}
	}
	if len(result) == 0 || result[len(result)-1] != service.genesisID {
		result = append(result, service.genesisID)
	}
	return result, nil
}

func (service *Service) BlocksAfter(request wire.GetBlocks) ([]block.Block, wire.BatchDone, error) {
	if err := request.Validate(); err != nil {
		return nil, wire.BatchDone{}, err
	}
	tip, err := service.ledger.Tip()
	if err != nil {
		return nil, wire.BatchDone{}, err
	}
	ancestorHeight, found, err := service.findCanonicalAncestor(request.Locators, tip)
	if err != nil {
		return nil, wire.BatchDone{}, err
	}
	if !found {
		return nil, wire.BatchDone{}, ErrNoCommonAncestor
	}
	remaining := tip.Height - ancestorHeight
	count := uint64(request.Limit)
	if count > remaining {
		count = remaining
	}
	blocks := make([]block.Block, 0, int(count))
	for offset := uint64(1); offset <= count; offset++ {
		candidate, err := service.ledger.Block(ancestorHeight + offset)
		if err != nil {
			return nil, wire.BatchDone{}, err
		}
		blocks = append(blocks, candidate)
	}
	return blocks, wire.BatchDone{Version: wire.Version0, TipID: tip.ID}, nil
}

// HeadersAfter returns the same canonical range as BlocksAfter without the
// bodies. Receivers can reject invalid PoW, target, time, or ancestry before
// allocating and executing multi-megabyte blocks.
func (service *Service) HeadersAfter(request wire.GetHeaders) (wire.Headers, error) {
	if err := request.Validate(); err != nil {
		return wire.Headers{}, err
	}
	tip, err := service.ledger.Tip()
	if err != nil {
		return wire.Headers{}, err
	}
	ancestorHeight, found, err := service.findCanonicalAncestor(request.Locators, tip)
	if err != nil {
		return wire.Headers{}, err
	}
	if !found {
		return wire.Headers{}, ErrNoCommonAncestor
	}
	remaining := tip.Height - ancestorHeight
	count := uint64(request.Limit)
	if count > remaining {
		count = remaining
	}
	result := wire.Headers{
		Version: wire.Version0,
		Values:  make([]block.Header, 0, int(count)),
		TipID:   tip.ID,
	}
	for offset := uint64(1); offset <= count; offset++ {
		candidate, err := service.ledger.Block(ancestorHeight + offset)
		if err != nil {
			return wire.Headers{}, err
		}
		result.Values = append(result.Values, candidate.Header)
	}
	return result, result.Validate()
}

// ValidateHeaders verifies a bounded response from the exact first canonical
// locator in request order. State/receipt commitments remain opaque here and
// are verified only by full block execution.
func (service *Service) ValidateHeaders(request wire.GetHeaders, response wire.Headers, validationTime uint64) error {
	if err := request.Validate(); err != nil {
		return err
	}
	if err := response.Validate(); err != nil {
		return err
	}
	if len(response.Values) > int(request.Limit) {
		return ErrBatch
	}
	current, err := service.ledger.Tip()
	if err != nil {
		return err
	}
	if len(response.Values) == 0 {
		return nil
	}
	parentID := response.Values[0].Parent
	requested := false
	for _, locator := range request.Locators {
		if locator == parentID {
			requested = true
			break
		}
	}
	if !requested {
		return ErrBatch
	}
	ancestorHeight, found, err := service.findCanonicalAncestor([]types.Hash{parentID}, current)
	if err != nil {
		return err
	}
	if !found {
		return ErrNoCommonAncestor
	}
	parent, err := service.canonicalTipAt(ancestorHeight, current)
	if err != nil {
		return err
	}
	history, err := service.recentTimestamps(parent)
	if err != nil {
		return err
	}
	for _, header := range response.Values {
		median := parent.Timestamp
		if len(history) > 0 {
			median = medianTimestamp(history)
		}
		parentContext := block.Parent{
			ID:             parent.ID,
			Height:         parent.Height,
			Timestamp:      parent.Timestamp,
			MedianTimePast: median,
			Target:         parent.Target,
		}
		if err := block.ValidateHeaderAt(parentContext, header, service.parameters, validationTime); err != nil {
			return err
		}
		id, err := header.ID()
		if err != nil {
			return err
		}
		parent = storage.Tip{ID: id, Height: header.Height, Timestamp: header.Timestamp, Target: header.Target, StateRoot: header.StateRoot}
		history = append(history, header.Timestamp)
		if len(history) > 11 {
			history = history[len(history)-11:]
		}
	}
	return nil
}

func (service *Service) ApplyBlocks(blocks []block.Block) (storage.Tip, error) {
	if len(blocks) == 0 || len(blocks) > wire.MaxBlocksPerRequest {
		return storage.Tip{}, ErrBatch
	}
	var result storage.Tip
	for _, candidate := range blocks {
		var err error
		result, err = service.chain.Submit(candidate)
		if errors.Is(err, storage.ErrBlockExists) {
			result, err = service.ledger.Tip()
		}
		if err != nil {
			return storage.Tip{}, err
		}
	}
	return result, nil
}

func (service *Service) findCanonicalAncestor(locators []types.Hash, tip storage.Tip) (uint64, bool, error) {
	for _, locator := range locators {
		if locator == service.genesisID {
			return 0, true, nil
		}
		node, err := service.ledger.TipByID(locator)
		if errors.Is(err, storage.ErrNodeNotFound) {
			continue
		}
		if err != nil {
			return 0, false, err
		}
		if node.Height == 0 || node.Height > tip.Height {
			continue
		}
		canonical, err := service.ledger.Block(node.Height)
		if err != nil {
			return 0, false, err
		}
		canonicalID, err := canonical.Header.ID()
		if err != nil {
			return 0, false, err
		}
		if canonicalID == locator {
			return node.Height, true, nil
		}
	}
	return 0, false, nil
}

func (service *Service) canonicalTipAt(height uint64, current storage.Tip) (storage.Tip, error) {
	if height == 0 {
		return service.ledger.TipByID(service.genesisID)
	}
	if height > current.Height {
		return storage.Tip{}, ErrBatch
	}
	candidate, err := service.ledger.Block(height)
	if err != nil {
		return storage.Tip{}, err
	}
	id, err := candidate.Header.ID()
	if err != nil {
		return storage.Tip{}, err
	}
	return service.ledger.TipByID(id)
}

func (service *Service) recentTimestamps(parent storage.Tip) ([]uint64, error) {
	if parent.Height == 0 {
		return nil, nil
	}
	result := make([]uint64, 0, 11)
	cursor := parent.ID
	for height := parent.Height; height > 0 && len(result) < 11; height-- {
		candidate, err := service.ledger.BlockByID(cursor)
		if err != nil {
			return nil, err
		}
		id, err := candidate.Header.ID()
		if err != nil || id != cursor || candidate.Header.Height != height {
			return nil, storage.ErrCorrupt
		}
		result = append(result, candidate.Header.Timestamp)
		cursor = candidate.Header.Parent
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result, nil
}

func medianTimestamp(values []uint64) uint64 {
	ordered := append([]uint64(nil), values...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	return ordered[len(ordered)/2]
}
