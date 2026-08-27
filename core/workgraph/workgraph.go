// Package workgraph implements bounded weak-proof-of-work share validation and
// deterministic native reward accounting. It is consensus-pure but is not yet
// integrated into a block version.
package workgraph

import (
	"container/heap"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/merkle"
	"github.com/outcomemesh/outcomemesh/core/pow"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0                 uint16 = 0
	ShareDifficultyRatio            = 512
	ExpectedSharesPerAnchor  uint64 = ShareDifficultyRatio - 1
	MaxParents                      = 4
	MaxShares                       = 8_192
	MaxRewardMiners                 = 256
	MaxBatchCanonicalBytes          = 3 << 20
	MaxShareCanonicalBytes          = 319
	MaxInclusionTransactions        = 4_096
	MaxShareTimestampLead    uint64 = 120
)

var (
	ErrVersion        = errors.New("unsupported work share version")
	ErrNetwork        = errors.New("invalid work share network")
	ErrAnchor         = errors.New("invalid work share anchor")
	ErrHeight         = errors.New("invalid work share height")
	ErrTimestamp      = errors.New("invalid work share timestamp")
	ErrTarget         = errors.New("invalid work share target")
	ErrPayload        = errors.New("invalid work share payload root")
	ErrMiner          = errors.New("invalid work share miner")
	ErrInclusion      = errors.New("invalid work share inclusion root")
	ErrParents        = errors.New("invalid work share parents")
	ErrProofOfWork    = errors.New("work share proof of work does not meet target")
	ErrShareCount     = errors.New("invalid work share count")
	ErrBatchSize      = errors.New("work share batch exceeds canonical byte limit")
	ErrDuplicate      = errors.New("duplicate work share")
	ErrCanonicalOrder = errors.New("work shares are not in canonical topological order")
	ErrRewardMiners   = errors.New("too many distinct work share reward miners")
	ErrReward         = errors.New("invalid work share reward")
)

type Share struct {
	Version       uint16
	NetworkID     uint32
	Height        uint64
	AnchorParent  types.Hash
	Timestamp     uint64
	Target        types.Hash
	PayloadRoot   types.Hash
	Miner         types.Address
	InclusionRoot types.Hash
	Parents       []types.Hash
	Nonce         uint64
}

type Context struct {
	NetworkID       uint32
	Height          uint64
	AnchorParent    types.Hash
	AnchorTarget    types.Hash
	PayloadRoot     types.Hash
	AnchorMiner     types.Address
	AnchorTimestamp uint64
	MedianTimePast  uint64
}

type Reward struct {
	Miner  types.Address
	Amount uint64
}

// Batch is created only by ValidateBatch and owns detached canonical shares.
type Batch struct {
	shares      []Share
	ids         []types.Hash
	root        types.Hash
	anchorMiner types.Address
}

func (share Share) ValidateBasic() error {
	if share.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrVersion, share.Version)
	}
	if share.NetworkID == 0 {
		return ErrNetwork
	}
	if share.AnchorParent.IsZero() {
		return ErrAnchor
	}
	if share.Height == 0 {
		return ErrHeight
	}
	if share.Timestamp == 0 {
		return ErrTimestamp
	}
	if share.Target.IsZero() {
		return ErrTarget
	}
	if share.PayloadRoot.IsZero() {
		return ErrPayload
	}
	if share.Miner.IsZero() {
		return ErrMiner
	}
	if share.InclusionRoot.IsZero() {
		return ErrInclusion
	}
	if len(share.Parents) > MaxParents {
		return ErrParents
	}
	for index, parent := range share.Parents {
		if parent.IsZero() || (index > 0 && types.CompareHash(share.Parents[index-1], parent) >= 0) {
			return ErrParents
		}
	}
	return nil
}

func (share Share) EncodeTo(encoder *codec.Encoder) {
	encoder.U16(share.Version)
	encoder.U32(share.NetworkID)
	encoder.U64(share.Height)
	encoder.Fixed(share.AnchorParent[:])
	encoder.U64(share.Timestamp)
	encoder.Fixed(share.Target[:])
	encoder.Fixed(share.PayloadRoot[:])
	encoder.Fixed(share.Miner[:])
	encoder.Fixed(share.InclusionRoot[:])
	encoder.Uvarint(uint64(len(share.Parents)))
	for _, parent := range share.Parents {
		encoder.Fixed(parent[:])
	}
	encoder.U64(share.Nonce)
}

func (share Share) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(MaxShareCanonicalBytes)
	share.EncodeTo(encoder)
	return encoder.Bytes()
}

func (share Share) ID() (types.Hash, error) {
	if err := share.ValidateBasic(); err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(types.DomainWorkID, share.CanonicalBytes()), nil
}

func Decode(input []byte) (Share, error) {
	if len(input) == 0 || len(input) > MaxShareCanonicalBytes {
		return Share{}, ErrBatchSize
	}
	decoder := codec.NewDecoder(input)
	share, err := DecodeFrom(decoder)
	if err != nil {
		return Share{}, err
	}
	if err := decoder.Finish(); err != nil {
		return Share{}, err
	}
	return share, nil
}

func DecodeFrom(decoder *codec.Decoder) (Share, error) {
	if decoder == nil {
		return Share{}, ErrBatchSize
	}
	var share Share
	var err error
	share.Version, err = decoder.U16()
	if err != nil {
		return Share{}, err
	}
	share.NetworkID, err = decoder.U32()
	if err != nil {
		return Share{}, err
	}
	share.Height, err = decoder.U64()
	if err != nil {
		return Share{}, err
	}
	anchor, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Share{}, err
	}
	copy(share.AnchorParent[:], anchor)
	share.Timestamp, err = decoder.U64()
	if err != nil {
		return Share{}, err
	}
	target, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Share{}, err
	}
	copy(share.Target[:], target)
	payload, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Share{}, err
	}
	copy(share.PayloadRoot[:], payload)
	miner, err := decoder.Fixed(types.AddressSize)
	if err != nil {
		return Share{}, err
	}
	copy(share.Miner[:], miner)
	inclusion, err := decoder.Fixed(types.HashSize)
	if err != nil {
		return Share{}, err
	}
	copy(share.InclusionRoot[:], inclusion)
	parentCount, err := decoder.ListLength(MaxParents)
	if err != nil {
		return Share{}, err
	}
	share.Parents = make([]types.Hash, parentCount)
	for index := range share.Parents {
		parent, err := decoder.Fixed(types.HashSize)
		if err != nil {
			return Share{}, err
		}
		copy(share.Parents[index][:], parent)
	}
	share.Nonce, err = decoder.U64()
	if err != nil {
		return Share{}, err
	}
	if err := share.ValidateBasic(); err != nil {
		return Share{}, err
	}
	return share, nil
}

func EncodeShares(shares []Share) ([]byte, error) {
	if len(shares) > MaxShares {
		return nil, ErrShareCount
	}
	encoder := codec.NewEncoder(min(MaxBatchCanonicalBytes, 10+len(shares)*192))
	encoder.Uvarint(uint64(len(shares)))
	for index, share := range shares {
		if err := share.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("share %d: %w", index, err)
		}
		share.EncodeTo(encoder)
		if encoder.Len() > MaxBatchCanonicalBytes {
			return nil, ErrBatchSize
		}
	}
	return encoder.Bytes(), nil
}

func DecodeShares(input []byte) ([]Share, error) {
	if len(input) == 0 || len(input) > MaxBatchCanonicalBytes {
		return nil, ErrBatchSize
	}
	decoder := codec.NewDecoder(input)
	count, err := decoder.ListLength(MaxShares)
	if err != nil {
		return nil, err
	}
	shares := make([]Share, count)
	for index := range shares {
		shares[index], err = DecodeFrom(decoder)
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", index, err)
		}
	}
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	return shares, nil
}

func InclusionRoot(transactionIDs []types.Hash) (types.Hash, error) {
	if len(transactionIDs) > MaxInclusionTransactions {
		return types.Hash{}, ErrInclusion
	}
	payloads := make([][]byte, len(transactionIDs))
	for index, id := range transactionIDs {
		if id.IsZero() {
			return types.Hash{}, ErrInclusion
		}
		payloads[index] = append([]byte(nil), id[:]...)
	}
	return merkle.Root(payloads, types.DomainInclusionEmpty, types.DomainInclusionLeaf, types.DomainInclusionNode), nil
}

func PayloadCommitment(transactionRoot, receiptRoot, stateRoot, previousWorkRoot types.Hash) (types.Hash, error) {
	if transactionRoot.IsZero() || receiptRoot.IsZero() || stateRoot.IsZero() || previousWorkRoot.IsZero() {
		return types.Hash{}, ErrPayload
	}
	return types.DomainHash(
		types.DomainWorkPayload, transactionRoot[:], receiptRoot[:], stateRoot[:], previousWorkRoot[:],
	), nil
}

// PayloadCommitmentV1 additionally commits the fork-local delayed-fee queue
// and the fee award already fixed for this height before nonce search.
func PayloadCommitmentV1(
	transactionRoot types.Hash,
	receiptRoot types.Hash,
	stateRoot types.Hash,
	previousWorkRoot types.Hash,
	feeQueueRoot types.Hash,
	feeAward uint64,
) (types.Hash, error) {
	if transactionRoot.IsZero() || receiptRoot.IsZero() || stateRoot.IsZero() ||
		previousWorkRoot.IsZero() || feeQueueRoot.IsZero() {
		return types.Hash{}, ErrPayload
	}
	var award [8]byte
	binary.BigEndian.PutUint64(award[:], feeAward)
	return types.DomainHash(
		types.DomainWorkPayloadV1, transactionRoot[:], receiptRoot[:], stateRoot[:],
		previousWorkRoot[:], feeQueueRoot[:], award[:],
	), nil
}

func DerivedTarget(anchorTarget types.Hash) (types.Hash, error) {
	if anchorTarget.IsZero() {
		return types.Hash{}, ErrTarget
	}
	value := new(big.Int).SetBytes(anchorTarget[:])
	value.Add(value, big.NewInt(1))
	value.Mul(value, big.NewInt(ShareDifficultyRatio))
	value.Sub(value, big.NewInt(1))
	maximum := new(big.Int).Lsh(big.NewInt(1), 256)
	maximum.Sub(maximum, big.NewInt(1))
	if value.Cmp(maximum) > 0 {
		value.Set(maximum)
	}
	var target types.Hash
	value.FillBytes(target[:])
	return target, nil
}

// ExactShareRatio reports whether the configured hard target preserves the
// full R-to-1 threshold ratio without clamping the derived target at 2^256-1.
// WorkGraph rewards assume this exact ratio when setting fixed per-share rates.
func ExactShareRatio(anchorTarget types.Hash) bool {
	if anchorTarget.IsZero() {
		return false
	}
	value := new(big.Int).SetBytes(anchorTarget[:])
	value.Add(value, big.NewInt(1))
	value.Mul(value, big.NewInt(ShareDifficultyRatio))
	value.Sub(value, big.NewInt(1))
	maximum := new(big.Int).Lsh(big.NewInt(1), 256)
	maximum.Sub(maximum, big.NewInt(1))
	return value.Cmp(maximum) <= 0
}

func ValidateShare(context Context, share Share) error {
	if err := share.ValidateBasic(); err != nil {
		return err
	}
	if context.NetworkID == 0 || share.NetworkID != context.NetworkID {
		return ErrNetwork
	}
	if context.AnchorParent.IsZero() || share.AnchorParent != context.AnchorParent {
		return ErrAnchor
	}
	if context.Height == 0 || share.Height != context.Height {
		return ErrHeight
	}
	if context.PayloadRoot.IsZero() || share.PayloadRoot != context.PayloadRoot {
		return ErrPayload
	}
	if context.MedianTimePast == 0 || context.AnchorTimestamp <= context.MedianTimePast ||
		share.Timestamp <= context.MedianTimePast {
		return ErrTimestamp
	}
	latest := context.AnchorTimestamp + MaxShareTimestampLead
	if latest < context.AnchorTimestamp {
		latest = ^uint64(0)
	}
	if share.Timestamp > latest {
		return ErrTimestamp
	}
	if share.Target != context.AnchorTarget {
		return ErrTarget
	}
	if !ExactShareRatio(context.AnchorTarget) {
		return ErrTarget
	}
	target, err := DerivedTarget(context.AnchorTarget)
	if err != nil {
		return ErrTarget
	}
	id, err := share.ID()
	if err != nil {
		return err
	}
	if !pow.MeetsTarget(id, target) {
		return ErrProofOfWork
	}
	return nil
}

// MeetsAnchor applies the hard target to the same Work ID used for weak-share
// admission. No proof or nonce is translated between the two thresholds.
func MeetsAnchor(share Share) (bool, error) {
	id, err := share.ID()
	if err != nil {
		return false, err
	}
	if !ExactShareRatio(share.Target) {
		return false, ErrTarget
	}
	return pow.MeetsTarget(id, share.Target), nil
}

// Mine searches the share nonce space without mutating the caller's template.
func Mine(ctx context.Context, template Share, start uint64) (Share, types.Hash, error) {
	if ctx == nil {
		return Share{}, types.Hash{}, context.Canceled
	}
	if err := template.ValidateBasic(); err != nil {
		return Share{}, types.Hash{}, err
	}
	if !ExactShareRatio(template.Target) {
		return Share{}, types.Hash{}, ErrTarget
	}
	shareTarget, err := DerivedTarget(template.Target)
	if err != nil {
		return Share{}, types.Hash{}, err
	}
	return mineAtTarget(ctx, template, start, shareTarget)
}

// MineAnchor searches the hard target in the exact same nonce space as Mine.
func MineAnchor(ctx context.Context, template Share, start uint64) (Share, types.Hash, error) {
	if ctx == nil {
		return Share{}, types.Hash{}, context.Canceled
	}
	if err := template.ValidateBasic(); err != nil {
		return Share{}, types.Hash{}, err
	}
	if !ExactShareRatio(template.Target) {
		return Share{}, types.Hash{}, ErrTarget
	}
	return mineAtTarget(ctx, template, start, template.Target)
}

func mineAtTarget(ctx context.Context, template Share, start uint64, target types.Hash) (Share, types.Hash, error) {
	nonce, id, err := pow.Mine(ctx, target, start, func(nonce uint64) (types.Hash, error) {
		candidate := template
		candidate.Nonce = nonce
		return candidate.ID()
	})
	if err != nil {
		return Share{}, types.Hash{}, err
	}
	template.Nonce = nonce
	return template, id, nil
}

func ValidateBatch(context Context, shares []Share) (*Batch, error) {
	if len(shares) > MaxShares {
		return nil, ErrShareCount
	}
	if context.AnchorMiner.IsZero() {
		return nil, ErrMiner
	}
	detached := make([]Share, len(shares))
	ids := make([]types.Hash, len(shares))
	indices := make(map[types.Hash]int, len(shares))
	miners := make(map[types.Address]struct{}, min(len(shares)+1, MaxRewardMiners))
	miners[context.AnchorMiner] = struct{}{}
	totalBytes := 0
	for index, share := range shares {
		share.Parents = append([]types.Hash(nil), share.Parents...)
		if err := ValidateShare(context, share); err != nil {
			return nil, fmt.Errorf("share %d: %w", index, err)
		}
		id, err := share.ID()
		if err != nil {
			return nil, fmt.Errorf("share %d: %w", index, err)
		}
		if _, exists := indices[id]; exists {
			return nil, ErrDuplicate
		}
		indices[id] = index
		ids[index] = id
		detached[index] = share
		miners[share.Miner] = struct{}{}
		if len(miners) > MaxRewardMiners {
			return nil, ErrRewardMiners
		}
		totalBytes += len(share.CanonicalBytes())
		if totalBytes > MaxBatchCanonicalBytes {
			return nil, ErrBatchSize
		}
	}
	order, err := canonicalOrder(detached, ids, indices)
	if err != nil {
		return nil, err
	}
	for position, index := range order {
		if index != position {
			return nil, ErrCanonicalOrder
		}
	}
	root := rootFromIDs(ids)
	return &Batch{
		shares: detached, ids: append([]types.Hash(nil), ids...), root: root, anchorMiner: context.AnchorMiner,
	}, nil
}

// ValidateCommittedBatch proves that shares are exactly the transitive closure
// of the winning anchor seal's parent tips. The following block may carry this
// closure for delayed payout, but cannot add or omit a share after the hard PoW
// was found.
func ValidateCommittedBatch(context Context, anchor Share, shares []Share) (*Batch, error) {
	if anchor.Miner != context.AnchorMiner {
		return nil, ErrMiner
	}
	if anchor.Timestamp != context.AnchorTimestamp {
		return nil, ErrTimestamp
	}
	if err := ValidateShare(context, anchor); err != nil {
		return nil, fmt.Errorf("anchor seal: %w", err)
	}
	meets, err := MeetsAnchor(anchor)
	if err != nil {
		return nil, err
	}
	if !meets {
		return nil, ErrProofOfWork
	}
	batch, err := ValidateBatch(context, shares)
	if err != nil {
		return nil, err
	}
	anchorID, err := anchor.ID()
	if err != nil {
		return nil, err
	}
	indices := make(map[types.Hash]int, len(batch.ids))
	for index, id := range batch.ids {
		if id == anchorID {
			return nil, ErrDuplicate
		}
		indices[id] = index
	}
	visited := make(map[types.Hash]struct{}, len(batch.ids))
	stack := append([]types.Hash(nil), anchor.Parents...)
	for len(stack) > 0 {
		last := len(stack) - 1
		id := stack[last]
		stack = stack[:last]
		if _, exists := visited[id]; exists {
			continue
		}
		index, exists := indices[id]
		if !exists {
			return nil, ErrParents
		}
		visited[id] = struct{}{}
		stack = append(stack, batch.shares[index].Parents...)
	}
	if len(visited) != len(batch.shares) {
		return nil, ErrParents
	}
	return batch, nil
}

// Canonicalize validates shares and returns the unique topological order. It is
// for block construction; ValidateBatch still checks the final committed list.
func Canonicalize(context Context, shares []Share) ([]Share, error) {
	if len(shares) > MaxShares {
		return nil, ErrShareCount
	}
	if context.AnchorMiner.IsZero() {
		return nil, ErrMiner
	}
	detached := make([]Share, len(shares))
	ids := make([]types.Hash, len(shares))
	indices := make(map[types.Hash]int, len(shares))
	miners := make(map[types.Address]struct{}, min(len(shares)+1, MaxRewardMiners))
	miners[context.AnchorMiner] = struct{}{}
	totalBytes := 0
	for index, share := range shares {
		share.Parents = append([]types.Hash(nil), share.Parents...)
		if err := ValidateShare(context, share); err != nil {
			return nil, fmt.Errorf("share %d: %w", index, err)
		}
		id, _ := share.ID()
		if _, exists := indices[id]; exists {
			return nil, ErrDuplicate
		}
		indices[id] = index
		ids[index] = id
		detached[index] = share
		miners[share.Miner] = struct{}{}
		if len(miners) > MaxRewardMiners {
			return nil, ErrRewardMiners
		}
		totalBytes += len(share.CanonicalBytes())
		if totalBytes > MaxBatchCanonicalBytes {
			return nil, ErrBatchSize
		}
	}
	order, err := canonicalOrder(detached, ids, indices)
	if err != nil {
		return nil, err
	}
	result := make([]Share, len(order))
	for position, index := range order {
		result[position] = detached[index]
	}
	return result, nil
}

func (batch *Batch) Len() int {
	if batch == nil {
		return 0
	}
	return len(batch.shares)
}

func (batch *Batch) Root() types.Hash {
	if batch == nil {
		return rootFromIDs(nil)
	}
	return batch.root
}

func EmptyRoot() types.Hash { return rootFromIDs(nil) }

func (batch *Batch) Shares() []Share {
	if batch == nil {
		return nil
	}
	result := make([]Share, len(batch.shares))
	for index, share := range batch.shares {
		share.Parents = append([]types.Hash(nil), share.Parents...)
		result[index] = share
	}
	return result
}

func (batch *Batch) IDs() []types.Hash {
	if batch == nil {
		return nil
	}
	return append([]types.Hash(nil), batch.ids...)
}

// RewardRates splits scheduled subsidy into a fixed anchor subsidy and a fixed
// per-share payment. At the expected R-1 weak shares per hard anchor, expected
// issuance equals blockSubsidy. A winner cannot increase its payment by
// omitting somebody else's share because neither rate depends on batch length.
func RewardRates(blockSubsidy uint64) (anchorSubsidy uint64, shareReward uint64, err error) {
	if blockSubsidy == 0 || ExpectedSharesPerAnchor == 0 {
		return 0, 0, ErrReward
	}
	shareReward = blockSubsidy / (2 * ExpectedSharesPerAnchor)
	if shareReward == 0 {
		return 0, 0, ErrReward
	}
	expectedShareSubsidy := shareReward * ExpectedSharesPerAnchor
	anchorSubsidy, err = types.SubAmount(blockSubsidy, expectedShareSubsidy)
	if err != nil {
		return 0, 0, ErrReward
	}
	// One miner may own the anchor and every maximum-size share batch. Reject
	// an economic parameter set that could make this bounded valid case fail.
	if shareReward > (^uint64(0)-anchorSubsidy)/uint64(MaxShares) {
		return 0, 0, ErrReward
	}
	return anchorSubsidy, shareReward, nil
}

func AllocateRewards(blockSubsidy, fees uint64, anchorMiner types.Address, batch *Batch) ([]Reward, error) {
	if anchorMiner.IsZero() || batch == nil || anchorMiner != batch.anchorMiner {
		return nil, ErrReward
	}
	anchorSubsidy, shareReward, err := RewardRates(blockSubsidy)
	if err != nil {
		return nil, err
	}
	amounts := make(map[types.Address]uint64, min(batch.Len()+1, MaxRewardMiners+1))
	anchorAmount, err := types.AddAmount(anchorSubsidy, fees)
	if err != nil {
		return nil, ErrReward
	}
	amounts[anchorMiner] = anchorAmount
	for _, share := range batch.shares {
		current := amounts[share.Miner]
		updated, err := types.AddAmount(current, shareReward)
		if err != nil {
			return nil, ErrReward
		}
		amounts[share.Miner] = updated
	}
	miners := make([]types.Address, 0, len(amounts))
	for miner, amount := range amounts {
		if amount != 0 {
			miners = append(miners, miner)
		}
	}
	sort.Slice(miners, func(left, right int) bool { return types.CompareAddress(miners[left], miners[right]) < 0 })
	rewards := make([]Reward, len(miners))
	var distributed uint64
	for index, miner := range miners {
		rewards[index] = Reward{Miner: miner, Amount: amounts[miner]}
		var err error
		distributed, err = types.AddAmount(distributed, amounts[miner])
		if err != nil {
			return nil, ErrReward
		}
	}
	expectedShareTotal := shareReward * uint64(batch.Len())
	expected, err := types.AddAmount(anchorAmount, expectedShareTotal)
	if err != nil || distributed != expected {
		return nil, ErrReward
	}
	return rewards, nil
}

// RewardResources materializes delayed payouts at earnedHeight+1. Identifiers
// commit to the earning anchor, recipient, and amount and are known before the
// payout block starts nonce search.
func RewardResources(
	networkID uint32,
	earnedHeight uint64,
	payoutHeight uint64,
	anchorID types.Hash,
	rewards []Reward,
	maturity uint64,
) ([]resource.Resource, error) {
	if networkID == 0 || earnedHeight == 0 || earnedHeight == ^uint64(0) || payoutHeight != earnedHeight+1 ||
		anchorID.IsZero() || maturity == 0 || payoutHeight > ^uint64(0)-maturity || len(rewards) > MaxRewardMiners {
		return nil, ErrReward
	}
	spendAfter := payoutHeight + maturity
	result := make([]resource.Resource, len(rewards))
	var network [4]byte
	var height [8]byte
	var amount [8]byte
	binary.BigEndian.PutUint32(network[:], networkID)
	binary.BigEndian.PutUint64(height[:], earnedHeight)
	for index, reward := range rewards {
		if reward.Miner.IsZero() || reward.Amount == 0 ||
			(index > 0 && types.CompareAddress(rewards[index-1].Miner, reward.Miner) >= 0) {
			return nil, ErrReward
		}
		binary.BigEndian.PutUint64(amount[:], reward.Amount)
		id := types.ResourceID(types.DomainHash(
			types.DomainWorkReward, network[:], height[:], anchorID[:], reward.Miner[:], amount[:],
		))
		result[index] = resource.Resource{
			ID: id, Version: resource.Version0, Owner: reward.Miner, Asset: types.NativeAssetID(),
			Amount: reward.Amount, SpendAfter: spendAfter,
		}
	}
	return result, nil
}

func canonicalOrder(shares []Share, ids []types.Hash, indices map[types.Hash]int) ([]int, error) {
	indegree := make([]int, len(shares))
	children := make([][]int, len(shares))
	for child, share := range shares {
		for _, parentID := range share.Parents {
			parent, exists := indices[parentID]
			if !exists {
				return nil, ErrParents
			}
			indegree[child]++
			children[parent] = append(children[parent], child)
		}
	}
	queue := &idHeap{ids: ids}
	for index, degree := range indegree {
		if degree == 0 {
			heap.Push(queue, index)
		}
	}
	order := make([]int, 0, len(shares))
	for queue.Len() > 0 {
		parent := heap.Pop(queue).(int)
		order = append(order, parent)
		for _, child := range children[parent] {
			indegree[child]--
			if indegree[child] == 0 {
				heap.Push(queue, child)
			}
		}
	}
	if len(order) != len(shares) {
		return nil, ErrParents
	}
	return order, nil
}

func rootFromIDs(ids []types.Hash) types.Hash {
	payloads := make([][]byte, len(ids))
	for index, id := range ids {
		payloads[index] = append([]byte(nil), id[:]...)
	}
	return merkle.Root(payloads, types.DomainWorkEmpty, types.DomainWorkLeaf, types.DomainWorkNode)
}

type idHeap struct {
	ids     []types.Hash
	indices []int
}

func (values idHeap) Len() int { return len(values.indices) }
func (values idHeap) Less(left, right int) bool {
	return types.CompareHash(values.ids[values.indices[left]], values.ids[values.indices[right]]) < 0
}
func (values idHeap) Swap(left, right int) {
	values.indices[left], values.indices[right] = values.indices[right], values.indices[left]
}
func (values *idHeap) Push(value any) { values.indices = append(values.indices, value.(int)) }
func (values *idHeap) Pop() any {
	last := len(values.indices) - 1
	value := values.indices[last]
	values.indices = values.indices[:last]
	return value
}
