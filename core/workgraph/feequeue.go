package workgraph

import (
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	FeeQueueVersion0          uint16 = 0
	MaxFeeDelay               uint16 = 4_096
	MinFeeQueueCanonicalBytes        = 14 + 8
	MaxFeeQueueCanonicalBytes        = 14 + int(MaxFeeDelay)*8
)

var ErrFeeQueue = errors.New("invalid WorkGraph fee queue")

// FeeQueue delays each block's collected fees by an exact number of anchor
// transitions. The matured slot is assigned to a future anchor independently
// of the block that deposited it. The queue is immutable and fork-local.
type FeeQueue struct {
	version uint16
	delay   uint16
	cursor  uint16
	balance uint64
	slots   []uint64
}

func NewFeeQueue(delay uint16) (*FeeQueue, error) {
	if delay == 0 || delay > MaxFeeDelay {
		return nil, ErrFeeQueue
	}
	return &FeeQueue{version: FeeQueueVersion0, delay: delay, slots: make([]uint64, int(delay))}, nil
}

func DecodeFeeQueue(input []byte) (*FeeQueue, error) {
	if len(input) < MinFeeQueueCanonicalBytes || len(input) > MaxFeeQueueCanonicalBytes {
		return nil, ErrFeeQueue
	}
	decoder := codec.NewDecoder(input)
	version, err := decoder.U16()
	if err != nil {
		return nil, err
	}
	delay, err := decoder.U16()
	if err != nil {
		return nil, err
	}
	cursor, err := decoder.U16()
	if err != nil {
		return nil, err
	}
	balance, err := decoder.U64()
	if err != nil {
		return nil, err
	}
	if version != FeeQueueVersion0 || delay == 0 || delay > MaxFeeDelay || cursor >= delay ||
		decoder.Remaining() != int(delay)*8 {
		return nil, ErrFeeQueue
	}
	queue := &FeeQueue{
		version: version, delay: delay, cursor: cursor, balance: balance, slots: make([]uint64, int(delay)),
	}
	for index := range queue.slots {
		queue.slots[index], err = decoder.U64()
		if err != nil {
			return nil, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return nil, err
	}
	if err := queue.validate(); err != nil {
		return nil, err
	}
	return queue, nil
}

// Advance returns the fee award fixed before the next anchor is mined and a
// detached queue containing the current block's newly collected fees. Exact
// conservation holds: old balance + collected = award + new balance.
func (queue *FeeQueue) Advance(collected uint64) (award uint64, next *FeeQueue, err error) {
	if err := queue.validate(); err != nil {
		return 0, nil, err
	}
	award = queue.slots[queue.cursor]
	balance, err := types.SubAmount(queue.balance, award)
	if err != nil {
		return 0, nil, ErrFeeQueue
	}
	balance, err = types.AddAmount(balance, collected)
	if err != nil {
		return 0, nil, ErrFeeQueue
	}
	next = &FeeQueue{
		version: queue.version,
		delay:   queue.delay,
		cursor:  (queue.cursor + 1) % queue.delay,
		balance: balance,
		slots:   append([]uint64(nil), queue.slots...),
	}
	next.slots[queue.cursor] = collected
	return award, next, nil
}

func (queue *FeeQueue) CanonicalBytes() ([]byte, error) {
	if err := queue.validate(); err != nil {
		return nil, err
	}
	encoder := codec.NewEncoder(14 + len(queue.slots)*8)
	encoder.U16(queue.version)
	encoder.U16(queue.delay)
	encoder.U16(queue.cursor)
	encoder.U64(queue.balance)
	for _, amount := range queue.slots {
		encoder.U64(amount)
	}
	return encoder.Bytes(), nil
}

func (queue *FeeQueue) Root() (types.Hash, error) {
	encoded, err := queue.CanonicalBytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.DomainHash(types.DomainWorkFeeQueue, encoded), nil
}

func (queue *FeeQueue) Delay() uint16 {
	if queue == nil {
		return 0
	}
	return queue.delay
}

func (queue *FeeQueue) Cursor() uint16 {
	if queue == nil {
		return 0
	}
	return queue.cursor
}

func (queue *FeeQueue) Balance() uint64 {
	if queue == nil {
		return 0
	}
	return queue.balance
}

func (queue *FeeQueue) Slots() []uint64 {
	if queue == nil {
		return nil
	}
	return append([]uint64(nil), queue.slots...)
}

func (queue *FeeQueue) validate() error {
	if queue == nil || queue.version != FeeQueueVersion0 || queue.delay == 0 ||
		queue.delay > MaxFeeDelay || queue.cursor >= queue.delay || len(queue.slots) != int(queue.delay) {
		return ErrFeeQueue
	}
	var total uint64
	for index, amount := range queue.slots {
		updated, err := types.AddAmount(total, amount)
		if err != nil {
			return fmt.Errorf("%w: slot %d overflows", ErrFeeQueue, index)
		}
		total = updated
	}
	if total != queue.balance {
		return ErrFeeQueue
	}
	return nil
}
