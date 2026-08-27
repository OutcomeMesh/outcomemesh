package guardvm

import (
	"errors"
	"fmt"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

const (
	Version0        uint16 = 0
	MaxInstructions        = 256
	MaxStackDepth          = 64
)

type Opcode uint8

const (
	OpPushU64 Opcode = iota + 1
	OpLoadBalanceBefore
	OpLoadBalanceAfter
	OpLoadFee
	OpLoadHeight
	OpAddU64
	OpSubU64
	OpEqualU64
	OpLessOrEqualU64
	OpGreaterOrEqualU64
	OpAnd
	OpOr
	OpNot
	OpRequire
	OpHalt
)

var (
	ErrUnsupportedVersion = errors.New("unsupported GuardVM version")
	ErrProgramSize        = errors.New("invalid GuardVM program size")
	ErrInvalidOpcode      = errors.New("invalid GuardVM opcode")
	ErrInvalidProgram     = errors.New("invalid GuardVM program")
	ErrStackUnderflow     = errors.New("GuardVM stack underflow")
	ErrStackOverflow      = errors.New("GuardVM stack overflow")
	ErrTypeMismatch       = errors.New("GuardVM type mismatch")
	ErrRequirementFailed  = errors.New("GuardVM requirement failed")
	ErrArithmetic         = errors.New("GuardVM arithmetic failure")
	ErrMissingContext     = errors.New("GuardVM context is missing")
)

type Instruction struct {
	Op    Opcode
	Owner types.Address
	Asset types.AssetID
	Value uint64
}

type Program struct {
	Version      uint16
	Instructions []Instruction
}

type BalanceView interface {
	Balance(owner types.Address, asset types.AssetID) (uint64, error)
}

type Context struct {
	Before BalanceView
	After  BalanceView
	Fee    uint64
	Height uint64
}

type valueKind uint8

const (
	kindU64 valueKind = iota + 1
	kindBool
)

type stackValue struct {
	kind    valueKind
	integer uint64
	boolean bool
}

func (program Program) EncodeTo(encoder *codec.Encoder) {
	encoder.U16(program.Version)
	encoder.Uvarint(uint64(len(program.Instructions)))
	for _, instruction := range program.Instructions {
		encoder.U8(uint8(instruction.Op))
		switch instruction.Op {
		case OpPushU64:
			encoder.U64(instruction.Value)
		case OpLoadBalanceBefore, OpLoadBalanceAfter:
			encoder.Fixed(instruction.Owner[:])
			encoder.Fixed(instruction.Asset[:])
		}
	}
}

func (program Program) CanonicalBytes() []byte {
	encoder := codec.NewEncoder(16 + len(program.Instructions)*8)
	program.EncodeTo(encoder)
	return encoder.Bytes()
}

func DecodeProgram(decoder *codec.Decoder) (Program, error) {
	version, err := decoder.U16()
	if err != nil {
		return Program{}, err
	}

	count, err := decoder.ListLength(MaxInstructions)
	if err != nil {
		return Program{}, err
	}

	program := Program{
		Version:      version,
		Instructions: make([]Instruction, count),
	}
	for index := range program.Instructions {
		opcode, err := decoder.U8()
		if err != nil {
			return Program{}, err
		}
		program.Instructions[index].Op = Opcode(opcode)

		switch program.Instructions[index].Op {
		case OpPushU64:
			program.Instructions[index].Value, err = decoder.U64()
			if err != nil {
				return Program{}, err
			}
		case OpLoadBalanceBefore, OpLoadBalanceAfter:
			owner, err := decoder.Fixed(types.AddressSize)
			if err != nil {
				return Program{}, err
			}
			copy(program.Instructions[index].Owner[:], owner)

			asset, err := decoder.Fixed(types.AssetIDSize)
			if err != nil {
				return Program{}, err
			}
			copy(program.Instructions[index].Asset[:], asset)
		case OpLoadFee, OpLoadHeight, OpAddU64, OpSubU64, OpEqualU64,
			OpLessOrEqualU64, OpGreaterOrEqualU64, OpAnd, OpOr, OpNot,
			OpRequire, OpHalt:
		default:
			return Program{}, fmt.Errorf("%w: 0x%02x", ErrInvalidOpcode, opcode)
		}
	}

	if err := program.Validate(); err != nil {
		return Program{}, err
	}
	return program, nil
}

func (program Program) Validate() error {
	if program.Version != Version0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, program.Version)
	}
	if len(program.Instructions) == 0 || len(program.Instructions) > MaxInstructions {
		return fmt.Errorf("%w: %d", ErrProgramSize, len(program.Instructions))
	}

	stack := make([]valueKind, 0, MaxStackDepth)
	push := func(kind valueKind) error {
		if len(stack) == MaxStackDepth {
			return ErrStackOverflow
		}
		stack = append(stack, kind)
		return nil
	}
	pop := func(expected valueKind) error {
		if len(stack) == 0 {
			return ErrStackUnderflow
		}
		actual := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if actual != expected {
			return fmt.Errorf("%w: have %d want %d", ErrTypeMismatch, actual, expected)
		}
		return nil
	}
	popTwo := func(expected valueKind) error {
		if err := pop(expected); err != nil {
			return err
		}
		return pop(expected)
	}

	for index, instruction := range program.Instructions {
		wrap := func(err error) error {
			return fmt.Errorf("instruction %d: %w", index, err)
		}

		switch instruction.Op {
		case OpPushU64, OpLoadFee, OpLoadHeight:
			if err := push(kindU64); err != nil {
				return wrap(err)
			}
		case OpLoadBalanceBefore, OpLoadBalanceAfter:
			if instruction.Owner.IsZero() || instruction.Asset.IsZero() {
				return wrap(ErrInvalidProgram)
			}
			if err := push(kindU64); err != nil {
				return wrap(err)
			}
		case OpAddU64, OpSubU64:
			if err := popTwo(kindU64); err != nil {
				return wrap(err)
			}
			if err := push(kindU64); err != nil {
				return wrap(err)
			}
		case OpEqualU64, OpLessOrEqualU64, OpGreaterOrEqualU64:
			if err := popTwo(kindU64); err != nil {
				return wrap(err)
			}
			if err := push(kindBool); err != nil {
				return wrap(err)
			}
		case OpAnd, OpOr:
			if err := popTwo(kindBool); err != nil {
				return wrap(err)
			}
			if err := push(kindBool); err != nil {
				return wrap(err)
			}
		case OpNot:
			if err := pop(kindBool); err != nil {
				return wrap(err)
			}
			if err := push(kindBool); err != nil {
				return wrap(err)
			}
		case OpRequire:
			if err := pop(kindBool); err != nil {
				return wrap(err)
			}
		case OpHalt:
			if index != len(program.Instructions)-1 || len(stack) != 0 {
				return wrap(ErrInvalidProgram)
			}
		default:
			return wrap(fmt.Errorf("%w: 0x%02x", ErrInvalidOpcode, instruction.Op))
		}
	}

	if program.Instructions[len(program.Instructions)-1].Op != OpHalt {
		return fmt.Errorf("%w: missing final HALT", ErrInvalidProgram)
	}
	return nil
}

func Execute(program Program, context Context) error {
	if context.Before == nil || context.After == nil {
		return ErrMissingContext
	}
	if err := program.Validate(); err != nil {
		return err
	}

	stack := make([]stackValue, 0, MaxStackDepth)
	pushU64 := func(value uint64) { stack = append(stack, stackValue{kind: kindU64, integer: value}) }
	pushBool := func(value bool) { stack = append(stack, stackValue{kind: kindBool, boolean: value}) }
	popU64 := func() uint64 {
		value := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return value.integer
	}
	popBool := func() bool {
		value := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return value.boolean
	}

	for index, instruction := range program.Instructions {
		switch instruction.Op {
		case OpPushU64:
			pushU64(instruction.Value)
		case OpLoadBalanceBefore:
			balance, err := context.Before.Balance(instruction.Owner, instruction.Asset)
			if err != nil {
				return fmt.Errorf("instruction %d: load before balance: %w", index, err)
			}
			pushU64(balance)
		case OpLoadBalanceAfter:
			balance, err := context.After.Balance(instruction.Owner, instruction.Asset)
			if err != nil {
				return fmt.Errorf("instruction %d: load after balance: %w", index, err)
			}
			pushU64(balance)
		case OpLoadFee:
			pushU64(context.Fee)
		case OpLoadHeight:
			pushU64(context.Height)
		case OpAddU64:
			right, left := popU64(), popU64()
			result, err := types.AddAmount(left, right)
			if err != nil {
				return fmt.Errorf("instruction %d: %w: %v", index, ErrArithmetic, err)
			}
			pushU64(result)
		case OpSubU64:
			right, left := popU64(), popU64()
			result, err := types.SubAmount(left, right)
			if err != nil {
				return fmt.Errorf("instruction %d: %w: %v", index, ErrArithmetic, err)
			}
			pushU64(result)
		case OpEqualU64:
			right, left := popU64(), popU64()
			pushBool(left == right)
		case OpLessOrEqualU64:
			right, left := popU64(), popU64()
			pushBool(left <= right)
		case OpGreaterOrEqualU64:
			right, left := popU64(), popU64()
			pushBool(left >= right)
		case OpAnd:
			right, left := popBool(), popBool()
			pushBool(left && right)
		case OpOr:
			right, left := popBool(), popBool()
			pushBool(left || right)
		case OpNot:
			pushBool(!popBool())
		case OpRequire:
			if !popBool() {
				return fmt.Errorf("instruction %d: %w", index, ErrRequirementFailed)
			}
		case OpHalt:
			return nil
		}
	}

	return ErrInvalidProgram
}
