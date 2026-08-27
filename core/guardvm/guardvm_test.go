package guardvm

import (
	"errors"
	"math"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/codec"
	"github.com/outcomemesh/outcomemesh/core/types"
)

type balanceKey struct {
	owner types.Address
	asset types.AssetID
}

type balanceView map[balanceKey]uint64

func (view balanceView) Balance(owner types.Address, asset types.AssetID) (uint64, error) {
	return view[balanceKey{owner: owner, asset: asset}], nil
}

func TestProgramCanonicalRoundTrip(t *testing.T) {
	t.Parallel()

	owner, asset := testOwnerAndAsset()
	program := maxSpendProgram(owner, asset, 100, 10)
	encoded := program.CanonicalBytes()
	decoder := codec.NewDecoder(encoded)
	decoded, err := DecodeProgram(decoder)
	if err != nil {
		t.Fatalf("DecodeProgram() error = %v", err)
	}
	if err := decoder.Finish(); err != nil {
		t.Fatalf("Finish() error = %v", err)
	}
	if len(decoded.Instructions) != len(program.Instructions) {
		t.Fatalf("instruction count = %d, want %d", len(decoded.Instructions), len(program.Instructions))
	}
	if string(decoded.CanonicalBytes()) != string(encoded) {
		t.Fatal("program did not preserve canonical encoding")
	}
}

func TestExecuteAcceptsBoundedOutcome(t *testing.T) {
	t.Parallel()

	owner, asset := testOwnerAndAsset()
	program := maxSpendProgram(owner, asset, 100, 10)
	context := Context{
		Before: balanceView{{owner: owner, asset: asset}: 1_000},
		After:  balanceView{{owner: owner, asset: asset}: 905},
		Fee:    5,
		Height: 10,
	}
	if err := Execute(program, context); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestExecuteRejectsExcessiveSpend(t *testing.T) {
	t.Parallel()

	owner, asset := testOwnerAndAsset()
	program := maxSpendProgram(owner, asset, 100, 10)
	context := Context{
		Before: balanceView{{owner: owner, asset: asset}: 1_000},
		After:  balanceView{{owner: owner, asset: asset}: 899},
		Fee:    5,
		Height: 10,
	}
	err := Execute(program, context)
	if !errors.Is(err, ErrRequirementFailed) {
		t.Fatalf("error = %v, want %v", err, ErrRequirementFailed)
	}
}

func TestExecuteRejectsArithmeticOverflow(t *testing.T) {
	t.Parallel()

	program := Program{
		Version: Version0,
		Instructions: []Instruction{
			{Op: OpPushU64, Value: math.MaxUint64},
			{Op: OpPushU64, Value: 1},
			{Op: OpAddU64},
			{Op: OpPushU64, Value: 0},
			{Op: OpEqualU64},
			{Op: OpRequire},
			{Op: OpHalt},
		},
	}
	err := Execute(program, Context{Before: balanceView{}, After: balanceView{}})
	if !errors.Is(err, ErrArithmetic) {
		t.Fatalf("error = %v, want %v", err, ErrArithmetic)
	}
}

func TestValidateRejectsMalformedPrograms(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		program Program
		want    error
	}{
		{name: "empty", program: Program{Version: Version0}, want: ErrProgramSize},
		{name: "unknown opcode", program: Program{Version: Version0, Instructions: []Instruction{{Op: 0xff}}}, want: ErrInvalidOpcode},
		{name: "stack underflow", program: Program{Version: Version0, Instructions: []Instruction{{Op: OpRequire}, {Op: OpHalt}}}, want: ErrStackUnderflow},
		{name: "nonempty halt", program: Program{Version: Version0, Instructions: []Instruction{{Op: OpPushU64}, {Op: OpHalt}}}, want: ErrInvalidProgram},
		{name: "missing halt", program: Program{Version: Version0, Instructions: []Instruction{{Op: OpPushU64}}}, want: ErrInvalidProgram},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.program.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func FuzzDecodeProgramNeverPanics(f *testing.F) {
	owner, asset := testOwnerAndAsset()
	f.Add(maxSpendProgram(owner, asset, 100, 10).CanonicalBytes())
	f.Add([]byte{})
	f.Add([]byte{0, 0, 1, 0xff})

	f.Fuzz(func(t *testing.T, input []byte) {
		decoder := codec.NewDecoder(input)
		_, _ = DecodeProgram(decoder)
	})
}

func FuzzExecuteDecodedProgramNeverPanics(f *testing.F) {
	owner, asset := testOwnerAndAsset()
	f.Add(maxSpendProgram(owner, asset, 100, 10).CanonicalBytes(), uint64(1_000), uint64(905), uint64(5), uint64(10))
	f.Add([]byte{}, uint64(0), uint64(0), uint64(0), uint64(0))

	f.Fuzz(func(t *testing.T, encoded []byte, before, after, fee, height uint64) {
		decoder := codec.NewDecoder(encoded)
		program, err := DecodeProgram(decoder)
		if err != nil || decoder.Finish() != nil {
			return
		}
		_ = Execute(program, Context{
			Before: balanceView{{owner: owner, asset: asset}: before},
			After:  balanceView{{owner: owner, asset: asset}: after},
			Fee:    fee,
			Height: height,
		})
	})
}

func maxSpendProgram(owner types.Address, asset types.AssetID, maxSpend, maxFee uint64) Program {
	return Program{
		Version: Version0,
		Instructions: []Instruction{
			{Op: OpLoadBalanceBefore, Owner: owner, Asset: asset},
			{Op: OpLoadBalanceAfter, Owner: owner, Asset: asset},
			{Op: OpPushU64, Value: maxSpend},
			{Op: OpAddU64},
			{Op: OpLessOrEqualU64},
			{Op: OpRequire},
			{Op: OpLoadFee},
			{Op: OpPushU64, Value: maxFee},
			{Op: OpLessOrEqualU64},
			{Op: OpRequire},
			{Op: OpHalt},
		},
	}
}

func testOwnerAndAsset() (types.Address, types.AssetID) {
	var owner types.Address
	owner[31] = 1
	var asset types.AssetID
	asset[31] = 2
	return owner, asset
}
