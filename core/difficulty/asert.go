package difficulty

import (
	"errors"
	"math/big"

	"github.com/outcomemesh/outcomemesh/core/types"
)

const radixBits = 16

var (
	ErrAnchorTarget  = errors.New("ASERT anchor target is zero")
	ErrTargetSpacing = errors.New("ASERT target spacing is zero")
	ErrHalfLife      = errors.New("ASERT half-life is zero")
)

var (
	radix                 = new(big.Int).Lsh(big.NewInt(1), radixBits)
	polynomialRound       = new(big.Int).Lsh(big.NewInt(1), 47)
	polynomialDenominator = new(big.Int).Lsh(big.NewInt(1), 48)
)

// ASERT calculates the target for a block at height and timestamp from one
// absolute genesis anchor. It uses the aserti3 cubic approximation with
// integer-only arithmetic. The anchor target is also the easiest allowed
// target; a result below one is clamped to one.
func ASERT(anchorTarget types.Hash, anchorTimestamp, height, timestamp, targetSpacing, halfLife uint64) (types.Hash, error) {
	if anchorTarget.IsZero() {
		return types.Hash{}, ErrAnchorTarget
	}
	if targetSpacing == 0 {
		return types.Hash{}, ErrTargetSpacing
	}
	if halfLife == 0 {
		return types.Hash{}, ErrHalfLife
	}

	elapsed := new(big.Int).SetUint64(timestamp)
	elapsed.Sub(elapsed, new(big.Int).SetUint64(anchorTimestamp))
	schedule := new(big.Int).SetUint64(targetSpacing)
	schedule.Mul(schedule, new(big.Int).SetUint64(height))
	numerator := new(big.Int).Sub(elapsed, schedule)
	numerator.Lsh(numerator, radixBits)

	exponent := floorDiv(numerator, new(big.Int).SetUint64(halfLife))
	numShifts, fractional := floorDivMod(exponent, radix)

	// These limits avoid attacker-controlled enormous shifts while preserving
	// the exact clamped result for every 256-bit target.
	if numShifts.Cmp(big.NewInt(256)) >= 0 {
		return anchorTarget, nil
	}
	if numShifts.Cmp(big.NewInt(-512)) <= 0 {
		return integerTarget(1), nil
	}

	factor := polynomialFactor(fractional)
	target := new(big.Int).SetBytes(anchorTarget[:])
	target.Mul(target, factor)
	shift := numShifts.Int64()
	if shift < 0 {
		target.Rsh(target, uint(-shift))
	} else {
		target.Lsh(target, uint(shift))
	}
	target.Rsh(target, radixBits)

	if target.Sign() <= 0 {
		return integerTarget(1), nil
	}
	powLimit := new(big.Int).SetBytes(anchorTarget[:])
	if target.Cmp(powLimit) > 0 {
		return anchorTarget, nil
	}
	return hashTarget(target), nil
}

func polynomialFactor(fractional *big.Int) *big.Int {
	x := new(big.Int).Set(fractional)
	x2 := new(big.Int).Mul(new(big.Int).Set(x), x)
	x3 := new(big.Int).Mul(new(big.Int).Set(x2), x)

	result := new(big.Int).Mul(big.NewInt(195_766_423_245_049), x)
	result.Add(result, new(big.Int).Mul(big.NewInt(971_821_376), x2))
	result.Add(result, new(big.Int).Mul(big.NewInt(5_127), x3))
	result.Add(result, polynomialRound)
	result.Div(result, polynomialDenominator)
	result.Add(result, radix)
	return result
}

func floorDiv(numerator, denominator *big.Int) *big.Int {
	quotient, _ := floorDivMod(numerator, denominator)
	return quotient
}

func floorDivMod(numerator, denominator *big.Int) (*big.Int, *big.Int) {
	quotient := new(big.Int)
	remainder := new(big.Int)
	quotient.DivMod(new(big.Int).Set(numerator), new(big.Int).Set(denominator), remainder)
	return quotient, remainder
}

func integerTarget(value byte) types.Hash {
	var result types.Hash
	result[len(result)-1] = value
	return result
}

func hashTarget(value *big.Int) types.Hash {
	var result types.Hash
	encoded := value.Bytes()
	copy(result[len(result)-len(encoded):], encoded)
	return result
}
