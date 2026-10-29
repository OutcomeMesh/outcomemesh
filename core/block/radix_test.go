package block

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/execution"
	"github.com/outcomemesh/outcomemesh/core/genesis"
	"github.com/outcomemesh/outcomemesh/core/outcome"
	"github.com/outcomemesh/outcomemesh/core/state"
)

func TestProtocol2TransferAndVersionIsolation(t *testing.T) {
	old, tx := testTransaction(t)
	radix, e := state.NewVersion(old.Resources(), state.CommitmentRadixV1)
	if e != nil {
		t.Fatal(e)
	}
	parameters := testParameters(tx.NetworkID)
	parameters.ProtocolVersion = Version2
	parent := testParent()
	candidate, result, e := Prepare(radix, parent, []outcome.Transaction{tx}, testMiner(), parent.Timestamp+1, parameters)
	if e != nil {
		t.Fatal(e)
	}
	if candidate.Header.Version != 2 || len(result.Receipts) != 1 || result.Receipts[0].Version != 2 || result.State.CommitmentVersion() != state.CommitmentRadixV1 {
		t.Fatal("version lost")
	}
	decoded, e := Decode(candidate.CanonicalBytes())
	if e != nil {
		t.Fatal(e)
	}
	actual, e := ValidateAndExecuteAt(radix, parent, decoded, parameters, candidate.Header.Timestamp)
	if e != nil || actual.FinalRoot != result.FinalRoot {
		t.Fatal("execute", e)
	}
	if _, _, e := Prepare(old, parent, nil, testMiner(), parent.Timestamp+1, parameters); !errors.Is(e, state.ErrCommitmentVersion) {
		t.Fatal("v0 state on v2", e)
	}
	legacy := parameters
	legacy.ProtocolVersion = 0
	if _, _, e := Prepare(radix, parent, nil, testMiner(), parent.Timestamp+1, legacy); !errors.Is(e, state.ErrCommitmentVersion) {
		t.Fatal("v1 state on v0", e)
	}
	if e := ValidateHeaderAt(parent, candidate.Header, legacy, candidate.Header.Timestamp); !errors.Is(e, ErrUnsupportedVersion) {
		t.Fatal("cross-version header", e)
	}
	if _, e := execution.Apply(radix, tx, execution.Context{NetworkID: tx.NetworkID, Height: 1}); !errors.Is(e, state.ErrCommitmentVersion) {
		t.Fatal("implicit context upgrade", e)
	}
	changed := candidate
	changed.Header.Version = 0
	if _, e := ValidateAndExecuteAt(radix, parent, changed, parameters, candidate.Header.Timestamp); !errors.Is(e, ErrUnsupportedVersion) {
		t.Fatal("downgrade", e)
	}
	parameters.ProtocolVersion = 1
	if parameters.Validate() == nil {
		t.Fatal("WorkGraph version collision")
	}
}

func TestProtocol2FixedVectors(t *testing.T) {
	raw, e := os.ReadFile("../state/testdata/radix-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct{ Genesis, GenesisID, Block, BlockID string }
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	gb, e := hex.DecodeString(f.Genesis)
	if e != nil {
		t.Fatal(e)
	}
	g, e := genesis.Decode(gb)
	if e != nil {
		t.Fatal(e)
	}
	id, e := g.ID()
	if e != nil || id.String() != f.GenesisID {
		t.Fatal("genesis ID", e)
	}
	bb, e := hex.DecodeString(f.Block)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Decode(bb)
	if e != nil {
		t.Fatal(e)
	}
	bid, e := b.Header.ID()
	if e != nil || bid.String() != f.BlockID {
		t.Fatal("block ID", e)
	}
	s, e := g.State()
	if e != nil {
		t.Fatal(e)
	}
	parent := Parent{ID: id, Timestamp: g.Timestamp, MedianTimePast: g.Timestamp, Target: g.Target}
	if _, e := ValidateAndExecuteAt(s, parent, b, ParametersFromGenesis(g), b.Header.Timestamp); e != nil {
		t.Fatal(e)
	}
	rebuilt, _, e := Prepare(s, parent, nil, b.Header.Miner, b.Header.Timestamp, ParametersFromGenesis(g))
	if e != nil || !bytes.Equal(rebuilt.CanonicalBytes(), bb) {
		t.Fatal("block rebuild", e)
	}
	g.Version = 0
	oldID, _ := g.ID()
	if oldID == id {
		t.Fatal("genesis version not committed")
	}
}
