package pruneservice

import (
	"bytes"
	"github.com/outcomemesh/outcomemesh/core/resource"
	"github.com/outcomemesh/outcomemesh/core/state"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
	"testing"
	"time"
)

func configFor(t testing.TB, version uint16) Config {
	t.Helper()
	h := types.DomainHash("prune-service-test", []byte("resource"))
	s, err := state.NewVersion([]resource.Resource{{ID: types.ResourceID(h), Owner: types.Address(h), Asset: types.NativeAssetID(), Amount: 37}}, version)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{GuardURL: "http://127.0.0.1:1", Witnesses: []prunenet.Endpoint{{Address: "/ip4/127.0.0.1/udp/1/quic-v1"}}, WitnessTimeout: time.Second}
	c.Runtime.Base.State = s
	return c
}

func TestPruneServiceConfigPreservesCompleteBaseState(t *testing.T) {
	for _, version := range []uint16{0, 1} {
		c := configFor(t, version)
		raw, err := EncodeConfig(c)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Runtime.Base.State.Root() != c.Runtime.Base.State.Root() || decoded.Runtime.Base.State.CommitmentVersion() != version || len(decoded.Runtime.Base.State.Resources()) != 1 {
			t.Fatal("base state lost")
		}
		if c.Runtime.Base.State == nil {
			t.Fatal("caller mutated")
		}
		for _, bad := range [][]byte{append(append([]byte{}, raw...), byte('\n')), append([]byte(`{"Version":0,`), raw[1:]...), bytes.Replace(raw, []byte(`"StateVersion":`), []byte(`"UnknownVersion":`), 1), bytes.Replace(raw, []byte(`"State":null`), []byte(`"State":{}`), 1)} {
			if _, err = DecodeConfig(bad); err == nil {
				t.Fatal("ambiguous or lossy config accepted")
			}
		}
	}
}

func TestPruneServiceConfigRejectsLossyPaths(t *testing.T) {
	c := configFor(t, 1)
	c.Runtime.ExecutorPath = "/private/" + string([]byte{0xff})
	if _, err := EncodeConfig(c); err == nil {
		t.Fatal("JSON would change the selected executor path")
	}
}

func FuzzPruneServiceConfig(f *testing.F) {
	for _, version := range []uint16{0, 1} {
		raw, err := EncodeConfig(configFor(f, version))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		c, err := DecodeConfig(raw)
		if err != nil {
			return
		}
		out, err := EncodeConfig(c)
		if err != nil || !bytes.Equal(raw, out) {
			t.Fatal("accepted config not canonical")
		}
	})
}
