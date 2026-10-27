package witnesswire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
)

func fixture(t testing.TB) (custodyfence.Scope, Request, Response) {
	t.Helper()
	s := f.Scope()
	id, _ := s.ID()
	p := custodyfence.WitnessPin{Position: custodyfence.Position{HeadID: id}}
	c := f.Sign(s, p.Position, custodyfence.Claim, types.Hash{}, types.Hash{})
	r := Request{Kind: Vote, ScopeID: id, Nonce: f.Hash("request"), Expected: p, Command: c}
	w, err := custodyfence.Create(filepath.Join(t.TempDir(), "owner"), s, id, f.Key(70))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	vote, err := w.VoteAt(p, c)
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := r.ID()
	obs, err := w.Observe(rid)
	if err != nil {
		t.Fatal(err)
	}
	return s, r, Response{Observation: obs, Vote: vote}
}

func TestWitnessWireCanonicalResponseAndExactBindings(t *testing.T) {
	s, r, response := fixture(t)
	if err := ValidateResponse(s, r, response, f.Public(70)); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Request){func(r *Request) { r.Nonce = f.Hash("replay-other-nonce") }, func(r *Request) { r.Expected.PendingID = f.Hash("other-lock") }, func(r *Request) { r.ScopeID = f.Hash("other-scope") }} {
		bad := r
		change(&bad)
		if err := ValidateResponse(s, bad, response, f.Public(70)); err == nil {
			t.Fatal("substituted request accepted")
		}
	}
	if err := ValidateResponse(s, r, response, f.Public(71)); err == nil {
		t.Fatal("wrong independently selected signer accepted")
	}
	for _, encoded := range []interface{ CanonicalBytes() ([]byte, error) }{r, response, response.Observation} {
		b, err := encoded.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0)} {
			if _, err := DecodeRequest(bad); err == nil {
				t.Fatal("bad request encoding")
			}
			if _, err := DecodeResponse(bad); err == nil {
				t.Fatal("bad response encoding")
			}
			if _, err := custodyfence.DecodeObservation(bad); err == nil {
				t.Fatal("bad observation encoding")
			}
		}
	}
}
func TestWitnessWireFrameBoundsAndPartialWrites(t *testing.T) {
	_, r, _ := fixture(t)
	var b bytes.Buffer
	if err := WriteRequest(&b, r); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadRequest(&b)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := decoded.ID()
	want, _ := r.ID()
	if got != want {
		t.Fatal("frame changed request")
	}
	for _, n := range []uint32{0, MaxFrameBytes + 1, ^uint32(0)} {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], n)
		if _, err := ReadRequest(bytes.NewReader(prefix[:])); err == nil {
			t.Fatal("oversized/empty frame accepted")
		}
	}
	if err := WriteRequest(zeroWriter{}, r); err == nil {
		t.Fatal("zero progress writer accepted")
	}
}

func TestWitnessWireFixedSignatureVectors(t *testing.T) {
	_, request, response := fixture(t)
	id, _ := request.ID()
	raw, _ := request.CanonicalBytes()
	reply, _ := response.CanonicalBytes()
	observation, _ := response.Observation.CanonicalBytes()
	if id.String() != "36a17d1b540789fb9bd70c44d6c470f50e3bad20cc01fe739f2f37e2a82f656b" || len(raw) != 360 || len(reply) != 458 || len(observation) != 308 {
		t.Fatal("witness V0 request/length vector changed", id)
	}
	if fmt.Sprintf("%x", sha256.Sum256(reply)) != "cf016899511878467e2f50686bfe2f326eccacaa6b71a160d227e5f9871ab65f" ||
		fmt.Sprintf("%x", sha256.Sum256(observation)) != "cebc4c27a3c68977c7bb49bb47ad3518c60e2a16c9afcaf2fecf1f3bb4d700e0" {
		t.Fatal("witness V0 signature/domain vector changed")
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
func FuzzWitnessWireCodecs(fz *testing.F) {
	_, r, response := fixture(fz)
	rb, _ := r.CanonicalBytes()
	sb, _ := response.CanonicalBytes()
	ob, _ := response.Observation.CanonicalBytes()
	fz.Add(rb)
	fz.Add(sb)
	fz.Add(ob)
	fz.Add([]byte{})
	fz.Fuzz(func(t *testing.T, b []byte) {
		if r, err := DecodeRequest(b); err == nil {
			out, err := r.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("request round trip")
			}
		}
		if r, err := DecodeResponse(b); err == nil {
			out, err := r.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("response round trip")
			}
		}
		if r, err := custodyfence.DecodeObservation(b); err == nil {
			out, err := r.CanonicalBytes()
			if err != nil || !bytes.Equal(b, out) {
				t.Fatal("observation round trip")
			}
		}
	})
}
