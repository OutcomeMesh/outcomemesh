package remoteworker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func workerKey(value byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
}
func workerPublic(value byte) [32]byte {
	return [32]byte(workerKey(value).Public().(ed25519.PublicKey))
}
func workerHash(value byte) (id types.Hash) {
	for i := range id {
		id[i] = value
	}
	return id
}

func workerConfig(t testing.TB) Config {
	t.Helper()
	a0 := custodyauthority.Assignment{NetworkID: 77, GenesisID: workerHash(11), ActivationHeight: 2, BaseID: workerHash(12), ManifestID: workerHash(13),
		StatementID: workerHash(14), InitialReceiptID: workerHash(15), CustodyPolicyID: workerHash(16), IncarnationID: workerHash(17),
		AuthorityPublicKey: workerPublic(1), ReplicaPublicKey: workerPublic(2), Auditors: [][32]byte{workerPublic(3)},
		Consumers: []custodyauthority.Consumer{{PublicKey: workerPublic(4), Purposes: custodyauthority.AllPurposes}}, MaximumOperations: 16, MaximumPending: 4}
	a, err := custodyauthority.WithRemoteParticipant(a0, workerPublic(5), workerPublic(6))
	if err != nil {
		t.Fatal(err)
	}
	id, err := a.ID()
	if err != nil {
		t.Fatal(err)
	}
	c := custodyauthority.Command{Version: custodyauthority.Version1, AssignmentID: id, ExpectedHead: id, Kind: custodyauthority.Admit, Purpose: custodyauthority.Serve, OperationID: workerHash(21)}
	c, err = c.Sign(workerKey(4))
	if err != nil {
		t.Fatal(err)
	}
	admission, err := custodyauthority.SignEntry(c, workerKey(1))
	if err != nil {
		t.Fatal(err)
	}
	p := Plan{AssignmentID: id, Admission: admission, AuthorityTransportPublicKey: workerPublic(8), AuditorTransportPublicKey: workerPublic(7), PriorReceiptID: a.InitialReceiptID, Nonce: workerHash(22)}
	planID, err := p.ID()
	if err != nil {
		t.Fatal(err)
	}
	admissionID, _ := admission.ID()
	begin, err := custodyauthority.BuildRemoteBeginCommand(a, admission, planID, custodyauthority.Position{Sequence: 1, HeadID: admissionID})
	if err != nil {
		t.Fatal(err)
	}
	begin, err = begin.Sign(workerKey(5))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := custodyauthority.SignEntry(begin, workerKey(1))
	if err != nil {
		t.Fatal(err)
	}
	beginID, _ := entry.ID()
	return Config{Assignment: a, Plan: p, PlanID: planID, Begin: entry, BeginID: beginID}
}

func TestPlanAndSealGoldenAndBounds(t *testing.T) {
	c := workerConfig(t)
	if err := c.Plan.Validate(c.Assignment); err != nil {
		t.Fatal(err)
	}
	b, err := c.Plan.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// Fixed deterministic Ed25519 fixture; golden pins both transport roles,
	// exact signed admission, predecessor, nonce and this codec's domain.
	const wantPlanID = "29e1f46f85cf0d4a6b9b883c0c0e227659961e46eef1bd473b326770f0779929"
	if len(b) != 594 || c.PlanID.String() != wantPlanID {
		t.Fatalf("plan golden len=%d id=%s hex=%x", len(b), c.PlanID, b)
	}
	decoded, err := DecodePlan(b)
	if err != nil || decoded != c.Plan {
		t.Fatal("plan roundtrip", err)
	}
	seal := Seal{PlanID: workerHash(1), BeginID: workerHash(2), SealingID: workerHash(3), Disposition: NoResult}
	sb, err := seal.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	const wantSealHex = "4f4d43525345414c0000010101010101010101010101010101010101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303020000000000000000000000000000000000000000000000000000000000000000"
	id, _ := seal.ID()
	const wantSealID = "7070477c5923dbd0a7c28cb445b81b1b66129b9d456f8627d0b75e86fe67c52c"
	if len(sb) != 139 || hex.EncodeToString(sb) != wantSealHex || id.String() != wantSealID {
		t.Fatalf("seal golden len=%d id=%s hex=%x", len(sb), id, sb)
	}
	goldenSeal, err := hex.DecodeString(wantSealHex)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := DecodeSeal(goldenSeal)
	if err != nil || parsed != seal {
		t.Fatal("seal roundtrip", err)
	}
	for _, bad := range [][]byte{nil, b[:len(b)-1], append(bytes.Clone(b), 0), bytes.Repeat([]byte{1}, MaximumPlanBytes+1)} {
		if _, err := DecodePlan(bad); err == nil {
			t.Fatal("accepted malformed plan")
		}
	}
	for _, bad := range [][]byte{nil, sb[:len(sb)-1], append(bytes.Clone(sb), 0), bytes.Repeat([]byte{1}, SealBytes+1)} {
		if _, err := DecodeSeal(bad); err == nil {
			t.Fatal("accepted malformed seal")
		}
	}
}

func TestPlanRejectsScopeAndTransportRoleSubstitution(t *testing.T) {
	c := workerConfig(t)
	keys := append([][32]byte{c.Assignment.AuthorityPublicKey, c.Assignment.ReplicaPublicKey, c.Assignment.RemoteControlPublicKey, c.Assignment.RemoteTransportPublicKey}, c.Assignment.Auditors...)
	for _, consumer := range c.Assignment.Consumers {
		keys = append(keys, consumer.PublicKey)
	}
	keys = append(keys, [32]byte{})
	for _, key := range keys {
		for _, authority := range []bool{false, true} {
			p := c.Plan
			if authority {
				p.AuthorityTransportPublicKey = key
			} else {
				p.AuditorTransportPublicKey = key
			}
			if err := p.Validate(c.Assignment); err == nil {
				t.Fatal("accepted a transport key in another role")
			}
		}
	}
	for _, mutate := range []func(*Plan){
		func(p *Plan) { p.AuthorityTransportPublicKey = p.AuditorTransportPublicKey }, func(p *Plan) { p.Nonce = types.Hash{} },
		func(p *Plan) { p.AssignmentID = workerHash(99) }, func(p *Plan) { p.PriorReceiptID = workerHash(99) },
		func(p *Plan) { p.PriorSequence = 1 }, func(p *Plan) { p.PriorHeadID = workerHash(99) }, func(p *Plan) { p.PriorSequence = ^uint64(0) },
		func(p *Plan) { p.Version = 1 }, func(p *Plan) { p.Admission.Signature[0] ^= 1 },
	} {
		p := c.Plan
		mutate(&p)
		if err := p.Validate(c.Assignment); err == nil {
			t.Fatal("accepted mismatched plan")
		}
	}
	p := c.Plan
	p.PriorSequence = 3
	p.PriorHeadID = workerHash(30)
	p.PriorReceiptID = workerHash(31)
	if err := p.Validate(c.Assignment); err != nil {
		t.Fatal("rejected an explicit noninitial predecessor", err)
	}
	for _, field := range []string{"authority", "auditor"} {
		p := c.Plan
		if field == "authority" {
			p.AuthorityTransportPublicKey = workerPublic(9)
		} else {
			p.AuditorTransportPublicKey = workerPublic(9)
		}
		id, err := p.ID()
		if err != nil || id == c.PlanID {
			t.Fatal("transport change was not committed", err)
		}
	}
}

func FuzzDecodeRemoteWorkerArtifacts(f *testing.F) {
	c := workerConfig(f)
	plan, _ := c.Plan.CanonicalBytes()
	seal, _ := (Seal{PlanID: c.PlanID, BeginID: c.BeginID, SealingID: workerHash(44), Disposition: RetainedResult, ResultID: workerHash(45)}).CanonicalBytes()
	f.Add(plan, seal)
	f.Add([]byte{}, []byte{})
	f.Add(plan[:10], seal[:10])
	f.Fuzz(func(t *testing.T, pb, sb []byte) {
		if p, err := DecodePlan(pb); err == nil {
			b, err := p.CanonicalBytes()
			if err != nil || !bytes.Equal(b, pb) {
				t.Fatal("accepted noncanonical plan", err)
			}
		}
		if s, err := DecodeSeal(sb); err == nil {
			b, err := s.CanonicalBytes()
			if err != nil || !bytes.Equal(b, sb) {
				t.Fatal("accepted noncanonical seal", err)
			}
		}
	})
}
