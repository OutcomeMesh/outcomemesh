package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestCustodyAuthorityAssignmentBindsEvidenceWithoutActivatingIt(t *testing.T) {
	f := newCustodyRecordFixture(t)
	key := func(seed byte) [ed25519.PublicKeySize]byte {
		return [ed25519.PublicKeySize]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	}
	consumers := []custodyauthority.Consumer{{PublicKey: key(123), Purposes: custodyauthority.AllPurposes}}
	incarnation := types.DomainHash("test/custody-authority/assignment/incarnation")
	a, err := CreateCustodyAuthorityAssignment(f.manifest, f.receipt, f.policy, incarnation, key(124), consumers, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	manifestID, _ := f.manifest.ID()
	receiptID, _ := f.receipt.ID()
	policyID, _ := custodyJournalPolicyID(f.policy)
	if a.ManifestID != manifestID || a.InitialReceiptID != receiptID || a.CustodyPolicyID != policyID || a.StatementID != f.receipt.StatementID ||
		a.NetworkID != f.receipt.Binding.NetworkID || a.GenesisID != f.receipt.Binding.GenesisID || a.ActivationHeight != f.receipt.Binding.ActivationHeight || a.BaseID != f.receipt.Binding.BaseID || a.ReplicaPublicKey != f.receipt.ReplicaPublicKey {
		t.Fatal("assignment lost evidence binding")
	}
	consumers[0].Purposes = 0
	if a.Consumers[0].Purposes != custodyauthority.AllPurposes {
		t.Fatal("consumer input aliases assignment")
	}
	encoded, err := a.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReplicaReceipt(encoded); err == nil {
		t.Fatal("assignment became live replica receipt")
	}
	if _, err := DecodeCustodyChallenge(encoded); err == nil {
		t.Fatal("assignment became live custody challenge")
	}
	if _, err := DecodeCustodyRebaselineProposal(encoded); err == nil {
		t.Fatal("assignment became rebaseline proposal")
	}
	if _, err := CreateCustodyAuthorityAssignment(f.manifest, f.receipt, f.policy, incarnation, f.receipt.ReplicaPublicKey, a.Consumers, 16, 4); !errors.Is(err, custodyauthority.ErrAssignment) {
		t.Fatal("evidence key also controls authority", err)
	}
	if _, err := CreateCustodyAuthorityAssignment(f.manifest, f.receipt, f.policy, types.Hash{}, key(124), a.Consumers, 16, 4); !errors.Is(err, custodyauthority.ErrAssignment) {
		t.Fatal("missing incarnation accepted", err)
	}
	altered := f.receipt
	altered.ManifestID = types.DomainHash("test/other-archive")
	if _, err := CreateCustodyAuthorityAssignment(f.manifest, altered, f.policy, incarnation, key(124), a.Consumers, 16, 4); err == nil {
		t.Fatal("invalid receipt binding accepted")
	}
	changedPolicy := f.policy
	changedPolicy.MaximumProofAge++
	other, err := CreateCustodyAuthorityAssignment(f.manifest, f.receipt, changedPolicy, incarnation, key(124), a.Consumers, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := a.ID()
	otherID, _ := other.ID()
	if id == otherID {
		t.Fatal("timing policy change kept old authority assignment")
	}
	if _, err := custodyauthority.NewState(other, id); !errors.Is(err, custodyauthority.ErrAssignment) {
		t.Fatal("changed policy accepted under old independent pin", err)
	}
}
