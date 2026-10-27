package workarchive

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
)

func TestCustodyRemoteAssignmentSelectsFreshVersionWithoutChangingReplicaIdentity(t *testing.T) {
	f := newCustodyRecordFixture(t)
	key := func(seed byte) [32]byte {
		return [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	}
	consumers := []custodyauthority.Consumer{{PublicKey: key(123), Purposes: custodyauthority.AllPurposes}}
	incarnation := types.DomainHash("test/custody-remote-assignment/incarnation")
	local, err := CreateCustodyAuthorityAssignment(f.manifest, f.receipt, f.policy, incarnation, key(124), consumers, 16, 4)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := CreateRemoteCustodyAuthorityAssignment(f.manifest, f.receipt, f.policy, incarnation, key(124), consumers, 16, 4, key(125), key(126))
	if err != nil {
		t.Fatal(err)
	}
	localID, _ := local.ID()
	remoteID, _ := remote.ID()
	if local.Version != custodyauthority.Version0 || remote.Version != custodyauthority.Version1 || localID == remoteID ||
		remote.ReplicaPublicKey != local.ReplicaPublicKey || remote.ManifestID != local.ManifestID ||
		remote.InitialReceiptID != local.InitialReceiptID || remote.CustodyPolicyID != local.CustodyPolicyID ||
		remote.RemoteControlPublicKey != key(125) || remote.RemoteTransportPublicKey != key(126) {
		t.Fatal("remote selection changed archive identity or reused the old assignment")
	}
	if _, err := custodyauthority.NewState(remote, localID); !errors.Is(err, custodyauthority.ErrAssignment) {
		t.Fatal("remote assignment accepted the old independently retained pin", err)
	}
	if _, err := custodyauthority.NewState(local, remoteID); !errors.Is(err, custodyauthority.ErrAssignment) {
		t.Fatal("local assignment accepted the new independently retained pin", err)
	}
	consumers[0].Purposes = 0
	if remote.Consumers[0].Purposes != custodyauthority.AllPurposes || local.Consumers[0].Purposes != custodyauthority.AllPurposes {
		t.Fatal("caller mutation changed a selected assignment")
	}
	for _, role := range [][32]byte{key(124), key(123), f.receipt.ReplicaPublicKey, f.policy.TrustedAuditors[0], key(126), {}} {
		if _, err := CreateRemoteCustodyAuthorityAssignment(f.manifest, f.receipt, f.policy, incarnation, key(124), local.Consumers, 16, 4, role, key(126)); err == nil {
			t.Fatal("remote control key accepted a shared or missing role")
		}
	}
	altered := f.receipt
	altered.ManifestID = types.DomainHash("test/custody-remote-assignment/other-manifest")
	if _, err := CreateRemoteCustodyAuthorityAssignment(f.manifest, altered, f.policy, incarnation, key(124), local.Consumers, 16, 4, key(125), key(126)); err == nil {
		t.Fatal("remote selection accepted a changed receipt scope")
	}
}
