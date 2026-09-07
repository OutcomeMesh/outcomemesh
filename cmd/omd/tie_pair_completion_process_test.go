//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/calibration"
	"github.com/outcomemesh/outcomemesh/node/tieexchange"
	"github.com/outcomemesh/outcomemesh/node/tieproducer"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// Hold back the final ACK read and then the coordinator's EOF. Both observer
// commands must keep their host alive across these independently gated steps.
func TestProcessTiePairCompletionWaitsForCoordinatorEOF(t *testing.T) {
	for _, mode := range []string{"one-shot", "campaign"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newCampaignStorageProcessFixture(t, "close-barrier-"+mode, "20260906")
			pairPath := fixture.root + "/pair.omtpair"
			created := runProcessCommand(t, 30*time.Second,
				"work-telemetry-tie-pair-create", "--data", fixture.coordinatorData,
				"--plan", fixture.planPath, "--plan-id", fixture.planID.String(),
				"--coordinator-public-key", fixture.coordinatorPublicKey,
				"--observer-public-key", fixture.observerPublicKey,
				"--sequence", "1", "--output", pairPath,
			)
			pairID, err := parseHash(outputFields(created, "work_tie_pair_created")["pair"])
			if err != nil {
				t.Fatal(err)
			}
			var receiver *tieReceiverProcess
			var peerIDText, address string
			if mode == "one-shot" {
				receiver, peerIDText, address = startTieReceiverProcess(t,
					fixture.observerData, fixture.observerTransportKey, fixture.observerReceiptKey,
					fixture.coordinatorTransportID, fixture.planPath, fixture.planID.String(),
					fixture.coordinatorPublicKey, pairID.String(),
				)
			} else {
				key, err := loadPrivateKey(fixture.coordinatorPlanKey)
				if err != nil {
					t.Fatal(err)
				}
				checkpoint, err := calibration.SignTiePairCheckpoint(key, fixture.plan, fixture.binding, fixture.planID, 1, pairID)
				if err != nil {
					t.Fatal(err)
				}
				id, err := checkpoint.ID(fixture.plan, fixture.binding, fixture.planID)
				if err != nil {
					t.Fatal(err)
				}
				if err := tieproducer.PublishCampaignCheckpoint(
					fixture.publicationDirectory, fixture.plan, fixture.binding, fixture.planID, checkpoint, id,
				); err != nil {
					t.Fatal(err)
				}
				receiver, peerIDText, address = startCampaignStorageObserver(t, fixture, "")
			}
			peerID, err := parseHash(peerIDText)
			if err != nil {
				t.Fatal(err)
			}
			key, err := loadPrivateKey(fixture.coordinatorTransportKey)
			if err != nil {
				t.Fatal(err)
			}
			observerKey, err := loadPrivateKey(fixture.observerReceiptKey)
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := readTiePairFile(pairPath)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := libp2ptransport.New(ctx, key, libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			stream, _, err := client.OpenTiePairStream(ctx, address, &peerID)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			deadline, _ := ctx.Deadline()
			if err := stream.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			binding := tieexchange.Binding{PlanID: fixture.planID, PairID: pairID, Sequence: 1}
			if err := tieexchange.WriteRequest(stream, tieexchange.Request{Binding: binding, Artifact: artifact}); err != nil {
				t.Fatal(err)
			}
			ack, err := tieexchange.ReadAcknowledgement(stream, binding, hashFromPublicKey(observerKey.Public().(ed25519.PublicKey)))
			if err != nil {
				t.Fatal(err)
			}
			if err := tieexchange.WriteConfirmation(stream, tieexchange.Confirmation{Binding: binding, ReceiptTail: ack.ReceiptTail}); err != nil {
				t.Fatal(err)
			}
			// Reading one byte proves the receiver reached final-ACK publication,
			// without yet consuming that ACK or closing the coordinator stream.
			var prefix [1]byte
			if _, err := io.ReadFull(stream, prefix[:]); err != nil {
				t.Fatal(err)
			}
			assertTieReceiverStillRunning(t, receiver, "before reading the final ACK")
			if _, err := tieexchange.ReadConfirmationAcknowledgement(io.MultiReader(bytes.NewReader(prefix[:]), stream), binding, ack.ReceiptTail); err != nil {
				t.Fatal(err)
			}
			assertTieReceiverStillRunning(t, receiver, "before coordinator EOF")
			retireTiePairCoordinatorStream(ctx, stream)
			output := waitTieReceiverProcess(t, receiver)
			prefixName := "work_tie_pair_received"
			if mode == "campaign" {
				prefixName = "work_tie_campaign_pair_received"
			}
			if outputFields(output, prefixName)["receipt_tail"] != ack.ReceiptTail.String() {
				t.Fatalf("completion changed the durable receipt: %s", output)
			}
			_, receipts, aggregate, err := calibration.LoadTieReceiptFile(defaultTieReceiptPath(fixture.observerData), fixture.binding)
			if err != nil || len(receipts) != 1 || !aggregate.Complete {
				t.Fatalf("receipt state: count=%d complete=%t error=%v", len(receipts), aggregate.Complete, err)
			}
		})
	}
}

func assertTieReceiverStillRunning(t testing.TB, receiver *tieReceiverProcess, boundary string) {
	t.Helper()
	select {
	case <-receiver.stdoutDone:
		t.Fatalf("receiver exited %s: stdout=%s", boundary, receiver.stdout.String())
	case <-time.After(150 * time.Millisecond):
	}
}
