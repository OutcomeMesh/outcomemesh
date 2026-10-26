package store

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func TestManagedCustodyServePinnedQUIC(t *testing.T) {
	for _, mode := range []string{"fresh", "cached", "recovered"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedServeFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			client, err := libp2ptransport.New(ctx, testKey(44), libp2ptransport.DefaultConfig(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			serverConfig := libp2ptransport.DefaultConfig()
			serverConfig.MaxArchiveCustodyStreamsPerMinute = 2
			server, err := libp2ptransport.New(ctx, testKey(45), serverConfig, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			f.config.AuditorPeerID = client.ID()
			session, err := NewManagedCustodyServeSession(ctx, f.archive.f.coordinator, f.config)
			if err != nil {
				t.Fatal(err)
			}
			before := testCoordination(t, f.archive.f.coordinator)
			var warmReport workarchive.CustodyServeReport
			var warmRecord []byte
			if mode != "fresh" {
				warm := newManagedServeStream(t, f.challenge)
				warmReport, err = session.Serve(ctx, client.ID(), warm)
				if err != nil || warmReport.JournalSequence != 1 {
					t.Fatal("warm managed response", err)
				}
				warmRecord, err = f.verifiedRecord(t, warm.output.Bytes()).CanonicalBytes()
				if err != nil {
					t.Fatal(err)
				}
				if mode == "recovered" {
					session, err = NewManagedCustodyServeSession(ctx, f.archive.f.coordinator, f.config)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			type result struct {
				report workarchive.CustodyServeReport
				err    error
			}
			served := make(chan result, 2)
			if err := server.SetArchiveCustodyHandler([]types.Hash{client.ID()}, func(handlerContext context.Context, peer types.Hash, stream network.Stream) {
				report, err := session.Serve(handlerContext, peer, stream)
				served <- result{report: report, err: err}
			}); err != nil {
				t.Fatal(err)
			}
			audit, err := workarchive.NewCustodyAuditorSession(f.config.Manifest, f.config.InitialReceipt, f.config.CustodyPolicy, f.config.SessionConfig)
			if err != nil {
				t.Fatal(err)
			}
			exchange := func(attempt string) (workarchive.CustodyResponse, workarchive.CustodyAuditReport, error, result) {
				t.Helper()
				stream, peer, err := client.OpenArchiveCustodyStream(ctx, server.Addresses()[0], server.ID())
				if err != nil || peer != server.ID() {
					t.Fatalf("%s: pinned transport open: peer=%s error=%v", attempt, peer, err)
				}
				if stream.Protocol() != libp2ptransport.ArchiveCustodyProtocol {
					t.Fatalf("%s: wrong custody protocol %s", attempt, stream.Protocol())
				}
				response, report, auditErr := audit.Audit(ctx, stream, f.challenge)
				select {
				case handled := <-served:
					return response, report, auditErr, handled
				case <-ctx.Done():
					t.Fatalf("%s: managed handler did not drain: audit=%v context=%v", attempt, auditErr, ctx.Err())
					return workarchive.CustodyResponse{}, workarchive.CustodyAuditReport{}, auditErr, result{}
				}
			}
			response, auditReport, auditErr, accepted := exchange("admitted")
			if auditErr != nil || accepted.err != nil || accepted.report.JournalSequence != 1 ||
				accepted.report.ChallengeID != f.config.ChallengeID || accepted.report.ChallengeID != auditReport.ChallengeID ||
				accepted.report.ProofID != auditReport.ProofID || accepted.report.RenewedReceiptID != auditReport.RenewedReceiptID {
				t.Fatalf("admitted: audit=%v handler=%v audit_report=%+v serve_report=%+v", auditErr, accepted.err, auditReport, accepted.report)
			}
			state := f.state(t, 1)
			head, exists, err := f.journal.Head()
			if err != nil || !exists {
				t.Fatal("missing committed response", err)
			}
			persisted, err := head.Record.CanonicalBytes()
			if err != nil {
				t.Fatal(err)
			}
			received, err := (workarchive.CustodyRecord{Version: workarchive.CustodyRecordVersion0, Challenge: f.challenge,
				Batch: response.Batch, Proof: response.Proof, RenewedReceipt: response.RenewedReceipt}).CanonicalBytes()
			if err != nil || !bytes.Equal(persisted, received) || state.CurrentReceipt != response.RenewedReceipt {
				t.Fatal("QUIC response differs from the exact persisted record", err)
			}
			if mode != "fresh" && (!bytes.Equal(warmRecord, received) || warmReport != accepted.report) {
				t.Fatal("cached/recovered QUIC delivery minted another response")
			}
			if !reflect.DeepEqual(before, testCoordination(t, f.archive.f.coordinator)) {
				t.Fatal("Serve completed or changed authority")
			}
			ticket, _ := f.config.Admission.ID()
			complete := testEntry(t, before.Authority, custodyauthority.Complete, types.Hash{}, ticket, accepted.report.RenewedReceiptID)
			appendCoordinated(t, f.archive.f.coordinator, complete)
			completed := testCoordination(t, f.archive.f.coordinator)
			_, _, rejectedAuditErr, rejected := exchange("completed")
			if rejectedAuditErr == nil || !errors.Is(rejected.err, custodyauthority.ErrOperation) {
				t.Fatalf("completed: audit=%v handler=%v report=%+v", rejectedAuditErr, rejected.err, rejected.report)
			}
			if after, err := f.journal.State(); err != nil || !reflect.DeepEqual(state, after) {
				t.Fatal("completed exchange changed persisted evidence", err)
			}
			if !reflect.DeepEqual(completed, testCoordination(t, f.archive.f.coordinator)) {
				t.Fatal("rejected delivery changed authority")
			}
		})
	}
}
