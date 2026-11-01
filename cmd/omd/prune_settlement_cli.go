package main

import (
	"context"
	"flag"
	"io"
	"os"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	"github.com/outcomemesh/outcomemesh/node/prunefence/prunenet"
)

const pruneSettlementCommand = "work-prune-settlement"

// Offline signatures and network selection operate only on explicitly pinned
// artifacts. They do not open executors/storage or apply accounting changes.
func runPruneSettlementCLI(ctx context.Context, args []string, out io.Writer) error {
	if ctx == nil || out == nil {
		return prunefence.ErrFence
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f := flag.NewFlagSet(pruneSettlementCommand, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("mode", "review", "review, sign, collect or verify")
	planPath := f.String("plan", "", "original plan")
	planText := f.String("plan-id", "", "independently retained plan ID")
	inventoryPath := f.String("inventory", "", "original inventory")
	inventoryText := f.String("inventory-id", "", "independently retained inventory ID")
	proposalPath := f.String("proposal", "", "exact proposal artifact")
	proposalText := f.String("proposal-id", "", "independently retained proposal ID")
	role := f.String("role", "", "review/sign: owner or controller")
	keyPath := f.String("key", "", "sign: original role seed")
	expected := f.String("expected-review-id", "", "sign: exact preceding review ID")
	network := f.String("fence-network", "", "collect: original witness endpoints and transport pins")
	controller := f.String("controller-key", "", "collect: original controller seed")
	transport := f.String("fence-transport-key", "", "collect: client transport seed")
	timeout := f.Duration("fence-timeout", 5*time.Second, "bounded time per witness")
	dest := f.String("out", "", "sign/collect: immutable artifact")
	certPath := f.String("certificate", "", "verify: settlement certificate")
	certText := f.String("certificate-id", "", "verify: independently retained certificate ID")
	if err := parsePruneFlags(f, args); err != nil {
		return err
	}
	present := custodyCommandPresence(f)
	var forbidden []string
	switch *mode {
	case "review":
		forbidden = []string{"key", "expected-review-id", "fence-network", "controller-key", "fence-transport-key", "fence-timeout", "out", "certificate", "certificate-id"}
	case "sign":
		forbidden = []string{"fence-network", "controller-key", "fence-transport-key", "fence-timeout", "certificate", "certificate-id"}
	case "collect":
		forbidden = []string{"role", "key", "expected-review-id", "certificate", "certificate-id"}
	case "verify":
		forbidden = []string{"role", "key", "expected-review-id", "fence-network", "controller-key", "fence-transport-key", "fence-timeout", "out"}
	default:
		return prunefence.ErrFence
	}
	if err := custodyCommandForbid(present, forbidden...); err != nil {
		return err
	}
	pid, err := pruneExternalID("plan-id", *planText)
	if err != nil {
		return err
	}
	plan, err := store.LoadScheduledPrunePlan(*planPath, pid)
	if err != nil {
		return err
	}
	iid, err := pruneExternalID("inventory-id", *inventoryText)
	if err != nil {
		return err
	}
	inventory, err := store.LoadScheduledPruneInventory(*inventoryPath, iid)
	if err != nil {
		return err
	}
	proposalID, err := pruneExternalID("proposal-id", *proposalText)
	if err != nil {
		return err
	}
	raw, err := readRegularArtifact(*proposalPath, prunefence.MaximumSettlementProposalBytes)
	if err != nil {
		return err
	}
	proposal, err := prunefence.DecodeSettlementProposal(raw)
	if err != nil {
		return err
	}
	actual, _ := proposal.ID()
	if actual != proposalID {
		return prunefence.ErrFence
	}
	if err := store.VerifyScheduledPruneSettlementProposal(plan, inventory, proposal); err != nil {
		return err
	}
	c := proposal.Claim.Candidate
	scope, err := c.Policy.SettlementScope(c.Binding.AssignmentID, c.Binding.RequestID)
	if err != nil {
		return err
	}
	sid, _ := scope.ID()
	report := struct {
		ProposalID          string `json:"proposal_id"`
		ScopeID             string `json:"scope_id"`
		ReviewID            string `json:"review_id,omitempty"`
		CertificateID       string `json:"certificate_id,omitempty"`
		ProposalSigned      bool   `json:"proposal_signed"`
		CertificateVerified bool   `json:"certificate_verified"`
		ExecutionAuthorized bool   `json:"execution_authorized"`
		AccountingChanged   bool   `json:"accounting_changed"`
	}{ProposalID: actual.String(), ScopeID: sid.String(), ProposalSigned: proposal.Verify() == nil}
	var review types.Hash
	if *role != "" || *mode == "sign" {
		review, err = proposal.ReviewID(*role)
		if err != nil {
			return err
		}
		report.ReviewID = review.String()
	}
	inputs := []string{*planPath, *inventoryPath, *proposalPath, *keyPath, *network, *controller, *transport}
	if *mode == "sign" || *mode == "collect" {
		if err := scheduledOperatorOutput(*dest, inputs, nil); err != nil {
			return err
		}
	}
	verify := func(raw []byte) error {
		certificate, err := prunefence.DecodeSettlement(raw)
		if err != nil {
			return err
		}
		id, _ := certificate.Proposal.ID()
		if id != proposalID {
			return prunefence.ErrFence
		}
		cid, _ := certificate.ID()
		report.CertificateID = cid.String()
		report.CertificateVerified = true
		return nil
	}
	switch *mode {
	case "sign":
		want, err := pruneExternalID("expected-review-id", *expected)
		if err != nil || want != review {
			return prunefence.ErrFence
		}
		key, err := loadPruneOfflineKey(*keyPath)
		if err != nil {
			return err
		}
		defer clear(key)
		signed, err := proposal.Sign(*role, want, key)
		if err != nil {
			return err
		}
		raw, err := signed.CanonicalBytes()
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publishImmutableArtifact(*dest, raw); err != nil {
			return err
		}
		id, _ := signed.ID()
		report.ProposalID = id.String()
		report.ProposalSigned = signed.Verify() == nil
	case "collect":
		if err := proposal.Verify(); err != nil {
			return err
		}
		raw, err := readRegularArtifact(*dest, prunefence.MaximumSettlementBytes)
		if err == nil {
			if err := verify(raw); err != nil {
				return err
			}
		} else {
			if !os.IsNotExist(err) {
				return err
			}
			client, err := openPruneFenceNetwork(ctx, scope, c.Policy.Controller, *network, *controller, *transport, *timeout)
			if err != nil {
				return err
			}
			defer client.close()
			certificate, err := prunenet.CollectSettlement(ctx, client.host, client.key, client.local, client.endpoints, client.timeout, proposal)
			if err != nil {
				return err
			}
			raw, err = certificate.CanonicalBytes()
			if err != nil {
				return err
			}
			if err := verify(raw); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := publishCustodyCommandArtifact(*dest, raw); err != nil {
				return err
			}
		}
	case "verify":
		cid, err := pruneExternalID("certificate-id", *certText)
		if err != nil {
			return err
		}
		raw, err := readRegularArtifact(*certPath, prunefence.MaximumSettlementBytes)
		if err != nil {
			return err
		}
		if err := verify(raw); err != nil {
			return err
		}
		if report.CertificateID != cid.String() {
			return prunefence.ErrFence
		}
	}
	return scheduledOperatorReport(ctx, out, report)
}
