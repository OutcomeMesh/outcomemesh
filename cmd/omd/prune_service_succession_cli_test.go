//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	fencefixture "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	"github.com/outcomemesh/outcomemesh/node/custodyguard"
	"github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
	"github.com/outcomemesh/outcomemesh/node/prunefence"
	service "github.com/outcomemesh/outcomemesh/node/pruneservice"
	wire "github.com/outcomemesh/outcomemesh/node/pruneservice/servicewire"
)

func preparePruneServiceReplacement(t *testing.T) (*pruneServiceOwnerCLIFixture, guardwire.ReplacementReceipt) {
	t.Helper()
	config := custodyguard.Config{Limit: 16, Revoker: fencefixture.Public(201), Replacer: fencefixture.Public(202)}
	f := preparePruneServiceOwnerWithGuard(t, config)
	id := f.guard.Identity().ID()
	revoke, err := (guardwire.Revocation{GuardID: id, Subject: f.identity.Service, Authority: config.Revoker, ReasonID: fencefixture.Hash("replace service")}).Sign(fencefixture.Key(201))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.guard.Revoke(t.Context(), revoke)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.guard.Position()
	if err != nil {
		t.Fatal(err)
	}
	rid, err := revoke.ID()
	if err != nil {
		t.Fatal(err)
	}
	replacement := guardwire.Replacement{GuardID: id, Subject: f.identity.Service, Successor: fencefixture.Public(203), Authority: config.Replacer, RevocationID: rid, EvidenceID: fencefixture.Hash("retained original obligations"), Before: before}
	replacement, err = replacement.Accept(fencefixture.Key(203))
	if err != nil {
		t.Fatal(err)
	}
	replacement, err = replacement.Authorize(fencefixture.Key(202))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.guard.Replace(t.Context(), replacement)
	if err != nil {
		t.Fatal(err)
	}
	return f, receipt
}

func pruneSuccessorCLIArgs(t *testing.T, f *pruneServiceOwnerCLIFixture, receipt guardwire.ReplacementReceipt) []string {
	t.Helper()
	dir := t.TempDir()
	receiptPath, approvalPath := filepath.Join(dir, "replacement"), filepath.Join(dir, "succession")
	raw, err := receipt.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, receiptPath, raw)
	did, err := f.descriptor.ID()
	if err != nil {
		t.Fatal(err)
	}
	base := []string{pruneServiceCommand, "--descriptor", f.descriptorPath, "--descriptor-id", did.String()}
	issuer := filepath.Join(dir, "issuer.seed")
	authorize := append(append([]string{}, base...), "--action", "successor-authorize", "--replacement", receiptPath, "--replacement-id", cutoverArtifactID(raw).String(), "--key", issuer, "--out", approvalPath)
	authReview := pruneServiceCLIReview(t, authorize)
	run := func(args []string, review string) error {
		return runPruneServiceCLIContext(t.Context(), append(append([]string{}, args...), "--mode", "run", "--expected-review-id", review), io.Discard)
	}
	badID := fencefixture.Hash("wrong ID").String()
	if err = runPruneServiceCLIContext(t.Context(), replaceRemoteCLIFlag(authorize, "--replacement-id", badID), io.Discard); err == nil {
		t.Fatal("foreign receipt ID accepted")
	}
	writePruneCLIFile(t, issuer, fencefixture.Key(203).Seed())
	if err = run(authorize, authReview); err == nil {
		t.Fatal("successor self-authorized")
	}
	writePruneCLIFile(t, issuer, fencefixture.Key(109).Seed())
	if err = run(authorize, badID); err == nil {
		t.Fatal("wrong authorization review accepted")
	}
	if _, err = os.Lstat(approvalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("authorization leaked output on refusal", err)
	}
	approvalID := pruneServiceCLIRun(t, authorize)
	signed, err := prunefence.DecodeServiceSuccession(pruneServiceCLIRead(t, approvalPath), f.descriptor.Policy, f.descriptor.Binding)
	if err != nil || signed.Replacement != receipt {
		t.Fatal("invalid issuer authorization", err)
	}
	id, err := signed.ID(f.descriptor.Policy, f.descriptor.Binding)
	if err != nil || id.String() != approvalID {
		t.Fatal("wrong canonical approval ID", err)
	}
	if err = os.Remove(issuer); err != nil {
		t.Fatal(err)
	}
	if got := pruneServiceCLIRun(t, authorize); got != approvalID {
		t.Fatal("retry changed authorization")
	}
	cursor := filepath.Join(dir, "initial.json")
	pruneServiceCLIJSON(t, cursor, wire.Position{})
	successor := filepath.Join(dir, "successor.seed")
	activate := append(append([]string{}, base...), "--action", "successor-activate", "--root", f.root, "--position", cursor, "--succession", approvalPath, "--succession-id", approvalID, "--key", successor, "--out", filepath.Join(dir, "report"))
	activationReview := pruneServiceCLIReview(t, activate)
	if err = runPruneServiceCLIContext(t.Context(), replaceRemoteCLIFlag(activate, "--succession-id", badID), io.Discard); err == nil {
		t.Fatal("foreign approval ID accepted")
	}
	writePruneCLIFile(t, successor, fencefixture.Key(109).Seed())
	if err = run(activate, activationReview); err == nil {
		t.Fatal("issuer cannot install its key as successor")
	}
	writePruneCLIFile(t, successor, fencefixture.Key(203).Seed())
	return activate
}

func TestPruneServiceSuccessorCLIRetainsAdmissionAndExecutesOnce(t *testing.T) {
	f, receipt := preparePruneServiceReplacement(t)
	before := pruneFailureAuthorities(t, f)
	initial := pruneFailureSnapshot(t, f)
	activate := pruneSuccessorCLIArgs(t, f, receipt)
	initialGuard, err := f.guard.Position()
	if err != nil {
		t.Fatal(err)
	}
	writePruneCLIFile(t, activate[len(activate)-1], []byte("other report"))
	run := func(args []string, w io.Writer) error {
		review := pruneServiceCLIReview(t, args)
		return runPruneServiceCLIContext(t.Context(), append(append([]string{}, args...), "--mode", "run", "--expected-review-id", review), w)
	}
	if err = run(activate, io.Discard); err == nil {
		t.Fatal("conflicting output allowed key installation")
	}
	if _, err = os.Lstat(filepath.Join(f.root, "signer-succession")); !os.IsNotExist(err) {
		t.Fatal("signer installed after refusal", err)
	}
	if err = os.Remove(activate[len(activate)-1]); err != nil {
		t.Fatal(err)
	}
	fail := pruneEffectTestWriter(func([]byte) (int, error) { return 0, io.ErrClosedPipe })
	if err = run(activate, fail); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("lost console result", err)
	}
	originalReport := pruneServiceCLIRead(t, activate[len(activate)-1])
	pruneServiceCLIRun(t, activate)
	if !bytes.Equal(originalReport, pruneServiceCLIRead(t, activate[len(activate)-1])) {
		t.Fatal("changed exact activation report")
	}
	if !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) || !reflect.DeepEqual(initial, pruneFailureSnapshot(t, f)) {
		t.Fatal("activation modified admitted work")
	}
	afterGuard, err := f.guard.Position()
	if err != nil || afterGuard != initialGuard {
		t.Fatal("activation consumed an execution slot", err)
	}
	o := f.open(t, wire.Position{}, nil)
	calls := 0
	r, err := o.Execute(t.Context(), f.request, func(ctx context.Context, ch wire.Challenge) (custodyfence.Command, error) {
		calls++
		return approvePruneServiceChallenge(ctx, f.descriptor, f.request, ch, f.consumerPath, filepath.Join(f.public, "successor.challenge"), filepath.Join(f.public, "successor.approval"))
	})
	if err != nil || calls != 1 || r.Result == nil || r.Effect.Report.RemovedNodes == 0 {
		t.Fatal("successor did not execute original admission once", calls, err)
	}
	if err = r.Verify(f.descriptor, f.request); err != nil {
		t.Fatal(err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) {
		t.Fatal("execution changed replica accounting")
	}
	if err = run(activate, io.Discard); err == nil {
		t.Fatal("stale initial cursor activated after execution")
	}
	if !bytes.Equal(originalReport, pruneServiceCLIRead(t, activate[len(activate)-1])) {
		t.Fatal("stale activation overwrote report")
	}
	f.stopNetwork()
	p, err := r.Position()
	if err != nil {
		t.Fatal(err)
	}
	o = f.open(t, p, &f.request)
	replayed, err := o.Execute(t.Context(), f.request, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected, _ := r.CanonicalBytes()
	got, _ := replayed.CanonicalBytes()
	if !bytes.Equal(expected, got) {
		t.Fatal("cold retry changed successor outcome")
	}
	// Public cached responses undergo the same role checks even when neither
	// private caller key is available and the relay cannot be contacted.
	cache := filepath.Join(f.public, "cached.response")
	writePruneCLIFile(t, cache, expected)
	did, _ := f.descriptor.ID()
	pub := func(k byte) string { return hex.EncodeToString(fencefixture.Key(k)[32:]) }
	cachedCall := []string{pruneServiceCommand, "--action", "remote-call",
		"--descriptor", f.descriptorPath, "--descriptor-id", did.String(), "--request", f.requestPath,
		"--address", "/ip4/127.0.0.1/udp/1/quic-v1", "--transport-key", filepath.Join(f.public, "missing-transport.seed"),
		"--transport-public-key", pub(190), "--relay-public-key", pub(191), "--key", filepath.Join(f.public, "missing-consumer.seed"),
		"--challenge-out", filepath.Join(f.public, "remote.challenge"), "--approval-out", filepath.Join(f.public, "remote.approval"), "--out", cache}
	pruneServiceCLIRun(t, cachedCall)
	for _, flag := range []string{"--transport-public-key", "--relay-public-key"} {
		for _, role := range [][32]byte{receipt.Request.Successor, receipt.Request.Authority, r.Result.Claim.Candidate.Session} {
			args := replaceRemoteCLIFlag(cachedCall, flag, hex.EncodeToString(role[:]))
			if err = run(args, io.Discard); err == nil {
				t.Fatal("cached remote call accepted a signing role as transport", flag)
			}
		}
	}
	if !bytes.Equal(expected, pruneServiceCLIRead(t, cache)) {
		t.Fatal("refusal changed cached evidence")
	}
}

func TestPruneServiceSuccessorCLIHeldIntentCannotActivate(t *testing.T) {
	f, receipt := preparePruneServiceReplacement(t)
	activate := pruneSuccessorCLIArgs(t, f, receipt)
	before := pruneFailureAuthorities(t, f)
	o, pos := pruneFailureExecute(t, f, "guard-unavailable")
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	held := pruneFailureSnapshot(t, f)
	review := pruneServiceCLIReview(t, activate)
	err := runPruneServiceCLIContext(t.Context(), append(activate, "--mode", "run", "--expected-review-id", review), io.Discard)
	if err == nil {
		t.Fatal("input cursor zero reset retained intent")
	}
	if _, err = os.Lstat(filepath.Join(f.root, "signer-succession")); !os.IsNotExist(err) {
		t.Fatal("successor installed over held intent", err)
	}
	o = f.open(t, pos, &f.request)
	if _, err = o.Execute(t.Context(), f.request, nil); !errors.Is(err, service.ErrHeld) {
		t.Fatal("cold original intent was released", err)
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(held, pruneFailureSnapshot(t, f)) || !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) {
		t.Fatal("refusal changed pending work")
	}
	if _, ok := pruneFailureEffect(t, f); ok {
		t.Fatal("refusal performed deletion")
	}
}

func TestPruneServiceSuccessorCLISeparatesOriginalRuntimePaths(t *testing.T) {
	f, receipt := preparePruneServiceReplacement(t)
	activate := pruneSuccessorCLIArgs(t, f, receipt)
	before := pruneFailureSnapshot(t, f)
	authorities := pruneFailureAuthorities(t, f)
	validReview := pruneServiceCLIReview(t, activate)
	requireRefusal := func(args []string) {
		t.Helper()
		for _, suffix := range [][]string{nil, {"--mode", "run", "--expected-review-id", validReview}} {
			var out bytes.Buffer
			full := append(append([]string{}, args...), suffix...)
			if err := runPruneServiceCLIContext(t.Context(), full, &out); !errors.Is(err, service.ErrOwner) || out.Len() != 0 {
				t.Fatalf("expected placement refusal before review or mutation, got %v, %q", err, out.String())
			}
		}
	}
	r := f.config.Runtime
	for _, placement := range append(pruneServiceRuntimeRoots(r), r.InventoryPath) {
		st, err := os.Stat(placement)
		if err != nil {
			t.Fatal(err)
		}
		target := placement
		if st.IsDir() {
			target = filepath.Join(placement, "activation-report")
		}
		requireRefusal(replaceRemoteCLIFlag(activate, "--out", target))
		if st.IsDir() {
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("report written into original runtime", err)
			}
		}
	}
	arg := func(flag string) string {
		for i, value := range activate {
			if value == flag {
				return activate[i+1]
			}
		}
		t.Fatal("missing fixture flag", flag)
		return ""
	}
	for _, flag := range []string{"--descriptor", "--position", "--succession", "--key"} {
		target := filepath.Join(r.ChainPath, "outside-artifact")
		writePruneCLIFile(t, target, pruneServiceCLIRead(t, arg(flag)))
		requireRefusal(replaceRemoteCLIFlag(activate, flag, target))
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(t.TempDir(), "public-looking-link")
	if err := os.Symlink(filepath.Dir(r.ChainPath), alias); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(alias, filepath.Base(r.ChainPath), "activation-report")
	requireRefusal(replaceRemoteCLIFlag(activate, "--out", target))
	linked := filepath.Join(t.TempDir(), "inventory-alias")
	if err := os.Link(r.InventoryPath, linked); err != nil {
		t.Fatal(err)
	}
	requireRefusal(replaceRemoteCLIFlag(activate, "--out", linked))
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(f.root, "transport-key"), linked); err != nil {
		t.Fatal(err)
	}
	requireRefusal(replaceRemoteCLIFlag(activate, "--key", linked))
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	untrusted := t.TempDir()
	if err := os.Chmod(untrusted, 0777); err != nil {
		t.Fatal(err)
	}
	requireRefusal(replaceRemoteCLIFlag(activate, "--out", filepath.Join(untrusted, "activation-report")))
	did, _ := f.descriptor.ID()
	signed, err := prunefence.DecodeServiceSuccession(pruneServiceCLIRead(t, arg("--succession")), f.descriptor.Policy, f.descriptor.Binding)
	if err != nil {
		t.Fatal(err)
	}
	// A caller bypassing the CLI's read-only preflight still reaches the
	// same check under the owner lock, before signer publication.
	if err = service.ActivateSuccessor(t.Context(), f.root, did, wire.Position{}, signed, fencefixture.Key(203), filepath.Join(r.ChainPath, "activation-report")); !errors.Is(err, service.ErrOwner) {
		t.Fatal("owner accepted protected report destination", err)
	}
	if _, err = os.Lstat(filepath.Join(f.root, "signer-succession")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("placement refusal installed a signer", err)
	}
	if !reflect.DeepEqual(before, pruneFailureSnapshot(t, f)) || !reflect.DeepEqual(authorities, pruneFailureAuthorities(t, f)) {
		t.Fatal("placement refusal changed original obligations")
	}
}

func TestPruneServiceSuccessorCLIRevokedSignerAndTornInstallation(t *testing.T) {
	f, receipt := preparePruneServiceReplacement(t)
	activate := pruneSuccessorCLIArgs(t, f, receipt)
	before := pruneFailureAuthorities(t, f)
	pruneServiceCLIRun(t, activate)
	revoke, err := (guardwire.Revocation{GuardID: f.guard.Identity().ID(), Subject: receipt.Request.Successor, Authority: fencefixture.Public(201), ReasonID: fencefixture.Hash("revoke installed successor")}).Sign(fencefixture.Key(201))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.guard.Revoke(t.Context(), revoke); err != nil {
		t.Fatal(err)
	}
	expected, err := f.guard.Position()
	if err != nil {
		t.Fatal(err)
	}
	o, p := pruneFailureExecute(t, f, "")
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := f.guard.Position()
	if err != nil || current != expected || f.fault.choices.Load() != 0 {
		t.Fatal("revoked signer advanced guard", err)
	}
	if _, ok := pruneFailureEffect(t, f); ok {
		t.Fatal("revoked successor deleted history")
	}
	if !reflect.DeepEqual(before, pruneFailureAuthorities(t, f)) {
		t.Fatal("revoked successor changed accounting")
	}
	record := filepath.Join(f.root, "signer-succession")
	if err = os.Truncate(record, 1); err != nil {
		t.Fatal(err)
	}
	did, _ := f.descriptor.ID()
	if owner, err := service.Open(t.Context(), f.root, did, p, &f.request); err == nil {
		owner.Close()
		t.Fatal("partial successor record fell back to original signer")
	}
	if got := pruneServiceCLIRead(t, record); len(got) != 1 {
		t.Fatal("partial record silently changed")
	}
}
