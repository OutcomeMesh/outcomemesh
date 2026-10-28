package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	ct "github.com/outcomemesh/outcomemesh/internal/carryovertest"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	reg "github.com/outcomemesh/outcomemesh/node/custodyregistry"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"github.com/outcomemesh/outcomemesh/node/transport"
	"github.com/outcomemesh/outcomemesh/node/workarchive"
)

func importCLIInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	var err error
	switch args[0] {
	case custodyCutoverCommand:
		err = runCustodyCutover(t.Context(), args, &out)
	case custodyRegistryCommand:
		err = runCustodyRegistry(t.Context(), args, &out)
	case custodyV2AdmissionCommand:
		err = runCustodyV2Admission(t.Context(), args, &out)
	default:
		t.Fatal(args[0])
	}
	if err != nil {
		t.Fatal(args, err)
	}
	return out.String()
}
func importCLIReviewed(t testing.TB, driver v2CLIDriver, args []string) []string {
	t.Helper()
	fields := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
	if fields["keys_loaded"] != "false" || (fields["owners_opened"] != "false" && fields["stores_opened"] != "false") || fields["execution_granted"] != "false" || fields["review_id"] == "" {
		t.Fatal(fields)
	}
	return append(append([]string{}, args...), "--mode", "run", "--expected-review-id", fields["review_id"])
}
func runImportedAccountingCLI(t *testing.T, driver v2CLIDriver) {
	t.Helper()
	dir := t.TempDir()
	p := ct.Proposal(t)
	rid, _ := p.Anchor.ID()
	rdid, _ := p.Anchor.DescriptorID()
	lid, _ := p.Evidence.Assignment.ID()
	pid, _ := p.ID()
	write := func(name string, raw []byte) string {
		path := filepath.Join(dir, name)
		writePruneCLIFile(t, path, raw)
		return path
	}
	artifact := func(path string, registry bool) string {
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if registry {
			return custodyRegistryArtifactID(raw).String()
		}
		return custodyV2ArtifactID(raw).String()
	}
	keys := map[byte]string{}
	for _, seed := range []byte{101, 102, 110, 111, 112, 113, 70, 71, 72} {
		keys[seed] = write("key-"+strconv.Itoa(int(seed)), f.Key(seed).Seed())
	}
	raw, _ := p.CanonicalBytes()
	proposal := write("proposal", raw)
	genesis := filepath.Join(dir, "imported-genesis")
	run := func(args []string) { driver(t, importCLIReviewed(t, driver, args)) }
	run([]string{custodyCutoverCommand, "--action", "import-genesis", "--proposal", proposal, "--proposal-id", pid.String(), "--anchor-id", rid.String(), "--descriptor-id", rdid.String(), "--legacy-id", lid.String(), "--retired-sequence", strconv.FormatUint(p.Evidence.End.Sequence, 10), "--retired-head", p.Evidence.End.HeadID.String(), "--out", genesis})
	raw, e := os.ReadFile(genesis)
	if e != nil {
		t.Fatal(e)
	}
	g, e := v2.DecodeAdmissionGenesis(raw)
	if e != nil {
		t.Fatal(e)
	}
	gid, _ := g.ID()
	gdid, _ := g.DescriptorID()
	raw, _ = p.Anchor.CanonicalBytes()
	registry := write("registry", raw)
	registryArgs := func(action string, extra ...string) []string {
		return append([]string{custodyRegistryCommand, "--action", action, "--registry", registry, "--registry-id", rid.String(), "--registry-descriptor-id", rdid.String()}, extra...)
	}
	selection := filepath.Join(dir, "selection")
	run(registryArgs("selection", "--candidate", genesis, "--candidate-id", gid.String(), "--candidate-descriptor-id", gdid.String(), "--out", selection))
	for _, role := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 101}, {"control", 102}} {
		next := filepath.Join(dir, "selection-"+role.name)
		run(registryArgs("sign-selection", "--in", selection, "--in-id", artifact(selection, true), "--sign-role", role.name, "--sign-key", keys[role.seed], "--out", next))
		selection = next
	}
	raw, _ = os.ReadFile(selection)
	s, e := reg.DecodeSelection(raw)
	if e != nil || s.Version != reg.SelectionVersionImported {
		t.Fatal(e)
	}
	sid, _ := s.ID()
	var votes, ids []string
	for _, seed := range []byte{111, 112, 113} {
		root := filepath.Join(dir, "registry-"+strconv.Itoa(int(seed)))
		common := []string{"--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", keys[seed], "--sequence", "0", "--head-id", rid.String(), "--pending-id", (types.Hash{}).String()}
		run(registryArgs("witness-create", append(append([]string{}, common...), "--out", root+"-created")...))
		vote := root + "-vote"
		run(registryArgs("witness-vote", append(append([]string{}, common...), "--in", selection, "--in-id", artifact(selection, true), "--out", vote)...))
		votes = append(votes, vote)
		ids = append(ids, artifact(vote, true))
	}
	// Registry CLI expects canonical witness order, not operator iteration order.
	sortImportVotes(t, votes, ids)
	cert := filepath.Join(dir, "selection-certificate")
	run(registryArgs("certificate", "--in", selection, "--in-id", artifact(selection, true), "--votes", strings.Join(votes, ","), "--vote-ids", strings.Join(ids, ","), "--out", cert))
	for _, seed := range []byte{111, 112, 113} {
		root := filepath.Join(dir, "registry-"+strconv.Itoa(int(seed)))
		run(registryArgs("witness-commit", "--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", keys[seed], "--sequence", "0", "--head-id", rid.String(), "--pending-id", sid.String(), "--in", cert, "--in-id", artifact(cert, true), "--out", root+"-committed"))
	}
	enrollment := filepath.Join(dir, "enrollment")
	run(registryArgs("import-enrollment", "--in", cert, "--in-id", artifact(cert, true), "--out", enrollment))
	adArgs := func(action string, extra ...string) []string {
		return append([]string{custodyV2AdmissionCommand, "--action", action, "--genesis", genesis, "--genesis-id", gid.String(), "--genesis-descriptor-id", gdid.String(), "--enrollment", enrollment, "--enrollment-id", artifact(enrollment, false)}, extra...)
	}
	run(adArgs("inspect-genesis", "--out", filepath.Join(dir, "initial-accounting.json")))
	checkImportedCLIStatus(t, filepath.Join(dir, "initial-accounting.json"), 2, 0)

	state, e := v2.NewAdmissionState(g, gid)
	if e != nil {
		t.Fatal(e)
	}
	initial := state.Snapshot()
	c := importCLIContext(t, g, initial)
	raw, _ = c.CanonicalBytes()
	contextPath := write("context", raw)
	cid, _ := c.ID()
	entry := filepath.Join(dir, "admit")
	run(adArgs("admit-entry", "--context", contextPath, "--context-id", cid.String(), "--sequence", "0", "--head-id", gid.String(), "--sign-key", keys[101], "--out", entry))
	raw, _ = os.ReadFile(entry)
	ae, e := v2.DecodeAdmissionEntry(raw)
	if e != nil {
		t.Fatal(e)
	}
	eid, _ := ae.ID()
	votes = nil
	ids = nil
	for _, seed := range []byte{70, 71, 72} {
		root := filepath.Join(dir, "admission-"+strconv.Itoa(int(seed)))
		common := []string{"--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", keys[seed], "--sequence", "0", "--head-id", gid.String(), "--pending-id", (types.Hash{}).String()}
		run(adArgs("witness-create", append(append([]string{}, common...), "--out", root+"-created")...))
		checkImportedCLIStatus(t, root+"-created", 2, 0)
		vote := root + "-vote"
		args := adArgs("witness-vote", append(append([]string{}, common...), "--in", entry, "--in-id", artifact(entry, false), "--out", vote)...)
		run(args)
		// Exact cold retry uses the old before-pin and cannot choose a different entry.
		repeat := vote + "-retry"
		run(replaceRemoteCLIFlag(args, "--out", repeat))
		one, _ := os.ReadFile(vote)
		two, _ := os.ReadFile(repeat)
		if !bytes.Equal(one, two) {
			t.Fatal("recovery changed vote")
		}
		votes = append(votes, vote)
		ids = append(ids, artifact(vote, false))
	}
	aq := filepath.Join(dir, "admission-certificate")
	run(adArgs("certificate", "--in", entry, "--in-id", artifact(entry, false), "--votes", strings.Join(votes, ","), "--vote-ids", strings.Join(ids, ","), "--out", aq))
	for _, seed := range []byte{70, 71, 72} {
		root := filepath.Join(dir, "admission-"+strconv.Itoa(int(seed)))
		common := []string{"--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", keys[seed]}
		run(adArgs("witness-commit", append(append([]string{}, common...), "--sequence", "0", "--head-id", gid.String(), "--pending-id", eid.String(), "--in", aq, "--in-id", artifact(aq, false), "--out", root+"-committed")...))
		checkImportedCLIStatus(t, root+"-committed", 4, 2)
		run(adArgs("witness-status", append(append([]string{}, common...), "--sequence", "1", "--head-id", eid.String(), "--pending-id", (types.Hash{}).String(), "--out", root+"-cold")...))
		checkImportedCLIStatus(t, root+"-cold", 4, 2)
	}
	raw, e = os.ReadFile(aq)
	if e != nil {
		t.Fatal(e)
	}
	q, e := v2.DecodeAdmissionCertificate(raw)
	if e != nil {
		t.Fatal(e)
	}
	history := v2.AdmissionBinding{Version: v2.Version2, Genesis: g, Chain: []v2.AdmissionCertificate{q}}
	raw, e = history.CanonicalBytes()
	if e != nil {
		t.Fatal(e)
	}
	historyPath := write("accounting-history", raw)
	run(adArgs("inspect-history", "--in", historyPath, "--in-id", artifact(historyPath, false), "--out", filepath.Join(dir, "historical-accounting.json")))
	checkImportedCLIStatus(t, filepath.Join(dir, "historical-accounting.json"), 4, 2)
	if destination := os.Getenv("OMESH_IMPORTED_PUBLIC_EXPORT"); destination != "" {
		if e := os.Mkdir(destination, 0700); e != nil {
			t.Fatal(e)
		}
		for name, path := range map[string]string{"proposal": proposal, "genesis": genesis, "registry": registry, "selection": selection, "selection-certificate": cert, "enrollment": enrollment, "context": contextPath, "admission-entry": entry, "admission-certificate": aq, "accounting-history": historyPath, "initial-accounting.json": filepath.Join(dir, "initial-accounting.json"), "historical-accounting.json": filepath.Join(dir, "historical-accounting.json")} {
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(destination, name), raw, 0600); e != nil {
				t.Fatal(e)
			}
		}
	}

}
func sortImportVotes(t testing.TB, paths, ids []string) {
	t.Helper()
	for i := 0; i < len(paths); i++ {
		for j := i + 1; j < len(paths); j++ {
			a, _ := os.ReadFile(paths[i])
			b, _ := os.ReadFile(paths[j])
			av, e := reg.DecodeVote(a)
			if e != nil {
				t.Fatal(e)
			}
			bv, e := reg.DecodeVote(b)
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Compare(av.Witness[:], bv.Witness[:]) > 0 {
				paths[i], paths[j] = paths[j], paths[i]
				ids[i], ids[j] = ids[j], ids[i]
			}
		}
	}
}
func checkImportedCLIStatus(t testing.TB, path string, spent uint32, pending uint16) {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var out struct {
		Snapshot         v2.AdmissionSnapshot
		Pin              custodyfence.WitnessPin
		ExecutionGranted bool
	}
	if e := json.Unmarshal(raw, &out); e != nil {
		t.Fatal(e)
	}
	if out.Snapshot.SpentOperations != spent || out.Snapshot.PendingOperations != pending || out.Snapshot.SourceSequence != 1 || out.ExecutionGranted {
		t.Fatal(out)
	}
}
func importCLIContext(t testing.TB, g v2.AdmissionGenesis, x v2.AdmissionSnapshot) v2.Context {
	t.Helper()
	ch, e := workarchive.CreateCustodyChallenge(g.Manifest, x.CurrentReceipt, f.Key(3), x.CurrentReceipt.StoredAt+1, 10, 1, x.CurrentReceipt.RetainUntil+1)
	if e != nil {
		t.Fatal(e)
	}
	intent := g.Import.Evidence.Cycles[0].Terminal.Intent
	aid, _ := g.Assignment.ID()
	intent.AssignmentID = aid
	intent.PriorSequence = x.SourceSequence
	intent.PriorHeadID = x.SourceHeadID
	intent.PriorReceiptID = x.SourceReceiptID
	intent.Nonce = ch.Nonce
	intent.IssuedAt = ch.IssuedAt
	intent.ExpiresAt = ch.ExpiresAt
	intent.RenewUntil = ch.RenewUntil
	intent.RequestedSamples = ch.RequestedSamples
	intent.ReplicaPeerID, e = transport.PeerIDFromPublicKey(g.Assignment.Base.RemoteTransportPublicKey[:])
	if e != nil {
		t.Fatal(e)
	}
	plan := v2.Plan{Version: v2.Version2, AssignmentID: aid, Intent: intent, Challenge: ch, ServeConsumer: f.Public(4), ClientTransportPublicKey: f.Public(46)}
	for _, r := range []struct {
		name string
		seed byte
	}{{"audit", 4}, {"serve", 4}, {"authority", 101}} {
		plan, e = plan.Sign(r.name, f.Key(r.seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	c := v2.Context{Assignment: g.Assignment, Plan: plan, Manifest: g.Manifest, Initial: g.Initial, Previous: x.CurrentReceipt, CustodyPolicy: g.CustodyPolicy}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	return c
}
func TestRemoteImportedAccountingCLI(t *testing.T) { runImportedAccountingCLI(t, importCLIInProcess) }
