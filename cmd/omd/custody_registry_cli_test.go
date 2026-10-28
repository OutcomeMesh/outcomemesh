package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	reg "github.com/outcomemesh/outcomemesh/node/custodyregistry"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

type registryCLIFixture struct {
	dir, draft, origin, candidate string
	g                             reg.Genesis
	initial                       v2.AdmissionGenesis
	keys                          map[byte]string
	members                       []byte
}

func newRegistryCLIFixture(t testing.TB) registryCLIFixture {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join("..", "..", "node", "custodyv2", "testdata", "public-fixture", "context"))
	if e != nil {
		t.Fatal(e)
	}
	c, e := v2.DecodeContext(raw)
	if e != nil {
		t.Fatal(e)
	}
	c.Assignment.Policy.Version = v2.PolicyVersionAdmission
	aid, _ := c.Assignment.ID()
	c.Plan.AssignmentID, c.Plan.Intent.AssignmentID = aid, aid
	c.Plan.AuditSignature, c.Plan.ServeSignature, c.Plan.AuthoritySignature = [64]byte{}, [64]byte{}, [64]byte{}
	for _, role := range []string{"audit", "serve", "authority"} {
		seed := byte(4)
		if role == "authority" {
			seed = 1
		}
		c.Plan, e = c.Plan.Sign(role, f.Key(seed))
		if e != nil {
			t.Fatal(e)
		}
	}
	initial, e := v2.NewAdmissionGenesis(c)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	z := registryCLIFixture{dir: dir, draft: filepath.Join(dir, "draft.json"), origin: filepath.Join(dir, "registry"), candidate: filepath.Join(dir, "candidate"), initial: initial, keys: map[byte]string{}, members: []byte{111, 112, 113, 114}}
	z.g = reg.Genesis{Version: reg.Version1, NetworkID: c.Assignment.Base.NetworkID, ChainGenesisID: c.Assignment.Base.GenesisID, ResourceID: f.Hash("independently-pinned-cli-registry-anchor"), Issuer: f.Public(110), Threshold: 3, MaximumOperations: 32, MaximumPending: 8}
	sort.Slice(z.members, func(i, j int) bool {
		a, b := f.Public(z.members[i]), f.Public(z.members[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	for _, seed := range z.members {
		z.g.Witnesses = append(z.g.Witnesses, f.Public(seed))
	}
	raw, _ = json.Marshal(z.g)
	writePruneCLIFile(t, z.draft, raw)
	raw, _ = initial.CanonicalBytes()
	writePruneCLIFile(t, z.candidate, raw)
	for _, seed := range []byte{1, 14, 110, 111, 112, 113, 114} {
		path := filepath.Join(dir, "key-"+strconv.Itoa(int(seed)))
		writePruneCLIFile(t, path, f.Key(seed).Seed())
		z.keys[seed] = path
	}
	return z
}

func registryInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if e := runCustodyRegistry(t.Context(), args, &out); e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}
func registryReviewed(t testing.TB, driver v2CLIDriver, args []string) []string {
	t.Helper()
	r := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
	if r["keys_loaded"] != "false" || r["owners_opened"] != "false" || r["selection_only"] != "true" || r["execution_granted"] != "false" || r["legacy_cutover"] != "false" {
		t.Fatal(r)
	}
	return append(append([]string{}, args...), "--mode", "run", "--expected-review-id", r["review_id"])
}
func (z registryCLIFixture) args(action string, extra ...string) []string {
	a := []string{custodyRegistryCommand, "--action", action}
	if action != "genesis" {
		gid, _ := z.g.ID()
		did, _ := z.g.DescriptorID()
		a = append(a, "--registry", z.origin, "--registry-id", gid.String(), "--registry-descriptor-id", did.String())
	}
	return append(a, extra...)
}
func (z registryCLIFixture) artifact(t testing.TB, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return custodyRegistryArtifactID(b).String()
}
func (z registryCLIFixture) memberArgs(seed byte, sequence uint64, head, pending types.Hash) []string {
	return []string{"--root", filepath.Join(z.dir, "witness-"+strconv.Itoa(int(seed))), "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", z.keys[seed], "--sequence", strconv.FormatUint(sequence, 10), "--head-id", head.String(), "--pending-id", pending.String()}
}

func runRegistryCLICampaign(t *testing.T, driver v2CLIDriver) {
	t.Helper()
	z := newRegistryCLIFixture(t)
	run := func(args []string) { driver(t, registryReviewed(t, driver, args)) }
	run(z.args("genesis", "--draft", z.draft, "--out", z.origin))
	gid, _ := z.g.ID()
	did, _ := z.g.DescriptorID()
	raw, _ := os.ReadFile(z.origin)
	g, e := reg.DecodeGenesis(raw)
	if e != nil {
		t.Fatal(e)
	}
	actual, _ := g.DescriptorID()
	if actual != did {
		t.Fatal("registry preparation changed descriptor")
	}
	initialID, _ := z.initial.ID()
	initialDescriptor, _ := z.initial.DescriptorID()
	selection := filepath.Join(z.dir, "selection-unsigned")
	run(z.args("selection", "--candidate", z.candidate, "--candidate-id", initialID.String(), "--candidate-descriptor-id", initialDescriptor.String(), "--out", selection))
	for _, role := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		next := filepath.Join(z.dir, "selection-"+role.name)
		run(z.args("sign-selection", "--in", selection, "--in-id", z.artifact(t, selection), "--sign-role", role.name, "--sign-key", z.keys[role.seed], "--out", next))
		selection = next
	}
	raw, _ = os.ReadFile(selection)
	s, e := reg.DecodeSelection(raw)
	if e != nil || s.Verify(g) != nil {
		t.Fatal("invalid completed selection", e)
	}
	sid, _ := s.ID()
	var paths, pins []string
	for _, seed := range z.members {
		common := z.memberArgs(seed, 0, gid, types.Hash{})
		base := filepath.Join(z.dir, "member-"+strconv.Itoa(int(seed)))
		run(z.args("witness-create", append(append([]string{}, common...), "--out", base+"-created")...))
		args := z.args("witness-vote", append(append([]string{}, common...), "--in", selection, "--in-id", z.artifact(t, selection), "--out", base+"-vote")...)
		run(args)
		args[len(args)-1] = base + "-vote-recovered"
		run(args)
		one, _ := os.ReadFile(base + "-vote")
		two, _ := os.ReadFile(base + "-vote-recovered")
		if !bytes.Equal(one, two) {
			t.Fatal("cold vote recovery changed signature")
		}
		vote, e := reg.DecodeVote(two)
		if e != nil || vote.SelectionID != sid || vote.Verify(g) != nil {
			t.Fatal("vote selected another assignment", e)
		}
		paths = append(paths, base+"-vote-recovered")
		pins = append(pins, z.artifact(t, base+"-vote-recovered"))
	}
	certificate := filepath.Join(z.dir, "certificate")
	run(z.args("certificate", "--in", selection, "--in-id", z.artifact(t, selection), "--votes", strings.Join(paths[:3], ","), "--vote-ids", strings.Join(pins[:3], ","), "--out", certificate))
	raw, _ = os.ReadFile(certificate)
	q, e := reg.DecodeCertificate(raw)
	if e != nil || q.Verify(g) != nil {
		t.Fatal("CLI produced invalid quorum", e)
	}
	for _, seed := range z.members {
		common := z.memberArgs(seed, 0, gid, sid)
		base := filepath.Join(z.dir, "member-"+strconv.Itoa(int(seed)))
		args := z.args("witness-commit", append(append([]string{}, common...), "--in", certificate, "--in-id", z.artifact(t, certificate), "--out", base+"-committed")...)
		run(args)
		args[len(args)-1] = base + "-commit-recovered"
		run(args)
		one, _ := os.ReadFile(base + "-committed")
		two, _ := os.ReadFile(base + "-commit-recovered")
		if !bytes.Equal(one, two) {
			t.Fatal("cold commit recovery changed final snapshot")
		}
		status := base + "-status"
		run(z.args("witness-status", append(z.memberArgs(seed, 1, sid, types.Hash{}), "--out", status)...))
		b, _ := os.ReadFile(status)
		var x struct {
			Snapshot                                       reg.Snapshot
			Pin                                            custodyfence.WitnessPin
			SelectionOnly, ExecutionGranted, LegacyCutover bool
		}
		if e := json.Unmarshal(b, &x); e != nil || !x.SelectionOnly || x.ExecutionGranted || x.LegacyCutover || !x.Snapshot.SelectionFinal || x.Pin.Position.Sequence != 1 || x.Pin.Position.HeadID != sid || !x.Pin.PendingID.IsZero() || x.Snapshot.SelectedGenesisID != initialID || x.Snapshot.SelectedDescriptorID != initialDescriptor {
			t.Fatal("wrong final registry state", x, e)
		}
	}
	// A completed registry is not an admission prefix or execution permission.
	if _, e := v2.DecodeAdmissionBinding(raw); e == nil {
		t.Fatal("registry certificate reinterpreted as admission binding")
	}
}

func TestCustodyRegistryCLISelectionAndColdRecovery(t *testing.T) {
	runRegistryCLICampaign(t, registryInProcess)
}

func TestCustodyRegistryCLIReviewAndOutputLoss(t *testing.T) {
	z := newRegistryCLIFixture(t)
	args := z.args("genesis", "--draft", z.draft, "--out", z.origin)
	run := registryReviewed(t, registryInProcess, args)
	if _, e := os.Lstat(z.origin); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("review wrote registry", e)
	}
	changed := append([]string{}, run...)
	changed[len(args)-1] += "-changed"
	if e := runCustodyRegistry(t.Context(), changed, io.Discard); e == nil || !strings.Contains(e.Error(), "exact public review") {
		t.Fatal("changed output reused review", e)
	}
	for _, extra := range [][]string{{"--now", "1"}, {"--action", "genesis"}, {"--root", z.dir}, {"--sign-key", z.keys[110]}} {
		if e := runCustodyRegistry(t.Context(), append(append([]string{}, args...), extra...), io.Discard); e == nil {
			t.Fatal("duplicate/unused selector accepted", extra)
		}
	}
	if e := runCustodyRegistry(t.Context(), run, serveBrokenWriter{}); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("lost output not propagated", e)
	}
	if _, e := os.ReadFile(z.origin); e != nil {
		t.Fatal("genesis lost after stdout failure", e)
	}
	gid, _ := z.g.ID()
	member := z.members[0]
	common := z.memberArgs(member, 0, gid, types.Hash{})
	if e := os.WriteFile(z.keys[member], []byte("invalid private seed"), 0600); e != nil {
		t.Fatal(e)
	}
	args = z.args("witness-create", append(common, "--out", filepath.Join(z.dir, "created"))...)
	registryReviewed(t, registryInProcess, args) // no seed parsing, owner or journal
	if e := runCustodyRegistry(t.Context(), registryReviewed(t, registryInProcess, args), io.Discard); e == nil {
		t.Fatal("run accepted invalid witness seed")
	}
	for _, flag := range []string{"--sequence", "--head-id", "--pending-id", "--registry-descriptor-id"} {
		bad := append([]string{}, args...)
		for i := range bad {
			if bad[i] == flag {
				bad = append(bad[:i], bad[i+2:]...)
				break
			}
		}
		if e := runCustodyRegistry(t.Context(), bad, io.Discard); e == nil {
			t.Fatal("missing independent pin accepted", flag)
		}
	}
}
