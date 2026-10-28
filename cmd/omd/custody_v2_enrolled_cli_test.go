package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	reg "github.com/outcomemesh/outcomemesh/node/custodyregistry"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

// Both assignment selection and operation admission use durable witness CLI
// histories. Per-job execution endorsements remain public fixture signatures.
func newEnrolledCLIFixture(t testing.TB, driver v2CLIDriver) requiredCLIFixture {
	t.Helper()
	return newEnrolledCLIFixtureWithLifetime(t, driver, 60)
}
func newEnrolledCLIFixtureWithLifetime(t testing.TB, driver v2CLIDriver, lifetime uint64) requiredCLIFixture {
	t.Helper()
	var g reg.Genesis
	z := newRequiredCLIFixtureProfileAtLifetime(t, lifetime, func(c v2.Context) v2.Policy {
		g = reg.Genesis{Version: reg.Version2, NetworkID: c.Assignment.Base.NetworkID, ChainGenesisID: c.Assignment.Base.GenesisID, ResourceID: f.Hash("fresh-externally-enrolled-cli-resource"), Issuer: f.Public(110), Threshold: 3, MaximumOperations: 32, MaximumPending: 8}
		for seed := byte(111); seed <= 114; seed++ {
			g.Witnesses = append(g.Witnesses, f.Public(seed))
		}
		sort.Slice(g.Witnesses, func(i, j int) bool { return bytes.Compare(g.Witnesses[i][:], g.Witnesses[j][:]) < 0 })
		p := c.Assignment.Policy
		p.Version = v2.PolicyVersionEnrolled
		p.RegistryID, _ = g.ID()
		p.RegistryDescriptorID, _ = g.DescriptorID()
		return p
	}, driver)
	rdir := filepath.Join(z.dir, "registry-public")
	if e := os.Mkdir(rdir, 0700); e != nil {
		t.Fatal(e)
	}
	r := registryCLIFixture{dir: rdir, draft: filepath.Join(rdir, "draft"), origin: filepath.Join(rdir, "origin"), candidate: z.genesisPath, g: g, initial: z.binding.Genesis, keys: z.keys, members: []byte{111, 112, 113, 114}}
	sort.Slice(r.members, func(i, j int) bool {
		a, b := f.Public(r.members[i]), f.Public(r.members[j])
		return bytes.Compare(a[:], b[:]) < 0
	})
	for _, seed := range []byte{110, 111, 112, 113, 114} {
		path := filepath.Join(rdir, "key-"+strconv.Itoa(int(seed)))
		writePruneCLIFile(t, path, f.Key(seed).Seed())
		z.keys[seed] = path
	}
	raw, e := json.Marshal(g)
	if e != nil {
		t.Fatal(e)
	}
	writePruneCLIFile(t, r.draft, raw)
	run := func(a []string) { driver(t, registryReviewed(t, driver, a)) }
	run(r.args("genesis", "--draft", r.draft, "--out", r.origin))
	gid, _ := g.ID()
	iid, _ := z.binding.Genesis.ID()
	iidDesc, _ := z.binding.Genesis.DescriptorID()
	selection := filepath.Join(rdir, "selection")
	run(r.args("selection", "--candidate", z.genesisPath, "--candidate-id", iid.String(), "--candidate-descriptor-id", iidDesc.String(), "--out", selection))
	for _, role := range []struct {
		name string
		seed byte
	}{{"issuer", 110}, {"authority", 1}, {"control", 14}} {
		next := selection + "-" + role.name
		run(r.args("sign-selection", "--in", selection, "--in-id", r.artifact(t, selection), "--sign-role", role.name, "--sign-key", z.keys[role.seed], "--out", next))
		selection = next
	}
	raw, e = os.ReadFile(selection)
	if e != nil {
		t.Fatal(e)
	}
	s, e := reg.DecodeSelection(raw)
	if e != nil || s.Verify(g) != nil {
		t.Fatal("selected profile4", e)
	}
	sid, _ := s.ID()
	var votes, pins []string
	for _, seed := range r.members {
		common := r.memberArgs(seed, 0, gid, types.Hash{})
		path := filepath.Join(rdir, "vote-"+strconv.Itoa(int(seed)))
		run(r.args("witness-create", append(append([]string{}, common...), "--out", path+"-created")...))
		run(r.args("witness-vote", append(append([]string{}, common...), "--in", selection, "--in-id", r.artifact(t, selection), "--out", path)...))
		votes = append(votes, path)
		pins = append(pins, r.artifact(t, path))
	}
	qc := filepath.Join(rdir, "certificate")
	run(r.args("certificate", "--in", selection, "--in-id", r.artifact(t, selection), "--votes", strings.Join(votes[:3], ","), "--vote-ids", strings.Join(pins[:3], ","), "--out", qc))
	for _, seed := range r.members {
		common := r.memberArgs(seed, 0, gid, sid)
		out := filepath.Join(rdir, "committed-"+strconv.Itoa(int(seed)))
		a := r.args("witness-commit", append(common, "--in", qc, "--in-id", r.artifact(t, qc), "--out", out)...)
		run(a)
		a[len(a)-1] = out + "-cold"
		run(a)
		before, _ := os.ReadFile(out)
		after, _ := os.ReadFile(out + "-cold")
		if !bytes.Equal(before, after) {
			t.Fatal("registry cold commit changed")
		}
	}
	driver(t, requiredReviewed(t, driver, z.bindingArgs(t)))
	z.enrollmentPath = filepath.Join(z.dir, "enrollment")
	driver(t, requiredReviewed(t, driver, z.args("enrollment", "--registry", r.origin, "--registry-certificate", qc, "--registry-certificate-id", r.artifact(t, qc), "--out", z.enrollmentPath)))
	raw, e = os.ReadFile(z.enrollmentPath)
	if e != nil {
		t.Fatal(e)
	}
	z.enrollment, e = v2.DecodeEnrollmentBinding(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e := z.enrollment.Verify(z.c, z.binding); e != nil {
		t.Fatal(e)
	}
	return z
}
func TestCustodyV2EnrolledCLICompleteLifecycle(t *testing.T) {
	z := newEnrolledCLIFixture(t, requiredInProcess)
	runRequiredCLIFixtureCampaign(t, z, requiredInProcess, requiredInProcessStart)
}
func TestCustodyV2EnrolledCLIRefusesUnselectedOrMissingProof(t *testing.T) {
	z := newEnrolledCLIFixture(t, requiredInProcess)
	for _, kind := range []string{"missing", "corrupt", "profile3-command", "foreign-context"} {
		t.Run(kind, func(t *testing.T) {
			out := filepath.Join(z.dir, "refused-"+kind)
			args := z.args("create-target", "--root", out, "--journal", z.x.sources.Journal, "--objects", z.x.sources.Objects)
			switch kind {
			case "missing":
				for i := 0; i < len(args); i++ {
					if args[i] == "--enrollment" {
						args[i+1] = filepath.Join(z.dir, "absent")
					}
				}
			case "corrupt":
				raw, _ := os.ReadFile(z.enrollmentPath)
				raw[len(raw)-1] ^= 1
				path := filepath.Join(z.dir, "corrupt-proof")
				writePruneCLIFile(t, path, raw)
				for i := 0; i < len(args); i++ {
					if args[i] == "--enrollment" {
						args[i+1] = path
					}
				}
			case "profile3-command":
				args[0] = custodyV2RequiredCommand
			case "foreign-context":
				for i := 0; i < len(args); i++ {
					if args[i] == "--context-id" {
						args[i+1] = f.Hash("other-context").String()
					}
				}
			}
			var stdout bytes.Buffer
			if e := runCustodyV2Required(t.Context(), args, nil, &stdout); e == nil {
				t.Fatal("invalid enrollment reached review")
			}
			if _, e := os.Stat(out); !os.IsNotExist(e) {
				t.Fatal("refusal created owner", e)
			}
		})
	}
}
