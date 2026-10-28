package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/outcomemesh/outcomemesh/core/types"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

type serveCLIFixture struct {
	x      *custodyV2Fixture
	dir    string
	common []string
	keys   map[byte]string
}

func newServeCLIFixture(t testing.TB) serveCLIFixture {
	t.Helper()
	x := newCustodyV2Fixture(t)
	dir := t.TempDir()
	raw, _ := x.context.CanonicalBytes()
	writePruneCLIFile(t, filepath.Join(dir, "context"), raw)
	cid, _ := x.context.ID()
	scope, _ := x.context.ServeScope()
	sid, _ := scope.ID()
	z := serveCLIFixture{x: x, dir: dir, common: []string{"--context", filepath.Join(dir, "context"), "--context-id", cid.String(), "--scope-id", x.pin.String(), "--serve-scope-id", sid.String()}, keys: map[byte]string{}}
	for _, seed := range []byte{1, 4, 14, 61, 70, 71, 72} {
		p := filepath.Join(dir, "key-"+strconv.Itoa(int(seed)))
		writePruneCLIFile(t, p, f.Key(seed).Seed())
		z.keys[seed] = p
	}
	return z
}
func (z serveCLIFixture) args(action string, extra ...string) []string {
	return append(append([]string{custodyV2ServeCommand, "--action", action}, z.common...), extra...)
}
func serveInProcess(t testing.TB, args []string) string {
	t.Helper()
	var out bytes.Buffer
	if e := runCustodyV2Serve(t.Context(), args, &out); e != nil {
		t.Fatal(args, e)
	}
	return out.String()
}
func runServeCLICampaign(t *testing.T, driver v2CLIDriver) {
	t.Helper()
	for _, fulfilled := range []bool{false, true} {
		t.Run(strconv.FormatBool(fulfilled), func(t *testing.T) {
			z := newServeCLIFixture(t)
			x := z.x
			run := func(args []string) {
				t.Helper()
				review := pruneCLIFields(strings.SplitN(driver(t, args), "\n", 2)[0])
				if review["keys_loaded"] != "false" || review["owners_opened"] != "false" {
					t.Fatal(review)
				}
				driver(t, append(args, "--mode", "run", "--expected-review-id", review["review_id"]))
			}
			pin := func(path string) string {
				t.Helper()
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				return custodyV2ArtifactID(b).String()
			}
			draft := filepath.Join(z.dir, "proposal-draft")
			if fulfilled {
				target := x.open(t)
				bundle, _ := x.bundle(t, target)
				_ = target.Close()
				a, e := v2.OpenAcceptor(x.acceptor, x.context, x.pin, x.legacy.base.config.Audit.JournalPath, f.Key(1))
				if e != nil {
					t.Fatal(e)
				}
				receipt, e := a.Accept(t.Context(), bundle, x.context.Plan.Challenge.IssuedAt)
				if e != nil {
					t.Fatal(e)
				}
				_ = a.Close()
				b, _ := bundle.CanonicalBytes()
				r, _ := receipt.CanonicalBytes()
				bp, rp := filepath.Join(z.dir, "bundle"), filepath.Join(z.dir, "accepted")
				writePruneCLIFile(t, bp, b)
				writePruneCLIFile(t, rp, r)
				run(z.args("proposal-fulfilled", "--in", bp, "--in-id", pin(bp), "--proof", rp, "--proof-id", pin(rp), "--out", draft))
			} else {
				cmdPath := filepath.Join(z.dir, "unclaimed-command")
				run(z.args("unclaimed-command", "--evidence-id", f.Hash("cancel").String(), "--sign-key", z.keys[1], "--out", cmdPath))
				raw, _ := os.ReadFile(cmdPath)
				cmd, e := custodyfence.DecodeCommand(raw)
				if e != nil {
					t.Fatal(e)
				}
				q := f.Certificate(cmd, 70, 71, 72)
				b, _ := q.CanonicalBytes()
				qp := filepath.Join(z.dir, "unclaimed-qc")
				writePruneCLIFile(t, qp, b)
				run(z.args("proposal-unclaimed", "--in", qp, "--in-id", pin(qp), "--out", draft))
			}
			for _, role := range []string{"authority", "consumer"} {
				seed := byte(1)
				if role == "consumer" {
					seed = 4
				}
				next := filepath.Join(z.dir, "proposal-"+role)
				run(z.args("sign-proposal", "--in", draft, "--in-id", pin(draft), "--sign-role", role, "--sign-key", z.keys[seed], "--out", next))
				draft = next
			}
			decision := filepath.Join(z.dir, "decision")
			run(z.args("decision", "--in", draft, "--in-id", pin(draft), "--sign-key", z.keys[1], "--out", decision))
			scope, _ := x.context.ServeScope()
			sid, _ := scope.ID()
			var votePaths, votePins []string
			for i := 0; i < 3; i++ {
				seed := byte(70 + i)
				root := filepath.Join(z.dir, "witness-"+strconv.Itoa(i))
				common := []string{"--root", root, "--witness", types.Hash(f.Public(seed)).String(), "--sign-key", z.keys[seed]}
				run(z.args("witness-create", append(common, "--out", root+"-created")...))
				vp := root + "-vote"
				extra := append(append([]string{}, common...), "--in", draft, "--in-id", pin(draft), "--proof", decision, "--proof-id", pin(decision), "--sequence", "0", "--head-id", sid.String(), "--pending-id", types.Hash{}.String(), "--out", vp)
				run(z.args("witness-vote", extra...))
				extra[len(extra)-1] = vp + "-retry"
				run(z.args("witness-vote", extra...))
				a, _ := os.ReadFile(vp)
				b, _ := os.ReadFile(vp + "-retry")
				if !bytes.Equal(a, b) {
					t.Fatal("cold retry changed vote")
				}
				votePaths = append(votePaths, vp)
				votePins = append(votePins, pin(vp))
			}
			cp := filepath.Join(z.dir, "serve-certificate")
			run(z.args("certificate", "--in", draft, "--in-id", pin(draft), "--proof", decision, "--proof-id", pin(decision), "--votes", strings.Join(votePaths, ","), "--vote-ids", strings.Join(votePins, ","), "--out", cp))
			raw, _ := os.ReadFile(cp)
			cert, e := v2.DecodeServeCertificate(raw)
			if e != nil || cert.Verify(x.context) != nil {
				t.Fatal("CLI produced invalid certificate", e)
			}
			decisionID, _ := cert.Decision.Command.ID()
			for i := 0; i < 3; i++ {
				root := filepath.Join(z.dir, "witness-"+strconv.Itoa(i))
				extra := []string{"--root", root, "--witness", types.Hash(f.Public(byte(70 + i))).String(), "--sign-key", z.keys[byte(70+i)], "--in", cp, "--in-id", pin(cp), "--sequence", "0", "--head-id", sid.String(), "--pending-id", decisionID.String(), "--out", root + "-committed"}
				run(z.args("witness-commit", extra...))
				extra[len(extra)-1] = root + "-commit-recovered"
				run(z.args("witness-commit", extra...))
			}
			ap, bp := filepath.Join(z.dir, "a-applied"), filepath.Join(z.dir, "b-applied")
			aargs := []string{"--root", x.acceptor, "--journal", x.legacy.base.config.Audit.JournalPath, "--sign-key", z.keys[1]}
			bargs := []string{"--root", x.target, "--journal", x.sources.Journal, "--objects", x.sources.Objects, "--sign-key", z.keys[14], "--replica-key", z.keys[61]}
			run(z.args("apply-a", append(append([]string{}, aargs...), "--in", cp, "--in-id", pin(cp), "--out", ap)...))
			run(z.args("apply-b", append(append([]string{}, bargs...), "--in", cp, "--in-id", pin(cp), "--proof", ap, "--proof-id", pin(ap), "--out", bp)...))
			run(z.args("resume-a", append(append([]string{}, aargs...), "--in", cp, "--in-id", pin(cp), "--out", ap+"-recovered")...))
			old, _ := os.ReadFile(ap)
			recovered, _ := os.ReadFile(ap + "-recovered")
			if !bytes.Equal(old, recovered) {
				t.Fatal("cold resumed receipt changed")
			}
			for _, role := range []string{"a", "b"} {
				extra := aargs
				if role == "b" {
					extra = bargs
				}
				sp := filepath.Join(z.dir, role+"-status")
				run(z.args("status-"+role, append(append([]string{}, extra...), "--out", sp)...))
				raw, _ := os.ReadFile(sp)
				var s v2.ServeStatus
				if e := json.Unmarshal(raw, &s); e != nil || s.Pending || !s.ArchiveHeld {
					t.Fatal("CLI closed retention", s, e)
				}
			}
		})
	}
}
func TestCustodyV2ServeCLICompleteLifecycle(t *testing.T) { runServeCLICampaign(t, serveInProcess) }
func TestCustodyV2ServeReviewDoesNotReadKeysAndBindsInputs(t *testing.T) {
	z := newServeCLIFixture(t)
	key := z.keys[1]
	if e := os.WriteFile(key, []byte("not a private key"), 0600); e != nil {
		t.Fatal(e)
	}
	args := z.args("unclaimed-command", "--sign-key", key, "--evidence-id", f.Hash("one").String(), "--out", filepath.Join(z.dir, "command"))
	var out bytes.Buffer
	if e := runCustodyV2Serve(t.Context(), args, &out); e != nil {
		t.Fatal("review read seed", e)
	}
	review := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])["review_id"]
	altered := append([]string{}, args...)
	for i := range altered {
		if altered[i] == f.Hash("one").String() {
			altered[i] = f.Hash("two").String()
		}
	}
	if e := runCustodyV2Serve(t.Context(), append(altered, "--mode", "run", "--expected-review-id", review), io.Discard); e == nil {
		t.Fatal("stale review accepted")
	}
	for _, bad := range [][]string{append(args, "--now", "1"), append(args, "--objects", z.x.sources.Objects), append(args, "--action", "scope")} {
		if e := runCustodyV2Serve(t.Context(), bad, io.Discard); e == nil {
			t.Fatal("irrelevant or repeated selector accepted")
		}
	}
}

type serveBrokenWriter struct{}

func (serveBrokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestCustodyV2ServeLostOutputPublishesBeforeReply(t *testing.T) {
	z := newServeCLIFixture(t)
	args := z.args("unclaimed-command", "--sign-key", z.keys[1], "--evidence-id", f.Hash("lost-output").String(), "--out", filepath.Join(z.dir, "command"))
	var out bytes.Buffer
	if e := runCustodyV2Serve(t.Context(), args, &out); e != nil {
		t.Fatal(e)
	}
	review := pruneCLIFields(strings.SplitN(out.String(), "\n", 2)[0])["review_id"]
	if e := runCustodyV2Serve(t.Context(), append(args, "--mode", "run", "--expected-review-id", review), serveBrokenWriter{}); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("lost stdout", e)
	}
	raw, e := os.ReadFile(filepath.Join(z.dir, "command"))
	if e != nil {
		t.Fatal("artifact not durable before reply", e)
	}
	if _, e := custodyfence.DecodeCommand(raw); e != nil {
		t.Fatal(e)
	}
}
