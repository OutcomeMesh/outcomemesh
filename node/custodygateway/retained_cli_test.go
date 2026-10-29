//go:build integration && (linux || darwin)

package custodygateway

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	f "github.com/outcomemesh/outcomemesh/internal/fencetest"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

func TestRetainedAcceptanceCLIReviewSigningAndExtraction(t *testing.T) {
	x, b, a, _ := retainedFixture(t)
	a.AuthoritySignature = [64]byte{}
	a.ConsumerSignature = [64]byte{}
	dir := t.TempDir()
	binary := filepath.Join(dir, "omd")
	if out, e := exec.Command("go", "build", "-o", binary, "../../cmd/omd").CombinedOutput(); e != nil {
		t.Fatal(e, string(out))
	}
	c, _ := x.c.CanonicalBytes()
	bb, _ := b.CanonicalBytes()
	input := struct {
		Context, Bundle []byte
		Consent         v2.RetainedAcceptance
	}{c, bb, a}
	raw, _ := json.Marshal(input)
	path := filepath.Join(dir, "input.json")
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	for _, role := range []string{"authority", "consumer", "extract"} {
		out := filepath.Join(dir, role)
		args := []string{"work-archive-custody-profile5", "--input", path, "--out", out}
		if role == "extract" {
			args = append(args, "--action", "retained-acceptance")
		} else {
			key := filepath.Join(dir, role+".key")
			seed := byte(101)
			if role == "consumer" {
				seed = 4
			}
			if e := os.WriteFile(key, []byte(hex.EncodeToString(f.Key(seed).Seed())), 0600); e != nil {
				t.Fatal(e)
			}
			args = append(args, "--action", "sign-retained", "--role", role, "--key", key)
		}
		review, e := exec.Command(binary, args...).CombinedOutput()
		if e != nil {
			t.Fatal(e, string(review))
		}
		if _, e = os.Stat(out); !os.IsNotExist(e) {
			t.Fatal("review wrote")
		}
		pin := regexp.MustCompile(`review_id=([0-9a-f]{64})`).FindSubmatch(review)
		if len(pin) != 2 {
			t.Fatal(string(review))
		}
		wrong := append(append([]string{}, args...), "--mode", "run", "--expected-review-id", f.Hash("wrong").String())
		if e = exec.Command(binary, wrong...).Run(); e == nil {
			t.Fatal("review bypass")
		}
		run := append(append([]string{}, args...), "--mode", "run", "--expected-review-id", string(pin[1]))
		if log, e := exec.Command(binary, run...).CombinedOutput(); e != nil {
			t.Fatal(e, string(log))
		}
		path = out
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	actual, consent, e := v2.DecodeRetainedAcceptanceData(raw)
	if e != nil {
		t.Fatal(e)
	}
	got, _ := actual.CanonicalBytes()
	if !bytes.Equal(got, bb) || consent.Verify(x.c, b, consent.NotBefore) != nil {
		t.Fatal("CLI changed evidence or roles")
	}
}
