//go:build linux || darwin

package custodyguard

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	wire "github.com/outcomemesh/outcomemesh/node/custodyguard/guardwire"
)

type processSpec struct {
	Root     string
	Identity Identity
	Position Position
	Attempt  *wire.Request
}
type processNotice struct {
	Address  string
	Position Position
}

func TestGuardProcessHelper(t *testing.T) {
	text := os.Getenv("OMESH_GUARD_PROCESS_TEST")
	if text == "" {
		t.Skip("explicit subprocess fixture")
	}
	var spec processSpec
	if e := json.Unmarshal([]byte(text), &spec); e != nil {
		t.Fatal(e)
	}
	s, e := Open(spec.Root, spec.Identity, spec.Position, spec.Attempt)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	out := json.NewEncoder(os.Stdout)
	s.SetObserver(func(p Position, _ wire.Request) error { return out.Encode(processNotice{Position: p}) })
	if e = out.Encode(processNotice{Address: l.Addr().String()}); e != nil {
		t.Fatal(e)
	}
	if e = Serve(t.Context(), l, s); e != nil {
		t.Fatal(e)
	}
}
func TestGuardProcessKilledOwnerKeepsChoiceAgainstClonedKey(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess acceptance")
	}
	s := newStore(t, 8)
	id := s.Identity()
	root := s.root
	s.Close()
	start := func(spec processSpec) (Client, *exec.Cmd, *json.Decoder) {
		t.Helper()
		binary, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := json.Marshal(spec)
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		t.Cleanup(cancel)
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestGuardProcessHelper$", "-test.timeout=25s")
		cmd.Env = append(os.Environ(), "OMESH_GUARD_PROCESS_TEST="+string(raw))
		cmd.Stderr = os.Stderr
		stdout, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		decoder := json.NewDecoder(stdout)
		var notice processNotice
		if e = decoder.Decode(&notice); e != nil || notice.Address == "" {
			t.Fatal("daemon readiness", e)
		}
		return Client{URL: "http://" + notice.Address}, cmd, decoder
	}
	c, child, decoder := start(processSpec{Root: root, Identity: id})
	q := request(t, "selected")
	seal, e := wire.Obtain(t.Context(), c, id.PublicKey, q, testKey(1))
	if e != nil {
		t.Fatal(e)
	}
	var notice processNotice
	if e = decoder.Decode(&notice); e != nil || notice.Position.Sequence != 1 {
		t.Fatal("external cursor", e)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = child.Wait()
	c, child, decoder = start(processSpec{Root: root, Identity: id, Attempt: &q})
	again, e := wire.Obtain(t.Context(), c, id.PublicKey, q, testKey(1))
	if e != nil || again != seal {
		t.Fatal("cold daemon recovery", e)
	}
	if e = decoder.Decode(&notice); e != nil || notice.Position.Sequence != 1 {
		t.Fatal(e)
	}
	if _, e = wire.Obtain(t.Context(), c, id.PublicKey, request(t, "cloned-fork"), testKey(1)); e == nil {
		t.Fatal("copy defeated independent daemon")
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = child.Wait()
}
