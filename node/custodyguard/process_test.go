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
	Root              string
	Identity          Identity
	Position          Position
	Attempt           *wire.Request
	RevocationAttempt *wire.Revocation
	PauseRevocation   bool
}
type processNotice struct {
	Persisted bool
	Address   string
	Position  Position
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
	var s *Store
	var e error
	if spec.RevocationAttempt != nil {
		s, e = RecoverRevocation(spec.Root, spec.Identity, spec.Position, *spec.RevocationAttempt)
	} else {
		s, e = Open(spec.Root, spec.Identity, spec.Position, spec.Attempt)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	out := json.NewEncoder(os.Stdout)
	if spec.PauseRevocation {
		s.hook = func(stage string) error {
			if stage == "after-persist" {
				if e := out.Encode(processNotice{Persisted: true}); e != nil {
					return e
				}
				<-t.Context().Done()
				return t.Context().Err()
			}
			return nil
		}
	}
	s.SetRevocationObserver(func(p Position, _ wire.Revocation) error { return out.Encode(processNotice{Position: p}) })
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

	c, child, decoder := startGuardProcess(t, processSpec{Root: root, Identity: id})
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
	c, child, decoder = startGuardProcess(t, processSpec{Root: root, Identity: id, Attempt: &q})
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

func startGuardProcess(t *testing.T, spec processSpec) (Client, *exec.Cmd, *json.Decoder) {
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

func TestGuardProcessKilledAfterRevocationPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess acceptance")
	}
	s := revocableStore(t, 4)
	q := revokeRequest(t, s, 1)
	id, root := s.Identity(), s.root
	s.Close()
	client, child, decoder := startGuardProcess(t, processSpec{Root: root, Identity: id, PauseRevocation: true})
	done := make(chan error, 1)
	go func() { _, e := client.Revoke(t.Context(), q); done <- e }()
	var notice processNotice
	if e := decoder.Decode(&notice); e != nil || !notice.Persisted {
		t.Fatal("persistence barrier", e)
	}
	if e := child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = child.Wait()
	if e := <-done; e == nil {
		t.Fatal("killed before reply reported success")
	}
	client, child, decoder = startGuardProcess(t, processSpec{Root: root, Identity: id, RevocationAttempt: &q})
	r, e := wire.ObtainRevocation(t.Context(), client, id.PublicKey, id.ID(), q)
	if e != nil {
		t.Fatal(e)
	}
	if e = decoder.Decode(&notice); e != nil || notice.Position.Sequence != 1 {
		t.Fatal("durable cursor", e)
	}
	for _, label := range []string{"original", "copy"} {
		if _, e = client.Choose(t.Context(), request(t, label)); e == nil {
			t.Fatal("revoked clone after kill")
		}
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = child.Wait()
	client, child, decoder = startGuardProcess(t, processSpec{Root: root, Identity: id, Position: notice.Position})
	again, e := wire.ObtainRevocation(t.Context(), client, id.PublicKey, id.ID(), q)
	if e != nil || again != r {
		t.Fatal("cold exact receipt", e)
	}
	if e = decoder.Decode(&notice); e != nil || notice.Position.Sequence != 1 {
		t.Fatal(e)
	}
	if e = child.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	_ = child.Wait()
}
