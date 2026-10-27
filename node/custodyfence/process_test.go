//go:build integration && (darwin || linux)

package custodyfence

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
)

func TestIndependentWitnessProcessChild(t *testing.T) {
	path := os.Getenv("OMESH_FENCE_PROCESS_ROOT")
	if path == "" {
		t.Skip("explicit private process fixture")
	}
	s := testScope()
	pin := initial(s)
	w, err := Open(path, s, pin.Position.HeadID, testKey(3), pin)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.hook = func(stage string) error {
		if stage == "after-directory-sync" {
			fmt.Println("fence-proposal-durable-before-signature")
			// Parent kills the process at the fsync/sign boundary.
			for {
				time.Sleep(time.Second)
			}
		}
		return nil
	}
	c := signed(t, s, pin.Position, Claim, types.Hash{}, types.Hash{})
	_, _ = w.Vote(c)
	t.Fatal("private crash boundary returned")
}

func TestIndependentWitnessProcessDeathKeepsVoteLock(t *testing.T) {
	s := testScope()
	pin := initial(s)
	path := root(t)
	w, err := Create(path, s, pin.Position.HeadID, testKey(3))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestIndependentWitnessProcessChild$", "-test.count=1")
	child.Env = append(os.Environ(), "OMESH_FENCE_PROCESS_ROOT="+path)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "fence-proposal-durable-before-signature") {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child failed before durable boundary")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("child did not reach durable boundary")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	exit, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatal("child was not killed", err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("child exited for a reason other than the selected SIGKILL", err)
	}
	claim := signed(t, s, pin.Position, Claim, types.Hash{}, types.Hash{})
	w, err = RecoverVote(path, s, pin.Position.HeadID, testKey(3), pin, claim)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cancel := signed(t, s, pin.Position, CloseUnclaimed, types.Hash{}, testHash(80))
	if _, err := w.Vote(cancel); err == nil {
		t.Fatal("killed witness forgot its durable lock")
	}
	if vote, err := w.Vote(claim); err != nil || vote.CommandID.IsZero() {
		t.Fatal("explicit exact vote recovery failed", err)
	}
}
