//go:build integration && (linux || darwin)

package custodygateway

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	fixture "github.com/outcomemesh/outcomemesh/internal/protectedtest"
	wire "github.com/outcomemesh/outcomemesh/node/custodygateway/gatewaywire"
	guardstore "github.com/outcomemesh/outcomemesh/node/custodyguard"
)

type retainedCoreProcessConfig struct {
	Root          string
	DescriptorID  types.Hash
	Position      wire.Position
	Request       wire.Request
	Payload       []byte
	GuardURL      string
	Stage, Marker string
}

func TestProcessGuardedRetainedCoreRecovery(t *testing.T) {
	for _, stage := range []string{"retained-core-before-seal", "sealed-result-before-publish", "outer-before-publish"} {
		t.Run(stage, func(t *testing.T) {
			x, claim, q, payload, _ := interruptedCoreFixture(t, "core-result-before-seal", true)
			source, err := x.b.currentExecutionSource()
			fixture.Require(t, err)
			accounting := x.state.Snapshot()
			pin, _ := x.b.Position()
			did, _ := x.bd.ID()
			fixture.Require(t, x.b.Close())
			marker := filepath.Join(t.TempDir(), "reached")
			config := retainedCoreProcessConfig{Root: x.broot, DescriptorID: did, Position: pin, Request: q, Payload: payload, GuardURL: x.guard.(guardstore.Client).URL, Stage: stage, Marker: marker}
			raw, err := json.Marshal(config)
			fixture.Require(t, err)
			path := filepath.Join(t.TempDir(), "config.json")
			fixture.Require(t, os.WriteFile(path, raw, 0600))
			child := exec.Command(os.Args[0], "-test.run=^TestProcessGuardedRetainedCoreHelper$", "-test.count=1")
			child.Env = append(os.Environ(), "OM_RETAINED_CORE_CONFIG="+path)
			var output bytes.Buffer
			child.Stdout, child.Stderr = &output, &output
			fixture.Require(t, child.Start())
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			t.Cleanup(func() { _ = child.Process.Kill() })
			deadline := time.NewTimer(20 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
		wait:
			for {
				if _, err := os.Stat(marker); err == nil {
					break wait
				}
				select {
				case err := <-done:
					t.Fatal("child stopped early", err, output.String())
				case <-deadline.C:
					t.Fatal("child missed recovery boundary")
				case <-tick.C:
				}
			}
			if owner, err := Open(x.broot, did, pin, &q); err == nil {
				owner.Close()
				t.Fatal("concurrent process acquired original owner")
			}
			fixture.Require(t, child.Process.Kill())
			if err := <-done; err == nil {
				t.Fatal("child survived kill")
			}
			x.b, err = Open(x.broot, did, pin, &q)
			fixture.Require(t, err)
			x.b.SetGuard(x.guard)
			result, response := recoveredCore(t, x, q, payload, claim)
			_, again := recoveredCore(t, x, q, payload, claim)
			if !bytes.Equal(response, again) {
				t.Fatal("cold retry changed response")
			}
			if result.Protection == nil {
				t.Fatal("recovery omitted independent seal")
			}
			after, err := x.b.currentExecutionSource()
			fixture.Require(t, err)
			if !reflect.DeepEqual(source, after) || !reflect.DeepEqual(accounting, x.state.Snapshot()) {
				t.Fatal("process recovery repeated work or reset accounting")
			}
		})
	}
}
func TestProcessGuardedRetainedCoreHelper(t *testing.T) {
	path := os.Getenv("OM_RETAINED_CORE_CONFIG")
	if path == "" {
		t.Skip("subprocess only")
	}
	raw, err := os.ReadFile(path)
	fixture.Require(t, err)
	var c retainedCoreProcessConfig
	fixture.Require(t, json.Unmarshal(raw, &c))
	owner, err := Open(c.Root, c.DescriptorID, c.Position, &c.Request)
	fixture.Require(t, err)
	defer owner.Close()
	owner.SetGuard(guardstore.Client{URL: c.GuardURL})
	stop := func(stage string) error {
		if stage == c.Stage {
			if err := os.WriteFile(c.Marker, []byte(stage), 0600); err != nil {
				return err
			}
			select {}
		}
		return nil
	}
	owner.executionHook = stop
	owner.beforeCommit = func() error { return stop("outer-before-publish") }
	_, err = owner.ExecuteRuntime(t.Context(), c.Request, c.Payload)
	t.Fatal("escaped recovery boundary", err)
}
