//go:build integration && (linux || darwin)

package main

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Run the same acceptance driver used on SSH hosts against separate local
// processes. The fixture and crash barriers are separate test-only executables;
// preparation, delivery, review and recovery invoke the production CLI binary.
func TestProcessPruneWANAcceptance(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	repo, err = filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	build, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	omd, storeBinary := filepath.Join(build, "omd"), filepath.Join(build, "store.test")
	for _, args := range [][]string{{"build", "-trimpath", "-o", omd, "./cmd/omd"}, {"test", "-c", "-tags=integration", "-o", storeBinary, "./node/custodyauthority/store"}} {
		cmd := exec.CommandContext(t.Context(), "go", args...)
		cmd.Dir = repo
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("acceptance build: %v\n%s", err, output)
		}
	}
	testBinary, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	testBinary, err = filepath.EvalSymlinks(testBinary)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"cancellation", "settlement"} {
		t.Run(scenario, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			port, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			n := port.LocalAddr().(*net.UDPAddr).Port
			port.Close()
			host := func(role string) map[string]any {
				return map[string]any{"kind": "local", "root": filepath.Join(root, role), "binary": omd, "test_binary": testBinary, "store_test_binary": storeBinary, "support": filepath.Join(repo, "scripts/remote_acceptance/support.py")}
			}
			config := map[string]any{"version": 1, "scenario": scenario, "a": host("receiver"), "b": host("sender"), "server_ip": "127.0.0.1", "port": n}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			path, report := filepath.Join(root, "config.json"), filepath.Join(root, "report.json")
			writePruneCLIFile(t, path, raw)
			cmd := exec.CommandContext(t.Context(), "python3", filepath.Join(repo, "scripts/remote_acceptance/prune_delivery.py"), "--config", path, "--report", report)
			cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("acceptance driver: %v\n%s", err, output)
			}
			raw, err = os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var result struct {
				Completed       bool
				ChildrenDrained bool `json:"children_drained"`
				Steps           []struct {
					Kind      string
					Preserved bool `json:"original_accounting_preserved"`
				}
			}
			if err := json.Unmarshal(raw, &result); err != nil {
				t.Fatal(err)
			}
			if !result.Completed || !result.ChildrenDrained || len(result.Steps) != 4 {
				t.Fatal("incomplete acceptance", string(raw))
			}
			for i, s := range result.Steps {
				kind := "admit"
				if i >= 2 {
					kind = "complete"
				}
				if s.Kind != kind || !s.Preserved {
					t.Fatal("missing original accounting evidence", string(raw))
				}
			}
		})
	}
}
