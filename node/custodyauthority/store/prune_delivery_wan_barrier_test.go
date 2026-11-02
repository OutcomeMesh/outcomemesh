//go:build integration && (linux || darwin)

package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/scheduledwire"
	libp2ptransport "github.com/outcomemesh/outcomemesh/node/transport/libp2p"
)

// This process-only barrier is absent from production binaries. It allows a
// deterministic kill on the real host after a durable boundary, without changing
// protocol timeouts or adding administrative fault flags to the CLI.
func TestProcessPruneWANBarrier(t *testing.T) {
	path := os.Getenv("OMESH_REMOTE_GATE_ARGS")
	if path == "" {
		t.Skip("explicit WAN fault barrier")
	}
	var cfg struct {
		Root, Mode, Stage, IntentPath, IntentID, Listen, AssignmentPath, AssignmentID, Outbox, Address string
		Command                                                                                        ScheduledPruneCommandConfig
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	f.Close()
	if err != nil || len(raw) > 1024*1024 {
		t.Fatal("bounded barrier configuration", err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		t.Fatal("trailing barrier configuration")
	}
	root, err := filepath.EvalSymlinks(cfg.Root)
	if err != nil || root != cfg.Root || !filepath.IsAbs(root) {
		t.Fatal("invalid fixture root", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		t.Fatal("fixture root must be private", err)
	}
	for _, p := range []string{path, cfg.IntentPath, cfg.AssignmentPath, cfg.Outbox, cfg.Command.PlanPath, cfg.Command.EntryPath, cfg.Command.AuthorityPath, cfg.Command.AuthorityPinsPath, cfg.Command.ExecutorPath, cfg.Command.ExecutorPinsPath, cfg.Command.JournalPath, cfg.Command.InventoryPath} {
		if p == "" {
			continue
		}
		relative, e := filepath.Rel(root, p)
		if e != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || !filepath.IsAbs(p) {
			t.Fatal("barrier path escapes fixture")
		}
	}
	hash := func(text string) types.Hash {
		b, e := hex.DecodeString(text)
		if e != nil || len(b) != 32 {
			t.Fatal("invalid external pin")
		}
		var id types.Hash
		copy(id[:], b)
		if id.IsZero() {
			t.Fatal("zero external pin")
		}
		return id
	}
	id := hash(cfg.IntentID)
	allowed := map[string]bool{"server/pins-admission-confirm-before-publish": true, "server/scheduled-delivery-confirmed": true, "client/scheduled-outbox-reply-verified": true, "client/scheduled-outbox-after-publish": true}
	if !allowed[cfg.Mode+"/"+cfg.Stage] {
		t.Fatal("unsupported deterministic barrier")
	}
	hooks := storeHooks{at: func(at string) error {
		if at == cfg.Stage {
			fmt.Println("prune_wan_barrier_reached " + at)
			select {}
		}
		return nil
	}}
	if cfg.Mode == "server" {
		raw, err := os.ReadFile(cfg.IntentPath)
		if err != nil {
			t.Fatal(err)
		}
		intent, err := scheduledwire.DecodeIntent(raw)
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewScheduledPruneCommandServer(cfg.Command, intent, id, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		server.hooks = hooks
		transport := libp2ptransport.DefaultConfig()
		transport.Listen = []string{cfg.Listen}
		host, err := libp2ptransport.New(t.Context(), testKey(45), transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer host.Close()
		results := make(chan error, 1)
		if err := host.SetScheduledPruneHandler(intent.ClientPeerID, func(ctx context.Context, peer types.Hash, stream network.Stream) {
			results <- server.Serve(ctx, peer, stream)
		}); err != nil {
			t.Fatal(err)
		}
		ready, _ := json.Marshal(map[string]any{"listen": host.Addresses(), "test_barrier": cfg.Stage})
		fmt.Printf("prune_wan_barrier_ready %s\n", ready)
		t.Fatal("server missed controlled barrier", <-results)
	}
	raw, err = os.ReadFile(cfg.AssignmentPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := custodyauthority.DecodeAssignment(raw)
	if err != nil {
		t.Fatal(err)
	}
	aid, err := a.ID()
	if err != nil || aid != hash(cfg.AssignmentID) {
		t.Fatal("assignment pin changed", err)
	}
	box, err := OpenScheduledPruneOutbox(cfg.Outbox, a, id)
	if err != nil {
		t.Fatal(err)
	}
	defer box.Close()
	box.hooks = hooks
	host, err := libp2ptransport.New(t.Context(), testKey(46), libp2ptransport.DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if _, err := box.Deliver(t.Context(), host, cfg.Address, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	t.Fatal("delivery missed its controlled barrier")
}
