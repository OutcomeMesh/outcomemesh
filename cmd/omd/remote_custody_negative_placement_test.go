package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/core/types"
	"github.com/outcomemesh/outcomemesh/node/custodyauthority/remotewire"
	store "github.com/outcomemesh/outcomemesh/node/custodyauthority/store"
)

func enrollRemoteCLIPlacement(t testing.TB, f *remoteCLIFixture, role string) []string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "external-control")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "placement")
	var review bytes.Buffer
	if err := runRemoteCustody(t.Context(), append(f.args(role, "placement-review"), "--placement", path), nil, &review); err != nil {
		t.Fatal("placement review", err)
	}
	fields := make(map[string]string)
	for _, part := range strings.Fields(review.String()) {
		if key, value, ok := strings.Cut(part, "="); ok {
			fields[key] = value
		}
	}
	if fields == nil || fields["keys_loaded"] != "false" || fields["owners_opened"] != "false" {
		t.Fatal("review loaded private material", review.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("review created placement", err)
	}
	var created bytes.Buffer
	if err := runRemoteCustody(t.Context(), append(f.args(role, "placement-create"), "--placement", path, "--placement-id", fields["placement_id"]), nil, &created); err != nil {
		t.Fatal("placement create", err)
	}
	return []string{"--placement", path, "--placement-id", fields["placement_id"], "--require-placement=true"}
}

func replaceRemoteCLIFlag(args []string, flag, value string) []string {
	copy := append([]string{}, args...)
	for i := 0; i < len(copy)-1; i++ {
		if copy[i] == flag {
			copy[i+1] = value
			return copy
		}
	}
	return append(copy, flag, value)
}

func TestRemoteCustodyCLIPlacementChecksBeforeSeedsAndRejectsCopies(t *testing.T) {
	for _, role := range []string{"audit", "serve"} {
		t.Run(role, func(t *testing.T) {
			f := newRemoteCLIFixture(t)
			flags := enrollRemoteCLIPlacement(t, f, role)
			args := append(f.args(role, "review"), flags...)
			var view bytes.Buffer
			if err := runRemoteCustody(t.Context(), args, nil, &view); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(view.String(), "PlacementID") {
				t.Fatal("review did not disclose protection")
			}
			key := f.keyPaths[16]
			if role == "serve" {
				key = f.keyPaths[14]
			}
			copyPath := filepath.Join(t.TempDir(), "copied.seed")
			data, err := os.ReadFile(key)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(copyPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			bad := replaceRemoteCLIFlag(args, "--control-key", copyPath)
			if _, err := loadRemoteCustodyOptions(t.Context(), bad); !errors.Is(err, store.ErrRemotePlacement) {
				t.Fatal("identical copied key accepted", err)
			}
			kept := key + ".original"
			if err := os.Rename(key, kept); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(key, make([]byte, 32), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRemoteCustodyOptions(t.Context(), args); !errors.Is(err, store.ErrRemotePlacement) {
				t.Fatal("seed was loaded before placement rejection", err)
			}
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(kept, key); err != nil {
				t.Fatal(err)
			}
			if _, err := loadRemoteCustodyOptions(t.Context(), args); err != nil {
				t.Fatal("original restoration rejected", err)
			}
			if _, err := loadRemoteCustodyOptions(t.Context(), append(f.args(role, "control"), "--require-placement=true")); err == nil {
				t.Fatal("required placement was optional")
			}
		})
	}
}

func TestRemoteCustodyCLINegativeUnseenRetainsTicketsAndRecoversArtifact(t *testing.T) {
	f := newRemoteCLIFixture(t)
	aFlags := enrollRemoteCLIPlacement(t, f, "audit")
	bFlags := enrollRemoteCLIPlacement(t, f, "serve")
	b := startRemoteCLIControl(t, append(f.args("serve", "control"), bFlags...))
	b.send(t, "serve "+b.review(t))
	ready := b.next(t, "remote_custody_serving")
	path := filepath.Join(t.TempDir(), "negative")
	args := append(f.args("audit", "control"), aFlags...)
	args = append(args, "--peer", ready["listen"], "--negative", path)
	a := startRemoteCLIControl(t, args)
	for _, step := range []struct{ action, prefix string }{{"prepare", "remote_custody_prepared"}, {"begin", "remote_custody_begun"}, {"seal", "remote_custody_metadata"}} {
		a.send(t, step.action+" "+a.review(t))
		a.next(t, step.prefix)
	}
	a.send(t, "capture-negative "+a.review(t))
	captured := a.next(t, "remote_custody_negative")
	if captured["kind"] != "1" || captured["ordinary_tickets_retained"] != "true" || captured["source_advanced"] != "false" {
		t.Fatal("false negative completion", captured)
	}
	a.close(t)
	b.close(t)
	id, err := pruneExternalID("negative-id", captured["negative_id"])
	if err != nil {
		t.Fatal(err)
	}
	n, err := store.LoadRemoteCustodyNegative(path, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Validate(f.scope); err != nil {
		t.Fatal(err)
	}
	drainBytes, err := os.ReadFile(f.drain)
	if err != nil {
		t.Fatal(err)
	}
	response, err := decodeRemoteDrainForCLI(f, drainBytes)
	if err != nil {
		t.Fatal(err)
	}
	args = append(args, "--drain-id", response.String(), "--negative-id", id.String())
	a = startRemoteCLIControl(t, args)
	a.send(t, "capture-negative "+a.review(t))
	retry := a.next(t, "remote_custody_negative")
	if retry["negative_id"] != id.String() {
		t.Fatal("retry changed observation")
	}
	a.close(t)
	owner, err := store.OpenCoordinator(f.authority, f.pins, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	current, err := owner.Snapshot()
	if err != nil || current.Confirmed.Sequence != 4 || current.Authority.Pending != 2 || current.Authority.Remote != nil {
		t.Fatal("negative capture completed an obligation", current, err)
	}
	if _, err := os.Stat(f.terminal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("negative capture created successful terminal", err)
	}
}

func TestRemoteCustodyCLIPlacementRejectsLiveKeyReplacement(t *testing.T) {
	for _, role := range []string{"audit", "serve"} {
		t.Run(role, func(t *testing.T) {
			f := newRemoteCLIFixture(t)
			flags := enrollRemoteCLIPlacement(t, f, role)
			control := startRemoteCLIControl(t, append(f.args(role, "control"), flags...))
			if role == "audit" {
				control.send(t, "prepare "+control.review(t))
				control.next(t, "remote_custody_prepared")
				control.send(t, "begin "+control.review(t))
				control.next(t, "remote_custody_begun")
			}
			token := control.review(t)
			path := f.keyPaths[16]
			if role == "serve" {
				path = f.base.serve.replicaKey
			}
			bytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			kept := path + ".original"
			if err := os.Rename(path, kept); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, bytes, 0o600); err != nil {
				t.Fatal(err)
			}
			action := "prepare"
			if role == "serve" {
				action = "serve"
			}
			control.send(t, action+" "+token)
			select {
			case err := <-control.done:
				if !errors.Is(err, store.ErrRemotePlacement) {
					t.Fatal("live copied key bypassed guard", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("live copied key did not stop operator")
			}
			if role == "audit" {
				owner, err := store.OpenCoordinator(f.authority, f.pins, f.scope.Worker.Assignment, f.scope.Worker.Plan.AssignmentID)
				if err != nil {
					t.Fatal(err)
				}
				current, err := owner.Snapshot()
				_ = owner.Close()
				if err != nil || current.Confirmed.Sequence != 3 || current.Authority.Pending != 2 || current.Authority.Remote == nil {
					t.Fatal("key replacement released active hold", current, err)
				}
			}
		})
	}
}

func decodeRemoteDrainForCLI(f *remoteCLIFixture, b []byte) (types.Hash, error) {
	response, err := remotewire.DecodeResponse(b)
	if err != nil {
		return types.Hash{}, err
	}
	_, id, err := store.RemoteCustodyDrainArtifact(f.scope, response)
	return id, err
}
