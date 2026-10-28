//go:build integration && (darwin || linux)

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/outcomemesh/outcomemesh/node/custodyfence"
	v2 "github.com/outcomemesh/outcomemesh/node/custodyv2"
)

func admissionProcessFlag(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func TestProcessCustodyV2AdmissionLifecycleAndLostWitnessOutput(t *testing.T) {
	type lost struct {
		root, input string
		bytes       []byte
		recovered   bool
	}
	selected := map[string]*lost{}
	driver := func(t testing.TB, args []string) string {
		t.Helper()
		action := admissionProcessFlag(args, "--action")
		mode := admissionProcessFlag(args, "--mode")
		inject := mode == "run" && (action == "witness-vote" || action == "witness-commit") && selected[action] == nil
		if !inject {
			output := runProcessCommand(t, 15*time.Second, args...)
			if mode == "run" {
				if old := selected[action]; old != nil && !old.recovered && old.root == admissionProcessFlag(args, "--root") && old.input == admissionProcessFlag(args, "--in") {
					raw, e := os.ReadFile(admissionProcessFlag(args, "--out"))
					if e != nil || !bytes.Equal(raw, old.bytes) {
						t.Fatal("cold witness recovery changed retained output", action, e)
					}
					old.recovered = true
				}
			}
			return output
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		reader, writer, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		_ = reader.Close()
		child := helperCommand(ctx, args...)
		child.Stdout = writer
		var stderr bytes.Buffer
		child.Stderr = &stderr
		if e := child.Start(); e != nil {
			_ = writer.Close()
			t.Fatal(e)
		}
		_ = writer.Close()
		if e := child.Wait(); e == nil {
			t.Fatal("closed stdout reported witness success", action)
		}
		if e := ctx.Err(); e != nil {
			t.Fatal("witness timed out instead of losing stdout", action, e, stderr.String())
		}
		raw, e := os.ReadFile(admissionProcessFlag(args, "--out"))
		if e != nil {
			t.Fatal("witness output was not retained before stdout", action, e, stderr.String())
		}
		input, e := os.ReadFile(admissionProcessFlag(args, "--in"))
		if e != nil {
			t.Fatal(e)
		}
		if action == "witness-vote" {
			entry, e := v2.DecodeAdmissionEntry(input)
			if e != nil {
				t.Fatal(e)
			}
			id, _ := entry.ID()
			vote, e := v2.DecodeAdmissionVote(raw)
			if e != nil || vote.EntryID != id {
				t.Fatal("lost reply left invalid vote", e)
			}
		} else {
			cert, e := v2.DecodeAdmissionCertificate(input)
			if e != nil {
				t.Fatal(e)
			}
			id, _ := cert.Entry.ID()
			var result struct {
				Snapshot                          v2.AdmissionSnapshot
				Pin                               custodyfence.WitnessPin
				CoordinatorOnly, ExecutionGranted bool
			}
			if e := json.Unmarshal(raw, &result); e != nil || result.Pin.Position.HeadID != id || result.Pin.Position.Sequence != cert.Entry.ExpectedSequence+1 || !result.Pin.PendingID.IsZero() || result.Snapshot.Position != result.Pin.Position || result.Snapshot.GenesisID != cert.Entry.GenesisID || !result.CoordinatorOnly || result.ExecutionGranted {
				t.Fatal("lost commit reply did not retain exact coordinator state", result, e)
			}
		}
		selected[action] = &lost{root: admissionProcessFlag(args, "--root"), input: admissionProcessFlag(args, "--in"), bytes: raw}
		// The command's successful output is deliberately unavailable. The campaign
		// explicitly retries in another process with its retained original before pin.
		return ""
	}
	runAdmissionCLICampaign(t, driver)
	for _, action := range []string{"witness-vote", "witness-commit"} {
		if selected[action] == nil || !selected[action].recovered {
			t.Fatal("missing native lost-output/cold-retry boundary", action)
		}
	}
}
